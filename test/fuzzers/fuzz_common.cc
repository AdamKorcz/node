#include "fuzz_common.h"

#include <cstdlib>  // std::atexit

#include "v8.h"
#include "uv.h"

// cppgc platform init/shutdown like cctest does
#include "cppgc/platform.h"

namespace fuzz {
namespace {
// Process-wide plumbing (no JS/Environment state lives here)
std::unique_ptr<node::NodePlatform>   g_platform;
std::unique_ptr<node::ArrayBufferAllocator,
                decltype(&node::FreeArrayBufferAllocator)> g_allocator{
    nullptr, &node::FreeArrayBufferAllocator};
uv_loop_t                              g_loop;

void GlobalShutdown() {
  // Teardown order similar to test/cctest/node_test_fixture.cc
  cppgc::ShutdownProcess();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  if (g_platform) {
    g_platform->Shutdown();
    g_platform.reset();
  }
  g_allocator.reset();

  // uv_loop_close(&g_loop);  // Optional if you guarantee no remaining handles.
}
}  // namespace

// ---------- Runtime ----------
Runtime& Runtime::Get() {
  static Runtime rt;
  return rt;
}
uv_loop_t* Runtime::loop() { return &g_loop; }
node::NodePlatform* Runtime::platform() { return g_platform.get(); }
node::ArrayBufferAllocator* Runtime::allocator() { return g_allocator.get(); }

// ---------- IsolateScope ----------
IsolateScope::IsolateScope() {
  // Fresh isolate per input; reuse process-wide allocator/platform/loop
  isolate_ = node::NewIsolate(
      Runtime::Get().allocator(),
      Runtime::Get().loop(),
      Runtime::Get().platform());
  if (isolate_) isolate_->Enter();
}

IsolateScope::~IsolateScope() {
  if (!isolate_) return;

  auto* platform = Runtime::Get().platform();

  // Drain any pending foreground tasks, leave, then dispose.
  platform->DrainTasks(isolate_);
  isolate_->Exit();

  // IMPORTANT: Keep the isolate registered with the platform while disposing.
  // V8/CPPGC may query the platform during teardown.
  isolate_->Dispose();

  // Now it's safe to drop NodePlatform's per-isolate mapping.
  platform->UnregisterIsolate(isolate_);

  isolate_ = nullptr;
}

// Helper: bounded pump of foreground tasks + libuv + microtasks
static inline void BoundedPump(v8::Isolate* isolate,
                               int max_pumps,
                               node::NodePlatform* platform,
                               uv_loop_t* loop) {
  for (int i = 0; i < max_pumps; ++i) {
    bool progressed = false;
    platform->DrainTasks(isolate);
    progressed |= (uv_run(loop, UV_RUN_NOWAIT) != 0);
    isolate->PerformMicrotaskCheckpoint();
    if (!progressed) break;
  }
}

// ---------- RunInEnvironment ----------
void RunInEnvironment(v8::Isolate* isolate,
                      EnvCallback cb,
                      const EnvRunOptions& opts) {
  // Fresh handle scope + context per invocation (stateless across inputs).
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = node::NewContext(isolate);
  v8::Context::Scope context_scope(context);

  node::IsolateData* isolate_data =
      node::CreateIsolateData(isolate, Runtime::Get().loop(), Runtime::Get().platform());

  std::vector<std::string> args{ "node" };
  std::vector<std::string> exec_args;

  node::Environment* env =
      node::CreateEnvironment(isolate_data, context, args, exec_args, opts.flags);

  // Bootstrap Node (no entry script) so N-API/require/etc. are ready.
  node::LoadEnvironment(env, const_cast<char*>(""));

  // ---- caller's code inside a fully initialized Environment ----
  cb(env, context);
  // -------------------------------------------------------------

  auto* platform = Runtime::Get().platform();
  auto* loop     = Runtime::Get().loop();

  // Give async work a brief bounded chance (if requested)
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  // Proper Node shutdown: beforeExit → AtExit → Stop, with small pumps in-between
  env->RunBeforeExitCallbacks();
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  node::RunAtExit(env);

  node::Stop(env);
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);
}

// ---------- RunEnvString ----------
void RunEnvString(v8::Isolate* isolate,
                  const char* env_js,
                  const EnvRunOptions& opts) {
  if (opts.print_js_to_stdout && env_js) {
    fprintf(stdout, "%s\n", env_js);
  }

  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = node::NewContext(isolate);
  v8::Context::Scope context_scope(context);

  node::IsolateData* isolate_data =
      node::CreateIsolateData(isolate, Runtime::Get().loop(), Runtime::Get().platform());

  std::vector<std::string> args{ "node" };
  std::vector<std::string> exec_args;

  node::Environment* env =
      node::CreateEnvironment(isolate_data, context, args, exec_args, opts.flags);

  // Load & run entrypoint (may be empty string)
  node::LoadEnvironment(env, env_js ? const_cast<char*>(env_js) : const_cast<char*>(""));

  auto* platform = Runtime::Get().platform();
  auto* loop     = Runtime::Get().loop();

  // Optional bounded pumps (most fuzzers will leave this at 0)
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  // Proper Node shutdown sequence to avoid leaks/stalls
  env->RunBeforeExitCallbacks();
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  node::RunAtExit(env);

  node::Stop(env);
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);
}

// ---------- Shared libFuzzer initializer (process-wide) ----------
extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
  uv_os_unsetenv("NODE_OPTIONS");

  // Small, fast platform with no tracing (saves CPU/threads)
  static constexpr int kV8ThreadPoolSize = 1;
  g_platform = std::make_unique<node::NodePlatform>(kV8ThreadPoolSize, /*tracing_controller=*/nullptr);
  v8::V8::InitializePlatform(g_platform.get());

  // cppgc + V8 init (once per process)
  cppgc::InitializeProcess(g_platform->GetPageAllocator());
  v8::V8::Initialize();

  // Initialize the process uv loop we pass into IsolateData
  (void)uv_loop_init(&g_loop);

  // Node per-process initialization (public API).
  // Use flags that tell Node we've handled V8/platform/etc.
  std::vector<std::string> node_argv{ "fuzz_env" };
  (void) node::InitializeOncePerProcess(
      node_argv,
      node::ProcessInitializationFlags::kLegacyInitializeNodeWithArgsBehavior);

  // Process-wide allocator, reused for all isolates
  g_allocator.reset(node::CreateArrayBufferAllocator());

  // Ensure cleanup at process exit
  std::atexit(&GlobalShutdown);
  return 0;
}

}  // namespace fuzz
