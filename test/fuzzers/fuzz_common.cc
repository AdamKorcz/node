#include "fuzz_common.h"

#include <cstdlib>   // std::atexit
#include <string>
#include <vector>
#include <unordered_map>

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
    nullptr, &node::FreeArrayBufferAllocator};  // kept for ABI/back-compat; unused now
uv_loop_t                              g_loop;

// Per-isolate ArrayBuffer allocators so memory returns to the OS when an
// isolate is destroyed (prevents long-run RSS creep).
using ABAUnique =
    std::unique_ptr<node::ArrayBufferAllocator, decltype(&node::FreeArrayBufferAllocator)>;
static std::unordered_map<v8::Isolate*, ABAUnique> g_isolate_allocators;

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

// Always run a short final drain after Stop() so libuv close callbacks free
// memory and platform task queues empty.
static inline void FinalDrain(v8::Isolate* isolate,
                              node::NodePlatform* platform,
                              uv_loop_t* loop) {
  BoundedPump(isolate, /*max_pumps=*/8, platform, loop);
}

void GlobalShutdown() {
  // All environments/isolates must already be gone at this point.

  // Stop platform threads and drain remaining tasks before taking V8 down.
  if (g_platform) {
    g_platform->Shutdown();
  }

  // cppgc must be shut down after all isolates are disposed, but before V8::Dispose().
  cppgc::ShutdownProcess();

  // Dispose V8 itself.
  v8::V8::Dispose();

  // Tell V8 the platform is going away only after we’ve shut it down.
  v8::V8::DisposePlatform();

  // Free NodePlatform instance.
  g_platform.reset();

  // Process-wide allocator (unused in the new flow, but free it if present).
  g_allocator.reset();

  // Important for correctness and for sanitizers at process exit.
  uv_loop_close(&g_loop);
}

}  // namespace

// ---------- Runtime ----------
Runtime& Runtime::Get() {
  static Runtime rt;
  return rt;
}
uv_loop_t* Runtime::loop() { return &g_loop; }
node::NodePlatform* Runtime::platform() { return g_platform.get(); }
// Kept for API compatibility; per-isolate allocators are now used instead.
node::ArrayBufferAllocator* Runtime::allocator() { return g_allocator.get(); }

// ---------- IsolateScope ----------
IsolateScope::IsolateScope() {
  // Create a fresh ArrayBuffer allocator for this isolate so buffers/pages
  // can be released back to the OS when the isolate dies.
  ABAUnique aba{ node::CreateArrayBufferAllocator(), &node::FreeArrayBufferAllocator };

  isolate_ = node::NewIsolate(
      aba.get(),
      Runtime::Get().loop(),
      Runtime::Get().platform());

  if (isolate_) {
    // Transfer ownership of the allocator into our per-isolate map so it
    // lives exactly as long as the isolate.
    g_isolate_allocators.emplace(isolate_, ABAUnique{ std::move(aba) });
    isolate_->Enter();
  }
}

IsolateScope::~IsolateScope() {
  if (!isolate_) return;

  auto* platform = Runtime::Get().platform();

  // Drain any pending foreground tasks, leave, then dispose via the platform
  // so its per-isolate queues and bookkeeping are freed correctly.
  platform->DrainTasks(isolate_);
  isolate_->Exit();
  platform->DisposeIsolate(isolate_);

  // Drop the per-isolate allocator (returns backing pages to the OS).
  g_isolate_allocators.erase(isolate_);

  isolate_ = nullptr;
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

  // Optional bounded chance for async work before shutdown (caller-controlled).
  if (opts.max_pumps > 0) BoundedPump(isolate, opts.max_pumps, platform, loop);

  // Portable shutdown: bounded pump → RunAtExit → Stop → final pump.
  node::RunAtExit(env);
  node::Stop(env);

  // Unconditional final drain so uv_close completions free memory.
  FinalDrain(isolate, platform, loop);

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

  // Portable shutdown: bounded pump → RunAtExit → Stop → final pump.
  node::RunAtExit(env);
  node::Stop(env);

  // Unconditional final drain so uv_close completions free memory.
  FinalDrain(isolate, platform, loop);

  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);
}

// ---------- Shared libFuzzer initializer (process-wide) ----------
extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
  uv_os_unsetenv("NODE_OPTIONS");

  // Small, fast platform with no tracing (saves CPU/threads)
  static constexpr int kV8ThreadPoolSize = 1;
  g_platform = std::make_unique<node::NodePlatform>(
      kV8ThreadPoolSize, /*tracing_controller=*/nullptr);
  v8::V8::InitializePlatform(g_platform.get());

  // *** IMPORTANT ORDERING ***
  // Parse Node/V8 flags BEFORE V8 is initialized to avoid
  // "Check failed: !IsFrozen()" when Node sets V8 flags.
  std::vector<std::string> node_argv{ "fuzz_env" };
  (void) node::InitializeOncePerProcess(
      node_argv,
      node::ProcessInitializationFlags::kLegacyInitializeNodeWithArgsBehavior);

  // cppgc + V8 init (once per process)
  cppgc::InitializeProcess(g_platform->GetPageAllocator());
  v8::V8::Initialize();

  // Initialize the process uv loop we pass into IsolateData
  (void)uv_loop_init(&g_loop);

  // Note: we no longer pre-create a process-wide ArrayBuffer allocator.
  // Each Isolate gets its own allocator (see IsolateScope).

  // Ensure cleanup at process exit
  std::atexit(&GlobalShutdown);
  return 0;
}

}  // namespace fuzz
