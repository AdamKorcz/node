#include "fuzz_common.h"

#include "v8.h"
#include "uv.h"

#include "tracing/agent.h"
#include "tracing/trace_event.h"

// Match cctest fixture includes/behavior
#include "cppgc/platform.h"
#include "absl/synchronization/mutex.h"

namespace fuzz {
namespace {
// Process-wide plumbing (no JS state lives here)
std::unique_ptr<node::tracing::Agent> g_tracing_agent;
std::unique_ptr<node::NodePlatform>   g_platform;
uv_loop_t                              g_loop;

void GlobalShutdown() {
  // Mirror test/cctest/node_test_fixture.cc TearDown
  cppgc::ShutdownProcess();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  if (g_platform) {
    g_platform->Shutdown();
    g_platform.reset();
  }
  g_tracing_agent.reset();

  // uv_loop_close() can fail if handles still exist; fuzzers often skip it.
  // Uncomment if you ensure the loop is quiescent:
  // uv_loop_close(&g_loop);
}
}  // namespace

// ---------- Runtime ----------
Runtime& Runtime::Get() {
  static Runtime rt;
  return rt;
}
uv_loop_t* Runtime::loop() { return &g_loop; }
node::NodePlatform* Runtime::platform() { return g_platform.get(); }

// ---------- IsolateScope ----------
IsolateScope::IsolateScope() {
  isolate_ = node::NewIsolate(
      allocator_.get(),
      Runtime::Get().loop(),
      Runtime::Get().platform());
  if (isolate_) isolate_->Enter();
}

IsolateScope::~IsolateScope() {
  if (!isolate_) return;

  auto* platform = Runtime::Get().platform();

  // Drain any pending tasks, then leave & dispose.
  platform->DrainTasks(isolate_);
  isolate_->Exit();
  isolate_->Dispose();                     // let V8 finish; it may still call into platform
  platform->UnregisterIsolate(isolate_);   // now it's safe to drop the mapping

  isolate_ = nullptr;
}

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

  // Run Node's bootstrap (no entry script), to get a proper process/env.
  node::LoadEnvironment(env, const_cast<char*>(""));

  // ---- caller's code inside a fully initialized Environment ----
  cb(env, context);
  // -------------------------------------------------------------

  // Give any microtasks/callbacks a brief chance to run (bounded).
  auto* platform = Runtime::Get().platform();
  auto* loop     = Runtime::Get().loop();
  for (int i = 0; i < opts.max_pumps; ++i) {
    platform->DrainTasks(isolate);
    uv_run(loop, UV_RUN_NOWAIT);
    isolate->PerformMicrotaskCheckpoint();
  }

  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);

  platform->DrainTasks(isolate);
  uv_run(loop, UV_RUN_NOWAIT);
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

  node::LoadEnvironment(env, env_js ? const_cast<char*>(env_js) : const_cast<char*>(""));

  auto* platform = Runtime::Get().platform();
  auto* loop     = Runtime::Get().loop();

  for (int i = 0; i < opts.max_pumps; ++i) {
    platform->DrainTasks(isolate);
    uv_run(loop, UV_RUN_NOWAIT);
    isolate->PerformMicrotaskCheckpoint();
  }

  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);

  platform->DrainTasks(isolate);
  uv_run(loop, UV_RUN_NOWAIT);
}

// ---------- Shared libFuzzer initializer (process-wide) ----------
extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
  // Keep Node from picking up host flags
  uv_os_unsetenv("NODE_OPTIONS");

  // === Mirror cctest NodeTestEnvironment::SetUp ===
  g_tracing_agent = std::make_unique<node::tracing::Agent>();
  node::tracing::TraceEventHelper::SetAgent(g_tracing_agent.get());
  node::tracing::TracingController* tracing_controller =
      g_tracing_agent->GetTracingController();

  static constexpr int kV8ThreadPoolSize = 4;
  g_platform = std::make_unique<node::NodePlatform>(kV8ThreadPoolSize, tracing_controller);
  v8::V8::InitializePlatform(g_platform.get());

  cppgc::InitializeProcess(g_platform->GetPageAllocator());

  // Allow flags per test if ever needed (same as cctest)
  v8::V8::SetFlagsFromString("--no-freeze-flags-after-init");

  v8::V8::Initialize();

  // Abseil deadlock detection disabled (as in cctest)
  absl::SetMutexDeadlockDetectionMode(absl::OnDeadlockCycle::kIgnore);

  // Initialize libuv loop we use for isolate data
  if (uv_loop_init(&g_loop) != 0) {
    // Optional: handle error; usually safe to proceed in fuzzer context
  }

  // === Node per-process initialization (public API) ===
  // Use flags bundle that tells Node we already initialized V8 & platform, etc.
  std::vector<std::string> node_argv{ "fuzz_env" };
  (void) node::InitializeOncePerProcess(
      node_argv,
      node::ProcessInitializationFlags::kLegacyInitializeNodeWithArgsBehavior);

  // Ensure we clean up at process exit (like cctest TearDown)
  std::atexit(&GlobalShutdown);
  return 0;
}

}  // namespace fuzz
