#include "fuzz_common.h"

#include "v8.h"
// If your V8 build has cppgc and Node uses it, you can include and init it.
// It’s safe to omit if unavailable.
// #include "cppgc/common.h"

#include "uv.h"

// These headers exist in Node’s source; if your include paths differ, you can
// drop the tracing agent and pass nullptr when constructing NodePlatform.
#include "tracing/agent.h"
#include "tracing/trace_event.h"

namespace fuzz {
namespace {
// Process-wide state (no JS/Env state is kept here)
std::unique_ptr<node::tracing::Agent> g_tracing_agent;
std::unique_ptr<node::NodePlatform>   g_platform;
uv_loop_t                              g_loop;
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

  // Drain any remaining foreground tasks scheduled by V8/Node.
  platform->DrainTasks(isolate_);

  // Leave the isolate before disposal.
  isolate_->Exit();

  // Version-tolerant teardown: always supported
  platform->UnregisterIsolate(isolate_);
  isolate_->Dispose();

  isolate_ = nullptr;
}

// ---------- RunEnvString ----------
void RunEnvString(v8::Isolate* isolate,
                  const char* env_js,
                  const EnvRunOptions& opts) {
  if (opts.print_js_to_stdout && env_js) {
    fprintf(stdout, "%s\n", env_js);
  }

  // Fresh handle scope + context per invocation (stateless across inputs).
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Context> context = node::NewContext(isolate);
  v8::Context::Scope context_scope(context);

  node::IsolateData* isolate_data =
      node::CreateIsolateData(isolate, Runtime::Get().loop(), Runtime::Get().platform());

  std::vector<std::string> args{ "node" };  // argv[0] only
  std::vector<std::string> exec_args;

  node::Environment* env =
      node::CreateEnvironment(isolate_data, context, args, exec_args, opts.flags);

  // Load & run entrypoint synchronously.
  node::LoadEnvironment(env, env_js ? const_cast<char*>(env_js) : const_cast<char*>(""));

  // Bounded event-loop & microtask pumping so async callbacks get a chance.
  auto* platform = Runtime::Get().platform();
  auto* loop     = Runtime::Get().loop();

  for (int i = 0; i < opts.max_pumps; ++i) {
    // Run V8/Node foreground tasks.
    platform->DrainTasks(isolate);

    // Drive libuv once without blocking (process due I/O, timers, etc.).
    uv_run(loop, UV_RUN_NOWAIT);

    // Run microtasks (Promises).
    isolate->PerformMicrotaskCheckpoint();
  }

  // Tear down this Environment/IsolateData (no cross-input state).
  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);

  // Best-effort nudge to leave things tidy (no-op if already quiescent).
  platform->DrainTasks(isolate);
  uv_run(loop, UV_RUN_NOWAIT);
}

// ---------- Shared libFuzzer initializer ----------
extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
  // Keep the process environment clean for Node/V8.
  uv_os_unsetenv("NODE_OPTIONS");

  std::vector<std::string> node_argv{ "fuzz_env" };
  std::vector<std::string> exec_argv;
  std::vector<std::string> errors;
  node::InitializeNodeWithArgs(&node_argv, &exec_argv, &errors);

  // Tracing is optional; if these headers aren't available, you can set the
  // tracing controller to nullptr and skip TraceEventHelper.
  g_tracing_agent = std::make_unique<node::tracing::Agent>();
  node::tracing::TraceEventHelper::SetAgent(g_tracing_agent.get());
  auto* tracing_controller = g_tracing_agent->GetTracingController();

  // Init loop and platform
  if (uv_loop_init(&g_loop) != 0) {
    // If you prefer, handle the error or abort; fuzzers usually just proceed.
  }

  constexpr int kV8ThreadPoolSize = 4;
  g_platform = std::make_unique<node::NodePlatform>(kV8ThreadPoolSize, tracing_controller);

  v8::V8::InitializePlatform(g_platform.get());
  // If your build has cppgc available and Node expects it, you may enable:
  // cppgc::InitializeProcess(g_platform->GetPageAllocator());
  v8::V8::Initialize();

  return 0;
}

}  // namespace fuzz
