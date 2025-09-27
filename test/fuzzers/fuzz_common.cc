#include "fuzz_common.h"

#include "v8.h"
#include "uv.h"

namespace fuzz {

// --- IsolateScope ---

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

  // Prefer the helper if available (newer Node).
  // If your NodePlatform doesn't have DisposeIsolate(), fall back to the pair.
#if defined(NODE_PLATFORM_HAS_DISPOSE_ISOLATE)
  platform->DisposeIsolate(isolate_);
#else
  platform->UnregisterIsolate(isolate_);
  isolate_->Dispose();
#endif

  isolate_ = nullptr;
}

// --- RunEnvString ---

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
    bool progressed = false;

    // Run V8/Node foreground tasks (e.g., Promise continuations scheduled there).
    progressed |= platform->FlushForegroundTasks(isolate);

    // Drive libuv once without blocking (process due I/O, timers, etc.).
    progressed |= (uv_run(loop, UV_RUN_NOWAIT) != 0);

    // Run microtasks (Promises).
    isolate->PerformMicrotaskCheckpoint();

    if (!progressed) break;  // nothing left to do
  }

  // Tear down this Environment/IsolateData (no cross-input state).
  node::FreeEnvironment(env);
  node::FreeIsolateData(isolate_data);

  // Best-effort nudge to leave things tidy (no-op if already quiescent).
  platform->FlushForegroundTasks(isolate);
  uv_run(loop, UV_RUN_NOWAIT);
}

} // namespace fuzz
