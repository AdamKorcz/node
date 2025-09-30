#include "fuzz_common.h"

#include <cassert>
#include <cstdlib>   // std::atexit
#include <string>
#include <unordered_map>
#include <vector>

#include "v8.h"
#include "uv.h"

// cppgc platform init/shutdown like cctest does
#include "cppgc/platform.h"

#if defined(__GLIBC__)
#include <malloc.h>  // malloc_trim
#endif

namespace fuzz {
namespace {

// Process-wide platform. No JS/Environment state lives here.
std::unique_ptr<node::NodePlatform> g_platform;

// Kept for API/back-compat; no longer used as the main allocator.
// (We now create a per-isolate allocator instead.)
std::unique_ptr<node::ArrayBufferAllocator,
                decltype(&node::FreeArrayBufferAllocator)> g_allocator{
    nullptr, &node::FreeArrayBufferAllocator};

// Each Isolate gets its own ArrayBuffer allocator so buffer pages are
// returned to the OS when the isolate dies (prevents long-run RSS creep).
using ABAUnique =
    std::unique_ptr<node::ArrayBufferAllocator, decltype(&node::FreeArrayBufferAllocator)>;

static std::unordered_map<v8::Isolate*, ABAUnique> g_isolate_allocators;

// Per-iteration libuv loop (ownership lives in this TU), while Runtime::loop()
// returns a raw pointer (ABI compatibility with your header).
static thread_local std::unique_ptr<uv_loop_t> t_loop_owner;
static thread_local uv_loop_t* t_loop = nullptr;

// Helper: run Node platform tasks + libuv + microtasks once.
// Returns true if any progress was made.
static inline bool OnePump(v8::Isolate* isolate,
                           node::NodePlatform* platform,
                           uv_loop_t* loop) {
  bool progressed = false;
  platform->DrainTasks(isolate);
  progressed |= (uv_run(loop, UV_RUN_NOWAIT) != 0);
  isolate->PerformMicrotaskCheckpoint();
  return progressed;
}

// After Stop() we *must* give the close queue time to run so memory is freed.
// Drain up to `max_spins`, or stop earlier once the loop is idle (no pending
// or active handles and no platform work).
static inline void DrainUntilIdle(v8::Isolate* isolate,
                                  node::NodePlatform* platform,
                                  uv_loop_t* loop,
                                  int max_spins = 256) {
  for (int i = 0; i < max_spins; ++i) {
    const bool progressed = OnePump(isolate, platform, loop);
    if (!progressed && !uv_loop_alive(loop)) break;
  }
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

  // Any legacy process-wide allocator (unused now) — free it if present.
  g_allocator.reset();
}

}  // namespace

// ---------- Runtime ----------
Runtime& Runtime::Get() {
  static Runtime rt;
  return rt;
}
uv_loop_t* Runtime::loop() { return t_loop; }  // per-iteration loop
node::NodePlatform* Runtime::platform() { return g_platform.get(); }

// Kept for API compatibility; per-isolate allocators are used instead.
node::ArrayBufferAllocator* Runtime::allocator() { return g_allocator.get(); }

// ---------- IsolateScope ----------
IsolateScope::IsolateScope() {
  // Create a fresh libuv loop *per iteration* so libuv’s internal arrays
  // don’t accumulate capacity across runs.
  t_loop_owner = std::make_unique<uv_loop_t>();
  if (uv_loop_init(t_loop_owner.get()) != 0) {
    t_loop_owner.reset();
    t_loop = nullptr;
    return;
  }
  t_loop = t_loop_owner.get();

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
  } else {
    // If we failed to create an isolate, clean up the loop.
    uv_loop_close(t_loop_owner.get());
    t_loop_owner.reset();
    t_loop = nullptr;
  }
}

IsolateScope::~IsolateScope() {
  // The Environment should already be torn down by the caller (Run* functions).
  if (isolate_) {
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

  if (t_loop_owner) {
    // We expect the loop to be idle now; close it and free its internal arrays.
    int rc = uv_loop_close(t_loop_owner.get());
    if (rc != 0) {
      // Try to make progress without an isolate (libuv-only).
      for (int i = 0; i < 256 && uv_loop_alive(t_loop_owner.get()); ++i) {
        uv_run(t_loop_owner.get(), UV_RUN_NOWAIT);
      }
      rc = uv_loop_close(t_loop_owner.get());
    }
    // In fuzzing we prefer to be assertive; if needed, relax this.
    assert(rc == 0 && "uv_loop_close failed: some handles still alive");

    t_loop_owner.reset();
    t_loop = nullptr;
  }

#if defined(__GLIBC__)
  // Help the system RSS keep up with freed memory between iterations.
  malloc_trim(0);
#endif
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
  if (opts.max_pumps > 0) {
    for (int i = 0; i < opts.max_pumps; ++i) {
      if (!OnePump(isolate, platform, loop)) break;
    }
  }

  // Portable shutdown: RunAtExit → Stop → drain-until-idle → free.
  node::RunAtExit(env);
  node::Stop(env);

  // Unconditional final drain so uv_close completions free memory.
  DrainUntilIdle(isolate, platform, loop);

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

  // Optional pre-stop pump (caller-controlled).
  if (opts.max_pumps > 0) {
    for (int i = 0; i < opts.max_pumps; ++i) {
      if (!OnePump(isolate, platform, loop)) break;
    }
  }

  // Portable shutdown: RunAtExit → Stop → drain-until-idle → free.
  node::RunAtExit(env);
  node::Stop(env);

  // Unconditional final drain so uv_close completions free memory.
  DrainUntilIdle(isolate, platform, loop);

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

  // Note: libuv loop is now per-iteration (owned by IsolateScope), so we do
  // not initialize a process-wide loop here.

  // We also no longer pre-create a process-wide ArrayBuffer allocator. Each
  // Isolate gets its own allocator (see IsolateScope).

  // Ensure cleanup at process exit
  std::atexit(&GlobalShutdown);
  return 0;
}

}  // namespace fuzz
