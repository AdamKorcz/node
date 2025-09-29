#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "node.h"
#include "node_internals.h"
#include "node_platform.h"
#include "env-inl.h"
#include "libplatform/libplatform.h"
#include "uv.h"

namespace fuzz {

// Process-wide plumbing (does NOT hold JS/Environment state between inputs)
struct Runtime {
  static Runtime& Get();                 // singleton accessor
  uv_loop_t* loop();                     // process uv loop used by Node
  node::NodePlatform* platform();        // V8/Node platform
  node::ArrayBufferAllocator* allocator(); // process-wide ArrayBuffer allocator
private:
  Runtime() = default;
};

// RAII per-input isolate (fresh JS heap each call)
class IsolateScope {
 public:
  IsolateScope();
  ~IsolateScope();
  v8::Isolate* isolate() const { return isolate_; }
  bool ok() const { return isolate_ != nullptr; }
 private:
  v8::Isolate* isolate_{nullptr};
};

// Options for the one-off environment runners
struct EnvRunOptions {
  node::EnvironmentFlags::Flags flags = node::EnvironmentFlags::kDefaultFlags;
  bool print_js_to_stdout = false;
  // Pump foreground tasks + libuv + microtasks up to N rounds.
  // Most fuzzers are synchronous; override to small N (e.g., 2–4) in async fuzzers.
  int  max_pumps = 0;
};

// Evaluate a JS program string inside a fresh Context/Environment, then tear down.
void RunEnvString(v8::Isolate* isolate,
                  const char* env_js,
                  const EnvRunOptions& opts = {});

// Run arbitrary code inside a fresh Context/Environment (after Node bootstrap),
// then perform a proper Node shutdown and tear down.
using EnvCallback = std::function<void(node::Environment*, v8::Local<v8::Context>)>;

void RunInEnvironment(v8::Isolate* isolate,
                      EnvCallback cb,
                      const EnvRunOptions& opts = {});

}  // namespace fuzz
