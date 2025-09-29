#pragma once

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

// Process-wide plumbing (does NOT hold JS state between inputs)
struct Runtime {
  static Runtime& Get();              // singleton accessor
  uv_loop_t* loop();                  // uv loop used by Node
  node::NodePlatform* platform();     // V8/Node platform
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
  std::unique_ptr<node::ArrayBufferAllocator,
                  decltype(&node::FreeArrayBufferAllocator)> allocator_{
      node::CreateArrayBufferAllocator(), &node::FreeArrayBufferAllocator};
};

// Options for the one-off environment runner
struct EnvRunOptions {
  node::EnvironmentFlags::Flags flags = node::EnvironmentFlags::kDefaultFlags;
  bool print_js_to_stdout = false;
  int  max_pumps = 8;  // pump foreground tasks + libuv + microtasks up to N rounds
};

// Create a fresh Context/Environment, run JS, pump a bit, then tear down.
void RunEnvString(v8::Isolate* isolate,
                  const char* env_js,
                  const EnvRunOptions& opts = {});

}  // namespace fuzz
