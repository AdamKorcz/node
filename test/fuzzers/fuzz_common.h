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

// Shared runtime and helpers for all fuzzers.
// Replaces per-file FuzzerFixtureHelper, EnvTest, and LLVMFuzzerInitialize.


namespace fuzz {

// Add a bounded pump knob (defaults to a few ticks so async callbacks can run).
struct EnvRunOptions {
  node::EnvironmentFlags::Flags flags = node::EnvironmentFlags::kDefaultFlags;
  bool print_js_to_stdout = false;
  int  max_pumps = 8;  // run foreground tasks, uv loop, and microtasks up to N times
};

// Evaluate a one-off JS program inside a fresh Context/Environment.
void RunEnvString(v8::Isolate* isolate,
                  const char* env_js,
                  const EnvRunOptions& opts = {});

// RAII isolate scope (ctor unchanged; dtor updated in .cc below)
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

} // namespace fuzz