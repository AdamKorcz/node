#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(a, b) {
    const path = require('path');
    return path.join(a, b);
  })
)JS";
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const std::string s1 = p.ConsumeRandomLengthString(64);
  const std::string s2 = p.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx) {
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    v8::Local<v8::String> a, b;
    if (!fuzz::precompiled::NewUtf8String(iso, s1, &a)) return;
    if (!fuzz::precompiled::NewUtf8String(iso, s2, &b)) return;

    v8::Local<v8::Value> argv[2] = { a, b };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 2, argv);
  });

  return 0;
}