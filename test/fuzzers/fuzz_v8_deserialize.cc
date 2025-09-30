#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

// serialize -> deserialize round-trip on a string (matches original)
namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(s){
    const v8 = require('v8');
    try { v8.deserialize(v8.serialize(s)); } catch (_e) {}
  })
)JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  FuzzedDataProvider p(data, size);
  const std::string s = p.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    v8::Local<v8::String> arg;
    if (!fuzz::precompiled::NewUtf8String(iso, s, &arg)) return;
    v8::Local<v8::Value> argv[1] = { arg };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 1, argv);
  });
  return 0;
}
