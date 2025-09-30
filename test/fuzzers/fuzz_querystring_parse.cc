#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(s1, s2, s3) {
    const querystring = require('querystring');
    let _  = querystring.parse(s1);
    let __ = querystring.parse(s1, s2, s3);
    return _;
  })
)JS";
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  FuzzedDataProvider p(data, size);
  std::string s1 = p.ConsumeRandomLengthString(64);
  std::string s2 = p.ConsumeRandomLengthString(4);
  std::string s3 = p.ConsumeRemainingBytesAsString().substr(0, 4);

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    v8::Local<v8::String> a0, a1, a2;
    if (!fuzz::precompiled::NewUtf8String(iso, s1, &a0)) return;
    if (!fuzz::precompiled::NewUtf8String(iso, s2, &a1)) return;
    if (!fuzz::precompiled::NewUtf8String(iso, s3, &a2)) return;

    v8::Local<v8::Value> argv[3] = { a0, a1, a2 };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 3, argv);
  });
  return 0;
}
