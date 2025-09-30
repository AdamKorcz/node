#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(jwkStr){
    const crypto = require('crypto');
    const pk = crypto.createPrivateKey({ key: jwkStr, format: 'jwk' });
    try { crypto.createPublicKey({ key: pk, format: 'jwk' }); } catch {}
  })
)JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  const std::string key(reinterpret_cast<const char*>(data), size);
  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::String> s; if (!fuzz::precompiled::NewUtf8String(iso, key, &s)) return;
    v8::Local<v8::Value> argv[1] = { s };
    fuzz::precompiled::CallNoThrow(iso, ctx, g_fn.Get(iso), 1, argv);
  });
  return 0;
}
