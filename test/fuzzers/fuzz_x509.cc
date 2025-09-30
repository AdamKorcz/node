#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

// PEM + host/email checks (same behavior as original)
namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(pem, email, host1, host2){
    const { X509Certificate } = require('node:crypto');
    try {
      const x = new X509Certificate(pem);
      x.checkEmail(email);
      x.checkHost(host1);
      x.checkHost(host2, { subject: 'always' });
      void x.fingerprint; void x.fingerprint512; void x.issuer; void x.subject;
    } catch (_e) {}
  })
)JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  FuzzedDataProvider p(data, size);
  const std::string pem   = p.ConsumeRandomLengthString(512);
  const std::string email = p.ConsumeRandomLengthString(64);
  const std::string host1 = p.ConsumeRandomLengthString(64);
  const std::string host2 = p.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    v8::Local<v8::String> a0, a1, a2, a3;
    if (!fuzz::precompiled::NewUtf8String(iso, pem,   &a0)) return;
    if (!fuzz::precompiled::NewUtf8String(iso, email, &a1)) return;
    if (!fuzz::precompiled::NewUtf8String(iso, host1, &a2)) return;
    if (!fuzz::precompiled::NewUtf8String(iso, host2, &a3)) return;

    v8::Local<v8::Value> argv[4] = { a0, a1, a2, a3 };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 4, argv);
  });
  return 0;
}
