#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

// Stream-like API; still fine with drain-until-idle.
namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(ab){
    const zlib = require('zlib');
    const dec = zlib.createBrotliDecompress();
    try {
      dec.write(Buffer.from(ab));
      dec.flush();
    } catch (_e) {}
  })
)JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  FuzzedDataProvider p(data, size);
  const std::string bytes = p.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    auto ab = fuzz::precompiled::CopyToArrayBuffer(iso, bytes.data(), bytes.size());
    v8::Local<v8::Value> argv[1] = { ab };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 1, argv);
  });
  return 0;
}
