#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(ab){
    const { Blob } = require('node:buffer');
    return new Blob([Buffer.from(ab)]).text(); // Promise
  })
)JS";
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider prov(data, size);
  const std::string s1 = prov.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    auto ab = fuzz::precompiled::CopyToArrayBuffer(iso, s1.data(), s1.size());
    v8::Local<v8::Value> argv[1] = { ab };
    fuzz::precompiled::CallNoThrow(iso, ctx, g_fn.Get(iso), 1, argv);
  });
  return 0;
}
