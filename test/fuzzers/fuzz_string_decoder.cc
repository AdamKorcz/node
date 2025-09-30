#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(a, b, c){
    const { StringDecoder } = require('node:string_decoder');
    const decoder = new StringDecoder('utf8');
    decoder.write(Buffer.from(a));
    decoder.write(Buffer.from(b));
    decoder.end(Buffer.from(c));
  })
)JS";
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  FuzzedDataProvider p(data, size);
  const std::string r1 = p.ConsumeRandomLengthString(64);
  const std::string r2 = p.ConsumeRandomLengthString(64);
  const std::string r3 = p.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    auto a0 = fuzz::precompiled::CopyToArrayBuffer(iso, r1.data(), r1.size());
    auto a1 = fuzz::precompiled::CopyToArrayBuffer(iso, r2.data(), r2.size());
    auto a2 = fuzz::precompiled::CopyToArrayBuffer(iso, r3.data(), r3.size());

    v8::Local<v8::Value> argv[3] = { a0, a1, a2 };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 3, argv);
  });
  return 0;
}
