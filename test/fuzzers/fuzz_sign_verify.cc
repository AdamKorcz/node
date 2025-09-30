#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(s) {
    const Stream = require('stream');
    const readable = new Stream.Readable({ read() {} });
    readable.push(s);
    readable.push(null);
    (async () => {
      for await (const c of readable) { c.toString(); }
    })().catch(() => {});
  })
)JS";
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  FuzzedDataProvider p(data, size);
  std::string chunk = p.ConsumeRemainingBytesAsString();

  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso = ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::Function> fn = g_fn.Get(iso);

    v8::Local<v8::String> s;
    if (!fuzz::precompiled::NewUtf8String(iso, chunk, &s)) return;

    v8::Local<v8::Value> argv[1] = { s };
    fuzz::precompiled::CallNoThrow(iso, ctx, fn, 1, argv);
  });
  return 0;
}
