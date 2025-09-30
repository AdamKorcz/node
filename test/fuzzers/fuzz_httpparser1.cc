#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
// Use ArrayBuffer to avoid string transcoding differences.
constexpr const char* kSrc = R"JS(
  (function(ab){
    const { HTTPParser } = require('_http_common');
    const { REQUEST } = HTTPParser;
    function newParser(type) {
      const parser = new HTTPParser();
      parser.initialize(type, {});
      parser[HTTPParser.kOnHeaders] = function() {};
      parser[HTTPParser.kOnHeadersComplete] = function() {};
      parser[HTTPParser.kOnBody] = function() {};
      parser[HTTPParser.kOnMessageComplete] = function() {};
      return parser;
    }
    const request = Buffer.from(ab);
    const parser = newParser(REQUEST);
    try { parser.execute(request, 0, request.length); } catch {}
  })
)JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
  const std::string payload(reinterpret_cast<const char*>(data), size);
  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso=ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    auto ab = fuzz::precompiled::CopyToArrayBuffer(iso, payload.data(), payload.size());
    v8::Local<v8::Value> argv[1] = { ab };
    fuzz::precompiled::CallNoThrow(iso, ctx, g_fn.Get(iso), 1, argv);
  });
  return 0;
}
