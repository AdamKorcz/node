#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc = R"JS(
  (function(content){
    const fs = require('fs');
    try { fs.rmSync('fuzz-file', { force: true }); } catch {}
    fs.writeFileSync('fuzz-file', content);
    const buffer = Buffer.alloc(1024);
    fs.open('fuzz-file', 'r+', function (err, fd) {
      if (err) return;
      fs.read(fd, buffer, 0, buffer.length, 0, function (e, bytes) {
        try {
          if (!e && bytes > 0) buffer.slice(0, bytes).toString();
        } finally {
          try { fs.close(fd, ()=>{}); } catch {}
        }
      });
    });
  })
)JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string s(reinterpret_cast<const char*>(data), size);
  fuzz::RunInEnvironment(nullptr, [&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso=ctx->GetIsolate();
    if (!fuzz::precompiled::EnsureFn(iso, ctx, kSrc, g_fn)) return;
    v8::Local<v8::String> arg; if (!fuzz::precompiled::NewUtf8String(iso, s, &arg)) return;
    v8::Local<v8::Value> argv[1] = { arg };
    fuzz::precompiled::CallNoThrow(iso, ctx, g_fn.Get(iso), 1, argv);
  });
  return 0;
}
