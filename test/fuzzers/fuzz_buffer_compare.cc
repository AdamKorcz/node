#include <cstdint>
#include <string>
#include <cstring>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"

namespace {
v8::Global<v8::Function> g_fn;

inline void EnsureFn(v8::Isolate* iso, v8::Local<v8::Context> ctx) {
  if (!g_fn.IsEmpty()) return;
  const char* src = R"JS(
    (function(a, b) {
      // Share backing stores (no copy)
      const A = Buffer.from(a);
      const B = Buffer.from(b);
      return Buffer.compare(A, B);
    })
  )JS";
  v8::Local<v8::String> s;
  if (!v8::String::NewFromUtf8(iso, src).ToLocal(&s)) return;
  v8::Local<v8::Script> script;
  if (!v8::Script::Compile(ctx, s).ToLocal(&script)) return;
  v8::Local<v8::Value> fn;
  if (!script->Run(ctx).ToLocal(&fn)) return;
  g_fn.Reset(iso, fn.As<v8::Function>());
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const std::string s1 = p.ConsumeRandomLengthString(64);
  const std::string s2 = p.ConsumeRandomLengthString(64);

  fuzz::RunInEnvironment(nullptr,
    [&](node::Environment*, v8::Local<v8::Context> ctx) {
      v8::Isolate* iso = ctx->GetIsolate();
      EnsureFn(iso, ctx);
      v8::Local<v8::Function> fn = g_fn.Get(iso);

      v8::Local<v8::ArrayBuffer> a = v8::ArrayBuffer::New(iso, s1.size());
      v8::Local<v8::ArrayBuffer> b = v8::ArrayBuffer::New(iso, s2.size());
      if (!s1.empty()) std::memcpy(a->GetBackingStore()->Data(), s1.data(), s1.size());
      if (!s2.empty()) std::memcpy(b->GetBackingStore()->Data(), s2.data(), s2.size());

      v8::Local<v8::Value> argv[2] = { a, b };
      v8::TryCatch tc(iso);
      (void)fn->Call(ctx, v8::Undefined(iso), 2, argv);
    });
  return 0;
}
