#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_common.h"
#include "fuzz_js_precompiled.h"

namespace {
v8::Global<v8::Function> g_fn;
constexpr const char* kSrc=R"JS((function(s){ const path=require('path'); return path.basename(s); }))JS";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n){
  const std::string s(reinterpret_cast<const char*>(d), n);
  fuzz::RunInEnvironment(nullptr,[&](node::Environment*, v8::Local<v8::Context> ctx){
    v8::Isolate* iso=ctx->GetIsolate();
    if(!fuzz::precompiled::EnsureFn(iso,ctx,kSrc,g_fn))return;
    v8::Local<v8::String> arg; if(!fuzz::precompiled::NewUtf8String(iso,s,&arg))return;
    v8::Local<v8::Value> argv[1]={arg};
    fuzz::precompiled::CallNoThrow(iso,ctx,g_fn.Get(iso),1,argv);
  }); return 0;
}
