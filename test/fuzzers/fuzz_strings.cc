/*
 * A fuzzer focused on C string -> Javascript String using N-API.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include "js_native_api.h"
#include "js_native_api_v8.h"
#include "node.h"
#include "node_internals.h"
#include "node_api_internals.h"
#include "env-inl.h"
#include "util-inl.h"
#include "v8.h"

#include "fuzz_common.h"  // IsolateScope + RunInEnvironment

// Optional: same deleter you had (not currently used)
static void free_string(node_api_nogc_env /*env*/, void* data, void* /*hint*/) {
  std::free(data);
}

// Static used only to receive env from addon init; reset every run.
static napi_env g_addon_env = nullptr;

// Non-capturing addon init to receive napi_env
static napi_value CaptureEnvInit(napi_env env, napi_value exports) {
  g_addon_env = env;
  return exports;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* bytes = reinterpret_cast<const char*>(data);
  std::string s(bytes, size);

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;

  // Fresh Context + Environment for this input
  fuzz::RunInEnvironment(iso.isolate(),
    [&](node::Environment* /*env*/, v8::Local<v8::Context> context) {
      g_addon_env = nullptr;  // reset before registering

      // Create module/exports objects and register a dummy addon to obtain napi_env.
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      v8::Local<v8::Object> module_obj  = v8::Object::New(isolate);
      v8::Local<v8::Object> exports_obj = v8::Object::New(isolate);

      napi_module_register_by_symbol(
          exports_obj, module_obj, context, &CaptureEnvInit, NAPI_VERSION);

      napi_env addon_env = g_addon_env;
      if (addon_env == nullptr) {
        // Couldn’t get an env; bail out gracefully.
        return;
      }

      // ---- Your original N-API string ops (unchanged in spirit) ----
      size_t copied1 = 0, copied2 = 0;
      bool copied3 = false;
      napi_value output1, output2, output3, output4, output5, output6, output7,
                 output8, output9, output10, output11, output12;

      // Allocate temp buffers (respecting size)
      char* buf1 = static_cast<char*>(std::malloc(size ? size : 1));
      char* buf2 = static_cast<char*>(std::malloc(size ? size : 1));
      if (!buf1 || !buf2) {
        std::free(buf1); std::free(buf2);
        return;
      }

      // create/get UTF-8
      (void) napi_create_string_utf8(addon_env, s.data(), size, &output1);
      (void) napi_get_value_string_utf8(addon_env, output1, buf1, size, &copied1);

      // create/get Latin-1
      (void) napi_create_string_latin1(addon_env, s.data(), size, &output2);
      (void) napi_get_value_string_latin1(addon_env, output2, buf2, size, &copied2);

      // symbol.for
      (void) node_api_symbol_for(addon_env, s.data(), size, &output4);

      // Property ops using raw fuzz bytes for the property name
      (void) napi_set_named_property(addon_env, output1, s.c_str(), output2);
      (void) napi_get_named_property(addon_env, output1, s.c_str(), &output6);
      (void) napi_has_named_property(addon_env, output1, s.c_str(), &copied3);

      (void) napi_get_property_names(addon_env, output1, &output7);
      (void) napi_has_property(addon_env, output1, output2, &copied3);
      (void) napi_get_property(addon_env, output1, output2, &output8);
      (void) napi_delete_property(addon_env, output1, output2, &copied3);
      (void) napi_has_own_property(addon_env, output1, output2, &copied3);

      (void) napi_create_type_error(addon_env, output1, output2, &output9);
      (void) napi_create_range_error(addon_env, output1, output2, &output10);
      (void) node_api_create_syntax_error(addon_env, output1, output2, &output11);

      (void) napi_run_script(addon_env, output2, &output12);

      std::free(buf1);
      std::free(buf2);
      // ---------------------------------------------------------------

      g_addon_env = nullptr;  // avoid leakage across inputs
    },
    /*opts=*/fuzz::EnvRunOptions{
        node::EnvironmentFlags::kDefaultFlags,
        /*print_js_to_stdout=*/false,
        /*max_pumps=*/4  // give microtasks/callbacks a chance, still bounded
    });

  return 0;
}
