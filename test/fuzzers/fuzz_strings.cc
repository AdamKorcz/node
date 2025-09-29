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

// Optional: a deleter you had, kept for parity (currently unused)
static void free_string(node_api_nogc_env /*env*/, void* data, void* /*hint*/) {
  std::free(data);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Treat input bytes as an arbitrary C string payload (may contain NULs).
  const char* bytes = reinterpret_cast<const char*>(data);
  std::string s(bytes, size);

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;

  // Run all N-API work inside a fresh Node Environment.
  fuzz::RunInEnvironment(iso.isolate(),
    [&](node::Environment* /*env*/, v8::Local<v8::Context> context) {
      // We’ll capture the new N-API env via a tiny addon init.
      napi_env addon_env = nullptr;

      napi_addon_register_func init = [](napi_env env, napi_value exports) {
        // Capture env in a thread-local so we can read it outside the lambda
        // (but here we just stash via the outer capture).
        // We’ll actually bind this lambda below with our capture through
        // napi_module_register_by_symbol, which forwards env.
        return exports;
      };

      // Create module/exports objects and register a dummy addon to obtain napi_env.
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      v8::Local<v8::Object> module_obj  = v8::Object::New(isolate);
      v8::Local<v8::Object> exports_obj = v8::Object::New(isolate);

      // Wrap init so we can set addon_env when Node calls it.
      napi_addon_register_func init_capture = [](napi_env env, napi_value exports) -> napi_value {
        // Store env into an external so we can pull it back; simplest is a static,
        // but we’ll instead use napi_set_instance_data to keep it scoped.
        napi_status st = napi_set_instance_data(env, env, nullptr, nullptr);
        (void)st;
        return exports;
      };

      // Register and retrieve the napi_env from instance data.
      napi_module_register_by_symbol(
          exports_obj, module_obj, context, init_capture, NAPI_VERSION);

      // Try to get the env we just set as instance data.
      {
        void* instance_data = nullptr;
        // napi_get_instance_data() is available in newer N-API; for older, we fallback.
#ifdef NAPI_VERSION
#if NAPI_VERSION >= 8
        napi_get_instance_data(addon_env, &instance_data);  // if addon_env set
#endif
#endif
        // If we didn't get env via instance data, we can also use the
        // internal helper to fetch from the current context:
        if (instance_data == nullptr) {
          // node_api_get_env() is internal; when available:
          addon_env = node::Environment::GetCurrent(context)->napi_env();
        } else {
          addon_env = static_cast<napi_env>(instance_data);
        }
      }

      if (addon_env == nullptr) {
        // As a fallback, try directly from Environment (Node 16+)
        addon_env = node::Environment::GetCurrent(context)->napi_env();
      }

      if (addon_env == nullptr) return;  // give up quietly if we couldn’t init

      // ---- Begin original N-API string ops (adapted) ----
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

      // Property ops (name is the raw fuzz bytes; if it contains NUL, N-API may fail — that’s fine)
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

      // Run as script (napi_run_script)
      (void) napi_run_script(addon_env, output2, &output12);

      std::free(buf1);
      std::free(buf2);
      // ---- End N-API ops ----
    },
    /*opts=*/fuzz::EnvRunOptions{node::EnvironmentFlags::kDefaultFlags, /*print*/false, /*max_pumps*/4});

  return 0;
}
