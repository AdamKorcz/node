#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

// Simple serialize->deserialize round-trip on fuzzed string.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string s = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const v8 = require('v8');
try { v8.deserialize(v8.serialize({0})); } catch (e) {}
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(s));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
