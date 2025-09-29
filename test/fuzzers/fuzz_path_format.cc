#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

// If you actually pass an object to path.format in your current fuzzer,
// keep it; here we keep the string input pattern for parity.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string s = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const path = require('path');
try { path.format({0}); } catch (e) {}
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(s));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
