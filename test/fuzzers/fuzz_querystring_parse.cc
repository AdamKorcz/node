#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

// Reuses s1; also parses with custom sep/eq.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string s1 = p.ConsumeRandomLengthString(64);
  std::string s2 = p.ConsumeRandomLengthString(4);
  std::string s3 = p.ConsumeRemainingBytesAsString().substr(0, 4);

  static constexpr std::string_view kTemplate = R"(
const querystring = require('querystring');
let _ = querystring.parse({0});
let __ = querystring.parse({0}, {1}, {2});
)";

  const std::string js = FormatJs(
      kTemplate,
      ToSingleQuotedJsLiteral(s1),
      ToSingleQuotedJsLiteral(s2),
      ToSingleQuotedJsLiteral(s3));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
