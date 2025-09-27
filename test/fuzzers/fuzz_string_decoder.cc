#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string r1 = p.ConsumeRandomLengthString(64);
  std::string r2 = p.ConsumeRandomLengthString(64);
  std::string r3 = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const { StringDecoder } = require('node:string_decoder');
const decoder = new StringDecoder('utf8');
decoder.write(Buffer.from({0}, 'utf8'));
decoder.write(Buffer.from({1}, 'utf8'));
decoder.end(Buffer.from({2}, 'utf8'));
)";

  const std::string js = FormatJs(
      kTemplate,
      ToSingleQuotedJsLiteral(r1),
      ToSingleQuotedJsLiteral(r2),
      ToSingleQuotedJsLiteral(r3));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
