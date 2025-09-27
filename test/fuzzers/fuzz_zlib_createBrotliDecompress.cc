#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string s = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const zlib = require('zlib');
const dec = zlib.createBrotliDecompress();
try {
  dec.write(Buffer.from({0}, 'latin1'));
  dec.flush();
} catch (e) {}
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(s));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
