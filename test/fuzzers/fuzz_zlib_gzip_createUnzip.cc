#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string s = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const zlib = require('zlib');

zlib.gzip({0}, (err, data) => {
  if (err || !data) return;
  const unzip = zlib.createUnzip();
  unzip.on('data', (d) => { d.toString('utf8'); });
  unzip.write(data);
  unzip.end();
});
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(s));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
