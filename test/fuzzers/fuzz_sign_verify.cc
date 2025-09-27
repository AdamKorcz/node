#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string chunk = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const Stream = require('stream');
const readable = new Stream.Readable({ read() {} });

readable.push({0});
readable.push(null);

(async () => {
  for await (const c of readable) { c.toString(); }
})().catch(() => {});
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(chunk));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
