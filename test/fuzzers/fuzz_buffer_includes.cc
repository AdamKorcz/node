#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string hay = p.ConsumeRandomLengthString(64);
  std::string needle = p.ConsumeRandomLengthString(16);

  static constexpr std::string_view kTemplate = R"(
const buffer1 = Buffer.from({0});
const checkStr = {1};
const _ = buffer1.includes(checkStr);
)";

  const std::string js =
      FormatJs(kTemplate, ToSingleQuotedJsLiteral(hay), ToSingleQuotedJsLiteral(needle));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
