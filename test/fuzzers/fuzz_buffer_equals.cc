#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string s1 = p.ConsumeRandomLengthString(64);
  std::string s2 = p.ConsumeRandomLengthString(64);

  static constexpr std::string_view kTemplate = R"(
const buffer1 = Buffer.from({0});
const buffer2 = Buffer.from({1});
const _ = buffer1.equals(buffer2);
)";

  const std::string js =
      FormatJs(kTemplate, ToSingleQuotedJsLiteral(s1), ToSingleQuotedJsLiteral(s2));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
