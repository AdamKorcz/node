#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider prov(data, size);
  std::string s1 = prov.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(const { Blob } = require('node:buffer');
const blob = new Blob([{0}]);
const _ = blob.text();
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(s1));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::EnvRunOptions opts;
  opts.max_pumps = 4;
  fuzz::RunEnvString(iso.isolate(), js.c_str(), opts);
  return 0;
}
