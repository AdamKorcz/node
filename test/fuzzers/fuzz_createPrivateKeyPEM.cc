#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string key = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
require('crypto');
var privateKey = crypto.createPrivateKey({ key: {0}, format: 'pem' });
try {
  crypto.createPublicKey({ key: privateKey, format: 'pem' });
} catch (e) {}
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(key));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
