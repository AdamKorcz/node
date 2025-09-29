#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

// Uses double quotes consistently for PEM/host inputs.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string pem    = p.ConsumeRandomLengthString(512);
  std::string email  = p.ConsumeRandomLengthString(64);
  std::string host1  = p.ConsumeRandomLengthString(64);
  std::string host2  = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const { X509Certificate } = require('node:crypto');
try {
  const x = new X509Certificate({0});
  x.checkEmail({1});
  x.checkHost({2});
  x.checkHost({3}, { subject: 'always' });
  void x.fingerprint; void x.fingerprint512; void x.issuer; void x.subject;
} catch (e) {}
)";

  const std::string js = FormatJs(
      kTemplate,
      ToDoubleQuotedJsLiteral(pem),
      ToDoubleQuotedJsLiteral(email),
      ToDoubleQuotedJsLiteral(host1),
      ToDoubleQuotedJsLiteral(host2));

  fuzz::IsolateScope iso; if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
