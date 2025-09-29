#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "fuzz_common.h"
#include "fuzz_js_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider prov(data, size);
  std::string s1 = prov.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(const fs = require('fs');

const buffer = Buffer.alloc(1024);

try { fs.rmSync('fuzz-file', { force: true }); } catch {}

fs.writeFileSync('fuzz-file', {0});

fs.open('fuzz-file', 'r+', function (err, fd) {
  if (err) { var _ = err; return; }

  fs.read(fd, buffer, 0, buffer.length, 0, function (err, bytes) {
    if (err) { var _ = err; return; }
    if (bytes > 0) {
      var _ = buffer.slice(0, bytes).toString();
    }
  });
});
)";

  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(s1));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
