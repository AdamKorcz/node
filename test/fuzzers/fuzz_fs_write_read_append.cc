#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

// Combines write/read/append operations on a temp file with fuzzed data.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string w1 = p.ConsumeRandomLengthString(256);
  std::string w2 = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const fs = require('fs');

try { fs.rmSync('/tmp/fuzz-file', { force: true }); } catch (e) {}

fs.writeFileSync('/tmp/fuzz-file', {0});

try {
  const fd = fs.openSync('/tmp/fuzz-file', 'r+');
  const buffer = Buffer.alloc(1024);
  fs.readSync(fd, buffer, 0, buffer.length, 0);
  fs.closeSync(fd);
} catch (e) {}

const textToAppend = {1};
try {
  fs.appendFileSync('/tmp/fuzz-file', textToAppend, { encoding: 'utf8' });
  fs.readFileSync('/tmp/fuzz-file', { encoding: 'utf8' });
} catch (e) {}
)";

  const std::string js =
      FormatJs(kTemplate, ToSingleQuotedJsLiteral(w1), ToSingleQuotedJsLiteral(w2));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
