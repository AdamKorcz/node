#include <cstdint>
#include <string>
#include "FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

// Uses double-quoted literal for Buffer.from("...", "utf-8")
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  std::string payload = p.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const { HTTPParser } = require('_http_common');
const { REQUEST } = HTTPParser;

function newParser(type) {
  const parser = new HTTPParser();
  parser.initialize(type, {});
  parser[HTTPParser.kOnHeaders] = function() {};
  parser[HTTPParser.kOnHeadersComplete] = function() {};
  parser[HTTPParser.kOnBody] = function() {};
  parser[HTTPParser.kOnMessageComplete] = function() {};
  return parser;
}

const request = Buffer.from({0}, 'utf-8');
const parser = newParser(REQUEST);
try { parser.execute(request, 0, request.length); } catch (e) {}
)";

  const std::string js = FormatJs(kTemplate, ToDoubleQuotedJsLiteral(payload));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
