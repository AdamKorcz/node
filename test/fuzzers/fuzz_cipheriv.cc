#include <cstdint>
#include <string>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_common.h"
#include "fuzz_js_format.h"

// OpenSSL/Node cipher names (from your original list).
static const char* kCiphers[] = {
  "aes-128-cbc","aes-128-cbc-hmac-sha1","aes-128-cbc-hmac-sha256","aes-128-ccm","aes-128-cfb",
  "aes-128-cfb1","aes-128-cfb8","aes-128-ctr","aes-128-ecb","aes-128-gcm","aes-128-ocb","aes-128-ofb",
  "aes-128-xts","aes-192-cbc","aes-192-ccm","aes-192-cfb","aes-192-cfb1","aes-192-cfb8","aes-192-ctr",
  "aes-192-ecb","aes-192-gcm","aes-192-ocb","aes-192-ofb","aes-256-cbc","aes-256-cbc-hmac-sha1",
  "aes-256-cbc-hmac-sha256","aes-256-ccm","aes-256-cfb","aes-256-cfb1","aes-256-cfb8","aes-256-ctr",
  "aes-256-ecb","aes-256-gcm","aes-256-ocb","aes-256-ofb","aes-256-xts","aes128","aes128-wrap","aes192",
  "aes192-wrap","aes256","aes256-wrap","aria-128-cbc","aria-128-ccm","aria-128-cfb","aria-128-cfb1",
  "aria-128-cfb8","aria-128-ctr","aria-128-ecb","aria-128-gcm","aria-128-ofb","aria-192-cbc",
  "aria-192-ccm","aria-192-cfb","aria-192-cfb1","aria-192-cfb8","aria-192-ctr","aria-192-ecb",
  "aria-192-gcm","aria-192-ofb","aria-256-cbc","aria-256-ccm","aria-256-cfb","aria-256-cfb1",
  "aria-256-cfb8","aria-256-ctr","aria-256-ecb","aria-256-gcm","aria-256-ofb","aria128","aria192",
  "aria256","camellia-128-cbc","camellia-128-cfb","camellia-128-cfb1","camellia-128-cfb8",
  "camellia-128-ctr","camellia-128-ecb","camellia-128-ofb","camellia-192-cbc","camellia-192-cfb",
  "camellia-192-cfb1","camellia-192-cfb8","camellia-192-ctr","camellia-192-ecb","camellia-192-ofb",
  "camellia-256-cbc","camellia-256-cfb","camellia-256-cfb1","camellia-256-cfb8","camellia-256-ctr",
  "camellia-256-ecb","camellia-256-ofb","camellia128","camellia192","camellia256","chacha20",
  "chacha20-poly1305","des-ede","des-ede-cbc","des-ede-cfb","des-ede-ecb","des-ede-ofb","des-ede3",
  "des-ede3-cbc","des-ede3-cfb","des-ede3-cfb1","des-ede3-cfb8","des-ede3-ecb","des-ede3-ofb",
  "des3","des3-wrap","id-aes128-CCM","id-aes128-GCM","id-aes128-wrap","id-aes128-wrap-pad",
  "id-aes192-CCM","id-aes192-GCM","id-aes192-wrap","id-aes192-wrap-pad","id-aes256-CCM","id-aes256-GCM",
  "id-aes256-wrap","id-aes256-wrap-pad","id-smime-alg-CMS3DESwrap","sm4","sm4-cbc","sm4-cfb","sm4-ctr",
  "sm4-ecb","sm4-ofb"
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider prov(data, size);

  // Key/IV sizes used by typical AES-256-CBC; your original code enforced these lengths.
  std::string enc_key = prov.ConsumeRandomLengthString();
  if (enc_key.length() != 32) return 0;  // 32 bytes
  std::string vector  = prov.ConsumeRandomLengthString();
  if (vector.length() != 16) return 0;   // 16 bytes
  std::string textToEncrypt = prov.ConsumeRandomLengthString();

  // Simple quote/escape guards as in your originals (now centralized by the literal escaper).
  const int min = 0;
  const int max = static_cast<int>(sizeof(kCiphers) / sizeof(kCiphers[0])) - 1;
  const int idx = prov.ConsumeIntegralInRange<int>(min, max);
  const char* chosen = kCiphers[idx];

  static constexpr std::string_view kTemplate = R"(const crypto  = require('crypto');
const enc_key = {0};
const vector = {1};
const textToEncrypt = {2};
const cipherAlg = {3};
function encrypt(text){
  const cipher = crypto.createCipheriv(cipherAlg, Buffer.from(enc_key), Buffer.from(vector))
  var encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted
}
function decrypt(text){
  const decipher = crypto.createDecipheriv(cipherAlg, Buffer.from(enc_key), Buffer.from(vector));
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted
}
const crypted = encrypt(textToEncrypt);
var _ = decrypt(crypted);
)";

  const std::string js = FormatJs(
      kTemplate,
      ToDoubleQuotedJsLiteral(enc_key),
      ToDoubleQuotedJsLiteral(vector),
      ToDoubleQuotedJsLiteral(textToEncrypt),
      ToDoubleQuotedJsLiteral(chosen));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
