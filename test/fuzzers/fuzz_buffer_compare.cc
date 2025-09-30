#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_common.h"

// Fast-path we expose from fuzz_common.cc.
namespace fuzz {
void RunBufCompare(const uint8_t* a, size_t alen,
                   const uint8_t* b, size_t blen);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);

  std::string s1 = p.ConsumeRandomLengthString(64);
  std::string s2 = p.ConsumeRandomLengthString(64);

  fuzz::RunBufCompare(reinterpret_cast<const uint8_t*>(s1.data()), s1.size(),
                      reinterpret_cast<const uint8_t*>(s2.data()), s2.size());
  return 0;
}
