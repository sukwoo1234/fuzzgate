#include "loader.h"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  tool::openvino_loader::LoadSummary summary;
  std::string error;
  (void)tool::openvino_loader::LoadBundle(data, size, &summary, &error);
  return 0;
}
