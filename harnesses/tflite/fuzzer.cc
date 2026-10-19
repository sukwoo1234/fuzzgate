#include <cstddef>
#include <cstdint>
#include <string>

#include "loader.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  tool::tflite_loader::LoadSummary summary;
  std::string error;
  (void)tool::tflite_loader::LoadAndAllocate(data, size, &summary, &error);
  return 0;
}
