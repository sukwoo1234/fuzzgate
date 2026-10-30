#include "loader.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  (void)tool::hdf5_loader::LoadImage(data, size);
  return 0;
}
