#ifndef TOOL_HARNESSES_TFLITE_LOADER_H_
#define TOOL_HARNESSES_TFLITE_LOADER_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tool::tflite_loader {

constexpr std::size_t kMaxInputBytes = 16U * 1024U * 1024U;
constexpr int kMaxTensors = 4096;
constexpr std::size_t kMaxConstantPayloadBytes = 1024U * 1024U;

struct TensorObservation {
  int index = 0;
  std::string role;
  std::string name;
  std::string dtype;
  std::vector<int> shape;
  std::size_t bytes = 0;
  std::vector<std::uint8_t> constant_payload;
};

struct LoadSummary {
  int inputs = 0;
  int outputs = 0;
  int tensors = 0;
  int constants = 0;
  std::size_t constant_bytes = 0;
  std::vector<TensorObservation> observations;
};

// `data` must outlive this call. The model and interpreter are destroyed before
// control returns, so the caller-owned buffer is always released last.
int LoadAndAllocate(const std::uint8_t* data, std::size_t size,
                    LoadSummary* summary, std::string* error);

}  // namespace tool::tflite_loader

#endif  // TOOL_HARNESSES_TFLITE_LOADER_H_
