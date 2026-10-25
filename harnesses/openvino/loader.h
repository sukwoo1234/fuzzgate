#ifndef TOOL_HARNESSES_OPENVINO_LOADER_H_
#define TOOL_HARNESSES_OPENVINO_LOADER_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tool::openvino_loader {

constexpr std::size_t kMaxXmlBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaxNodes = 4096;
constexpr std::size_t kMaxConstantPayloadBytes = 1U * 1024U * 1024U;

struct OperationObservation {
  std::size_t index = 0;
  std::string name;
  std::string type;
  std::vector<std::string> inputs;
  std::vector<std::string> outputs;
};

struct ConstantObservation {
  std::size_t operation_index = 0;
  std::string name;
  std::string dtype;
  std::string shape;
  std::size_t bytes = 0;
  std::vector<std::uint8_t> payload;
};

struct LoadSummary {
  std::size_t nodes = 0;
  std::size_t parameters = 0;
  std::size_t results = 0;
  std::size_t constants = 0;
  std::size_t constant_bytes = 0;
  std::vector<OperationObservation> operations;
  std::vector<ConstantObservation> constant_observations;
};

// `data` owns both FZB1 entries and must outlive this call. The model is
// destroyed before the weights view and model text, so no input-backed state
// survives into the next invocation.
int LoadBundle(const std::uint8_t* data, std::size_t size,
               LoadSummary* summary, std::string* error);

}  // namespace tool::openvino_loader

#endif  // TOOL_HARNESSES_OPENVINO_LOADER_H_
