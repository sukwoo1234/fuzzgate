#include "harnesses/common/model_bundle.h"

#include <openvino/openvino.hpp>
#include <openvino/op/constant.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kMaxXmlBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaxObservedConstantBytes = 1U * 1024U * 1024U;

int Reject(std::string_view stage, const std::string& message) {
  std::cerr << "OPENVINO_FIXTURE_REJECTED stage=" << stage << " error=" << message << '\n';
  return 9;
}

bool ReadBundle(const std::string& path, std::vector<std::uint8_t>* output,
                std::string* error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    *error = "cannot open bundle";
    return false;
  }
  const std::streampos end = input.tellg();
  if (end < 0 || static_cast<std::uintmax_t>(end) > tool::model_bundle::kMaxBundleBytes) {
    *error = "bundle exceeds the FZB1 size limit";
    return false;
  }
  output->resize(static_cast<std::size_t>(end));
  input.seekg(0, std::ios::beg);
  if (!output->empty()) {
    input.read(reinterpret_cast<char*>(output->data()),
               static_cast<std::streamsize>(output->size()));
  }
  if (!input) {
    *error = "short read from bundle";
    return false;
  }
  return true;
}

std::string Hex(const std::uint8_t* data, std::size_t size) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string result;
  result.reserve(size * 2U);
  for (std::size_t index = 0; index < size; ++index) {
    result.push_back(kDigits[data[index] >> 4U]);
    result.push_back(kDigits[data[index] & 0x0fU]);
  }
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    return Reject("arguments", "expected exactly one FZB1 bundle path");
  }
  std::vector<std::uint8_t> bundle;
  std::string error;
  if (!ReadBundle(argv[1], &bundle, &error)) {
    return Reject("bundle", error);
  }
  std::vector<tool::model_bundle::EntryView> entries;
  const std::vector<std::string_view> allowlist = {"model.bin", "model.xml"};
  if (!tool::model_bundle::DecodeWithAllowlist(bundle.data(), bundle.size(), allowlist,
                                                &entries, &error)) {
    return Reject("bundle", error);
  }
  const tool::model_bundle::EntryView* xml = nullptr;
  const tool::model_bundle::EntryView* weights_entry = nullptr;
  for (const auto& entry : entries) {
    if (entry.name == "model.xml") {
      xml = &entry;
    } else if (entry.name == "model.bin") {
      weights_entry = &entry;
    }
  }
  if (xml == nullptr || weights_entry == nullptr || xml->size > kMaxXmlBytes) {
    return Reject("bundle", "required pair is absent or model.xml exceeds 8 MiB");
  }

  try {
    const std::string model_text(reinterpret_cast<const char*>(xml->data), xml->size);
    ov::Tensor weights;
    if (weights_entry->size != 0) {
      weights = ov::Tensor(ov::element::u8, ov::Shape{weights_entry->size},
                           weights_entry->data);
    }
    ov::Core core;
    const auto model = core.read_model(model_text, weights);
    if (!model) {
      return Reject("frontend", "IR frontend returned a null model");
    }
    model->validate_nodes_and_infer_types();

    std::size_t constant_count = 0;
    std::size_t constant_bytes = 0;
    std::string constant_hex;
    for (const auto& node : model->get_ordered_ops()) {
      const auto constant = std::dynamic_pointer_cast<ov::op::v0::Constant>(node);
      if (!constant) {
        continue;
      }
      const std::size_t size = constant->get_byte_size();
      if (size > kMaxObservedConstantBytes - constant_bytes) {
        return Reject("oracle", "constant observation exceeds 1 MiB");
      }
      const auto* data = static_cast<const std::uint8_t*>(constant->get_data_ptr());
      if (size != 0 && data == nullptr) {
        return Reject("oracle", "Constant has a null data pointer");
      }
      constant_hex += Hex(data, size);
      constant_bytes += size;
      ++constant_count;
    }
    if (constant_hex.empty()) {
      constant_hex = "-";
    }
    std::cout << "OPENVINO_FIXTURE_OK nodes=" << model->get_ordered_ops().size()
              << " parameters=" << model->get_parameters().size()
              << " results=" << model->get_results().size()
              << " constants=" << constant_count
              << " constant_bytes=" << constant_bytes
              << " constant_hex=" << constant_hex << '\n';
    return 0;
  } catch (const std::exception& exception) {
    return Reject("frontend", exception.what());
  }
}
