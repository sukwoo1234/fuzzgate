#include "loader.h"

#include "harnesses/common/model_bundle.h"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

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

std::string Hex(const std::vector<std::uint8_t>& data) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const std::uint8_t byte : data) {
    output << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return output.str();
}

std::string ErrorStage(const std::string& error) {
  const std::size_t separator = error.find(':');
  return separator == std::string::npos ? "unknown" : error.substr(0, separator);
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
  tool::openvino_loader::LoadSummary summary;
  const int status = tool::openvino_loader::LoadBundle(
      bundle.data(), bundle.size(), &summary, &error);
  if (status != 0) {
    return Reject(ErrorStage(error), error);
  }
  std::string constant_hex;
  for (const auto& observation : summary.constant_observations) {
    constant_hex += Hex(observation.payload);
  }
  if (constant_hex.empty()) {
    constant_hex = "-";
  }
  std::cout << "OPENVINO_FIXTURE_OK nodes=" << summary.nodes
            << " parameters=" << summary.parameters
            << " results=" << summary.results
            << " constants=" << summary.constants
            << " constant_bytes=" << summary.constant_bytes
            << " constant_hex=" << constant_hex << '\n';
  return 0;
}
