#include "loader.h"

#include "harnesses/common/model_bundle.h"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string Hex(std::string_view value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    output << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return output.str();
}

std::string Hex(const std::vector<std::uint8_t>& value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const std::uint8_t byte : value) {
    output << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return output.str();
}

std::string Join(const std::vector<std::string>& values) {
  if (values.empty()) {
    return "-";
  }
  std::ostringstream output;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      output << '|';
    }
    output << values[index];
  }
  return output.str();
}

std::string ErrorStage(const std::string& error) {
  const std::size_t separator = error.find(':');
  return separator == std::string::npos ? "unknown" : error.substr(0, separator);
}

int ReplayOne(const char* path, int ordinal) {
  std::cout << "OPENVINO_CASE_BEGIN ordinal=" << ordinal << std::endl;

  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    std::cerr << "OPENVINO_INPUT_UNAVAILABLE path=" << path << '\n';
    std::cout << "OPENVINO_CASE_END ordinal=" << ordinal
              << " status=unavailable" << std::endl;
    return 10;
  }
  const std::streampos end = input.tellg();
  if (end < 0) {
    std::cerr << "OPENVINO_INPUT_UNAVAILABLE path=" << path
              << " reason=size" << '\n';
    std::cout << "OPENVINO_CASE_END ordinal=" << ordinal
              << " status=unavailable" << std::endl;
    return 10;
  }
  if (static_cast<std::uintmax_t>(end) > tool::model_bundle::kMaxBundleBytes) {
    std::cerr << "OPENVINO_LOAD_REJECT stage=bundle reason=input exceeds 64 MiB\n";
    std::cout << "OPENVINO_CASE_END ordinal=" << ordinal
              << " status=reject" << std::endl;
    return 9;
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
  input.seekg(0, std::ios::beg);
  if (!bytes.empty()) {
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  }
  if (!input) {
    std::cerr << "OPENVINO_INPUT_UNAVAILABLE path=" << path
              << " reason=short_read" << '\n';
    std::cout << "OPENVINO_CASE_END ordinal=" << ordinal
              << " status=unavailable" << std::endl;
    return 10;
  }

  tool::openvino_loader::LoadSummary summary;
  std::string error;
  const int status = tool::openvino_loader::LoadBundle(
      bytes.data(), bytes.size(), &summary, &error);
  if (status != 0) {
    std::cerr << "OPENVINO_LOAD_REJECT stage=" << ErrorStage(error)
              << " reason=" << error << '\n';
    std::cout << "OPENVINO_CASE_END ordinal=" << ordinal
              << " status=reject" << std::endl;
    return status;
  }

  std::cout << "OPENVINO_LOAD_OK stage=read_validate_constants"
            << " nodes=" << summary.nodes
            << " parameters=" << summary.parameters
            << " results=" << summary.results << '\n';
  for (const auto& operation : summary.operations) {
    std::cout << "OPENVINO_OP index=" << operation.index
              << " name_hex=" << Hex(operation.name)
              << " type=" << operation.type
              << " inputs=" << Join(operation.inputs)
              << " outputs=" << Join(operation.outputs) << '\n';
  }
  for (const auto& constant : summary.constant_observations) {
    std::cout << "OPENVINO_CONSTANT index=" << constant.operation_index
              << " name_hex=" << Hex(constant.name)
              << " dtype=" << constant.dtype
              << " shape=" << constant.shape
              << " bytes=" << constant.bytes
              << " payload_hex=" << Hex(constant.payload) << '\n';
  }
  std::cout << "OPENVINO_ACCESS_OK nodes=" << summary.nodes
            << " constants=" << summary.constants
            << " constant_bytes=" << summary.constant_bytes << '\n';
  std::cout << "OPENVINO_CASE_END ordinal=" << ordinal << " status=ok"
            << std::endl;
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: openvino_ir_loader_replay INPUT.fzb [INPUT.fzb ...]\n";
    return 10;
  }
  for (int index = 1; index < argc; ++index) {
    const int status = ReplayOne(argv[index], index);
    if (status != 0) {
      return status;
    }
  }
  return 0;
}
