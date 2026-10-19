#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "loader.h"

namespace {

std::string Hex(const std::string& value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const unsigned char byte : value) {
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

std::string Shape(const std::vector<int>& value) {
  if (value.empty()) {
    return "-";
  }
  std::ostringstream output;
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index != 0) {
      output << ',';
    }
    output << value[index];
  }
  return output.str();
}

int ReplayOne(const char* path, int ordinal) {
  std::cout << "TFLITE_CASE_BEGIN ordinal=" << ordinal << std::endl;

  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    std::cerr << "input is not readable: " << path << '\n';
    std::cout << "TFLITE_CASE_END ordinal=" << ordinal
              << " status=reject" << std::endl;
    return 9;
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff length = stream.tellg();
  if (length < 0 ||
      static_cast<std::uintmax_t>(length) >
          tool::tflite_loader::kMaxInputBytes) {
    std::cerr << "input size is invalid or exceeds 16 MiB: " << path << '\n';
    std::cout << "TFLITE_CASE_END ordinal=" << ordinal
              << " status=reject" << std::endl;
    return 9;
  }
  stream.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
  if (!bytes.empty()) {
    stream.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
  }
  if (!stream) {
    std::cerr << "failed while reading input: " << path << '\n';
    std::cout << "TFLITE_CASE_END ordinal=" << ordinal
              << " status=reject" << std::endl;
    return 9;
  }

  tool::tflite_loader::LoadSummary summary;
  std::string error;
  const int status = tool::tflite_loader::LoadAndAllocate(
      bytes.data(), bytes.size(), &summary, &error);
  if (status != 0) {
    std::cerr << "TFLITE_LOAD_REJECT stage=load_allocate reason=" << error
              << '\n';
    std::cout << "TFLITE_CASE_END ordinal=" << ordinal
              << " status=reject" << std::endl;
    return status;
  }
  std::cout << "TFLITE_LOAD_OK stage=allocate_tensors inputs=" << summary.inputs
            << " outputs=" << summary.outputs << " tensors=" << summary.tensors
            << " threads=1\n";
  for (const auto& observation : summary.observations) {
    std::cout << "TFLITE_TENSOR index=" << observation.index
              << " role=" << observation.role
              << " name_hex=" << Hex(observation.name)
              << " dtype=" << observation.dtype
              << " shape=" << Shape(observation.shape)
              << " bytes=" << observation.bytes << " payload_hex=";
    if (observation.role == "constant") {
      std::cout << Hex(observation.constant_payload);
    } else {
      std::cout << '-';
    }
    std::cout << '\n';
  }
  std::cout << "TFLITE_ACCESS_OK tensors=" << summary.tensors
            << " constants=" << summary.constants
            << " constant_bytes=" << summary.constant_bytes << '\n';
  std::cout << "TFLITE_CASE_END ordinal=" << ordinal << " status=ok"
            << std::endl;
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr
        << "usage: tflite_loader_replay INPUT.tflite [INPUT.tflite ...]\n";
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
