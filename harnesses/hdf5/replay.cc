#include "loader.h"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string Hex(const std::string &value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    output << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return output.str();
}

std::string Shape(const std::vector<std::uint64_t> &shape) {
  if (shape.empty()) {
    return "-";
  }
  std::ostringstream output;
  for (std::size_t index = 0; index < shape.size(); ++index) {
    if (index != 0) {
      output << ',';
    }
    output << shape[index];
  }
  return output.str();
}

std::string Values(const std::vector<double> &values) {
  if (values.empty()) {
    return "-";
  }
  std::ostringstream output;
  output << std::setprecision(17);
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0) {
      output << ',';
    }
    output << values[index];
  }
  return output.str();
}

tool::hdf5_loader::LoadResult
SimpleResult(tool::hdf5_loader::Classification classification,
             const char *stage, const char *reason) {
  tool::hdf5_loader::LoadResult result;
  result.classification = classification;
  result.stage = stage;
  result.reason = reason;
  return result;
}

void PrintResult(const tool::hdf5_loader::LoadResult &result) {
  std::ostream &stream =
      result.classification == tool::hdf5_loader::Classification::kAccepted
          ? std::cout
          : std::cerr;
  stream << "HDF5_RESULT classification="
         << tool::hdf5_loader::ClassificationName(result.classification)
         << " stage=" << result.stage << " reason=" << result.reason << '\n';
  if (result.classification != tool::hdf5_loader::Classification::kAccepted) {
    return;
  }
  const auto &summary = result.summary;
  stream << "HDF5_LOAD_OK groups=" << summary.groups
         << " datasets=" << summary.datasets
         << " attributes=" << summary.attributes
         << " visited_objects=" << summary.visited_objects << '\n';
  for (const auto &dataset : summary.dataset_observations) {
    stream << "HDF5_DATASET path_hex=" << Hex(dataset.path)
           << " state=" << dataset.state << " dtype=" << dataset.dtype
           << " shape=" << Shape(dataset.shape)
           << " elements=" << dataset.elements
           << " read_elements=" << dataset.read_elements
           << " values=" << Values(dataset.values) << '\n';
  }
  for (const auto &attribute : summary.attribute_observations) {
    stream << "HDF5_ATTRIBUTE object_path_hex=" << Hex(attribute.object_path)
           << " name_hex=" << Hex(attribute.name)
           << " dtype=" << attribute.dtype
           << " shape=" << Shape(attribute.shape)
           << " elements=" << attribute.elements
           << " values=" << Values(attribute.values) << '\n';
  }
  stream << "HDF5_ACCESS_OK datasets=" << summary.datasets
         << " attributes=" << summary.attributes
         << " h5dread_calls=" << summary.h5dread_calls
         << " read_bytes=" << summary.read_bytes << '\n';
}

int ReplayOne(const char *path, int ordinal) {
  std::cout << "HDF5_CASE_BEGIN ordinal=" << ordinal << std::endl;
  tool::hdf5_loader::LoadResult result;

  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    result = SimpleResult(tool::hdf5_loader::Classification::kEnvironmentError,
                          "input_read", "input_unavailable");
  } else {
    const std::streampos end = input.tellg();
    if (end < 0) {
      result =
          SimpleResult(tool::hdf5_loader::Classification::kEnvironmentError,
                       "input_read", "input_size_unavailable");
    } else if (static_cast<std::uintmax_t>(end) >
               tool::hdf5_loader::kMaxInputBytes) {
      result = SimpleResult(tool::hdf5_loader::Classification::kPolicyLimit,
                            "input_size", "input_exceeds_limit");
    } else {
      std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
      input.seekg(0, std::ios::beg);
      if (!bytes.empty()) {
        input.read(reinterpret_cast<char *>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
      }
      if (!input) {
        result =
            SimpleResult(tool::hdf5_loader::Classification::kEnvironmentError,
                         "input_read", "input_short_read");
      } else {
        result = tool::hdf5_loader::LoadImage(bytes.data(), bytes.size());
      }
    }
  }

  PrintResult(result);
  std::cout << "HDF5_CASE_END ordinal=" << ordinal << " status="
            << tool::hdf5_loader::ClassificationName(result.classification)
            << std::endl;
  return tool::hdf5_loader::ExitCode(result.classification);
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "usage: hdf5_loader_replay INPUT.h5 [INPUT.h5 ...]\n";
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
