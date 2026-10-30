#ifndef TOOL_HARNESSES_HDF5_LOADER_H_
#define TOOL_HARNESSES_HDF5_LOADER_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tool::hdf5_loader {

constexpr std::size_t kMaxInputBytes = 32U * 1024U * 1024U;
constexpr std::size_t kMaxDatasets = 4096U;
constexpr std::size_t kMaxRank = 32U;
constexpr std::size_t kMaxReadBytes = 1U * 1024U * 1024U;
constexpr std::size_t kMaxDatasetReadBytes = 64U * 1024U;

struct Limits {
  std::size_t max_input_bytes = kMaxInputBytes;
  std::size_t max_datasets = kMaxDatasets;
  std::size_t max_rank = kMaxRank;
  std::size_t max_read_bytes = kMaxReadBytes;
};

enum class Classification {
  kAccepted,
  kTargetReject,
  kPolicyLimit,
  kUnsupportedFeature,
  kEnvironmentError,
};

struct DatasetObservation {
  std::string path;
  std::string state;
  std::string dtype;
  std::vector<std::uint64_t> shape;
  std::uint64_t elements = 0;
  std::size_t read_elements = 0;
  std::vector<double> values;
};

struct AttributeObservation {
  std::string object_path;
  std::string name;
  std::string dtype;
  std::vector<std::uint64_t> shape;
  std::uint64_t elements = 0;
  std::vector<double> values;
};

struct LoadSummary {
  std::size_t groups = 0;
  std::size_t datasets = 0;
  std::size_t attributes = 0;
  std::size_t visited_objects = 0;
  std::size_t h5dread_calls = 0;
  std::size_t read_bytes = 0;
  std::vector<DatasetObservation> dataset_observations;
  std::vector<AttributeObservation> attribute_observations;
};

struct LoadResult {
  Classification classification = Classification::kEnvironmentError;
  std::string stage;
  std::string reason;
  LoadSummary summary;
};

const char *ClassificationName(Classification classification);
int ExitCode(Classification classification);

// H5LTopen_file_image with flags 0 copies the caller-owned bytes. Every HDF5
// handle and every copied value is released before this function returns.
LoadResult LoadImage(const std::uint8_t *data, std::size_t size,
                     const Limits &limits = Limits{});

} // namespace tool::hdf5_loader

#endif // TOOL_HARNESSES_HDF5_LOADER_H_
