#include "loader.h"

#include <hdf5.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;

class Handle {
public:
  using CloseFunction = herr_t (*)(hid_t);

  Handle() = default;
  Handle(hid_t id, CloseFunction close) : id_(id), close_(close) {}
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept : id_(other.id_), close_(other.close_) {
    other.id_ = H5I_INVALID_HID;
    other.close_ = nullptr;
  }
  Handle &operator=(Handle &&other) noexcept {
    if (this != &other) {
      CloseOrAbort();
      id_ = other.id_;
      close_ = other.close_;
      other.id_ = H5I_INVALID_HID;
      other.close_ = nullptr;
    }
    return *this;
  }
  ~Handle() { CloseOrAbort(); }

  [[nodiscard]] bool valid() const { return id_ >= 0; }
  [[nodiscard]] hid_t get() const { return id_; }

private:
  void CloseOrAbort() noexcept {
    if (!valid()) {
      return;
    }
    const hid_t id = id_;
    id_ = H5I_INVALID_HID;
    if (close_ == nullptr || close_(id) < 0) {
      std::abort();
    }
  }

  hid_t id_ = H5I_INVALID_HID;
  CloseFunction close_ = nullptr;
};

struct FileAndGroup {
  Handle file;
  Handle group;
};

bool CreateFileAndGroup(const fs::path &path, FileAndGroup *output) {
  Handle file(H5Fcreate(path.c_str(), H5F_ACC_EXCL, H5P_DEFAULT, H5P_DEFAULT),
              H5Fclose);
  if (!file.valid()) {
    return false;
  }
  Handle group(
      H5Gcreate2(file.get(), "/weights", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT),
      H5Gclose);
  if (!group.valid()) {
    return false;
  }
  output->file = std::move(file);
  output->group = std::move(group);
  return true;
}

Handle SimpleSpace(const std::vector<hsize_t> &dimensions) {
  if (dimensions.empty()) {
    return Handle(H5Screate(H5S_SCALAR), H5Sclose);
  }
  return Handle(H5Screate_simple(static_cast<int>(dimensions.size()),
                                 dimensions.data(), nullptr),
                H5Sclose);
}

bool CreateDataset(hid_t group, const std::string &name,
                   const std::vector<hsize_t> &dimensions, hid_t type,
                   hid_t properties = H5P_DEFAULT) {
  Handle space = SimpleSpace(dimensions);
  if (!space.valid()) {
    return false;
  }
  Handle dataset(H5Dcreate2(group, name.c_str(), type, space.get(), H5P_DEFAULT,
                            properties, H5P_DEFAULT),
                 H5Dclose);
  return dataset.valid();
}

bool CreateLargeBounded(const fs::path &path) {
  FileAndGroup context;
  return CreateFileAndGroup(path, &context) &&
         CreateDataset(context.group.get(), "large", {200000}, H5T_IEEE_F64LE);
}

bool CreateNonDivisibleHyperslab(const fs::path &path) {
  FileAndGroup context;
  return CreateFileAndGroup(path, &context) &&
         CreateDataset(context.group.get(), "non_divisible", {3, 5000},
                       H5T_IEEE_F64LE);
}

bool CreateTooManyDatasets(const fs::path &path) {
  FileAndGroup context;
  if (!CreateFileAndGroup(path, &context)) {
    return false;
  }
  for (std::size_t index = 0; index < tool::hdf5_loader::kMaxDatasets + 1U;
       ++index) {
    std::ostringstream name;
    name << 'd' << std::setw(4) << std::setfill('0') << index;
    if (!CreateDataset(context.group.get(), name.str(), {}, H5T_STD_I32LE)) {
      return false;
    }
  }
  return true;
}

bool CreateReadBudget(const fs::path &path) {
  FileAndGroup context;
  if (!CreateFileAndGroup(path, &context)) {
    return false;
  }
  constexpr std::size_t kDatasets =
      tool::hdf5_loader::kMaxReadBytes /
          tool::hdf5_loader::kMaxDatasetReadBytes +
      1U;
  for (std::size_t index = 0; index < kDatasets; ++index) {
    const std::string name = "budget_" + std::to_string(index);
    if (!CreateDataset(context.group.get(), name, {8192}, H5T_IEEE_F64LE)) {
      return false;
    }
  }
  return true;
}

bool CreateRank32(const fs::path &path) {
  FileAndGroup context;
  std::vector<hsize_t> dimensions(tool::hdf5_loader::kMaxRank, 1);
  return CreateFileAndGroup(path, &context) &&
         CreateDataset(context.group.get(), "rank32", dimensions,
                       H5T_STD_I32LE);
}

bool CreateObjectAliasCycle(const fs::path &path) {
  FileAndGroup context;
  if (!CreateFileAndGroup(path, &context) ||
      !CreateDataset(context.group.get(), "value", {}, H5T_STD_I32LE)) {
    return false;
  }
  Handle child(H5Gcreate2(context.group.get(), "child", H5P_DEFAULT,
                          H5P_DEFAULT, H5P_DEFAULT),
               H5Gclose);
  if (!child.valid() ||
      H5Lcreate_hard(context.file.get(), "/weights/value", context.file.get(),
                     "/weights/value-alias", H5P_DEFAULT, H5P_DEFAULT) < 0 ||
      H5Lcreate_hard(context.file.get(), "/weights", child.get(), "back",
                     H5P_DEFAULT, H5P_DEFAULT) < 0) {
    return false;
  }
  return true;
}

bool CreateObjectReference(const fs::path &path) {
  FileAndGroup context;
  return CreateFileAndGroup(path, &context) &&
         CreateDataset(context.group.get(), "reference", {1}, H5T_STD_REF_OBJ);
}

bool CreateExternalStorage(const fs::path &path) {
  FileAndGroup context;
  if (!CreateFileAndGroup(path, &context)) {
    return false;
  }
  Handle properties(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
  if (!properties.valid() ||
      H5Pset_external(properties.get(), "outside-raw.bin", 0, H5F_UNLIMITED) <
          0) {
    return false;
  }
  return CreateDataset(context.group.get(), "external", {4}, H5T_STD_I32LE,
                       properties.get());
}

bool CreateVirtualDataset(const fs::path &path) {
  FileAndGroup context;
  if (!CreateFileAndGroup(path, &context)) {
    return false;
  }
  Handle properties(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
  Handle virtual_space = SimpleSpace({1});
  Handle source_space = SimpleSpace({1});
  if (!properties.valid() || !virtual_space.valid() || !source_space.valid() ||
      H5Pset_virtual(properties.get(), virtual_space.get(), "outside-vds.h5",
                     "/payload", source_space.get()) < 0) {
    return false;
  }
  Handle dataset(H5Dcreate2(context.group.get(), "virtual", H5T_STD_I32LE,
                            virtual_space.get(), H5P_DEFAULT, properties.get(),
                            H5P_DEFAULT),
                 H5Dclose);
  return dataset.valid();
}

bool ReadFile(const fs::path &path, std::vector<std::uint8_t> *bytes) {
  std::error_code error;
  const fs::file_status status = fs::symlink_status(path, error);
  if (error || status.type() != fs::file_type::regular) {
    return false;
  }
  const std::uintmax_t size = fs::file_size(path, error);
  if (error || size > std::numeric_limits<std::size_t>::max()) {
    return false;
  }
  bytes->resize(static_cast<std::size_t>(size));
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return false;
  }
  if (!bytes->empty()) {
    stream.read(reinterpret_cast<char *>(bytes->data()),
                static_cast<std::streamsize>(bytes->size()));
  }
  return static_cast<bool>(stream);
}

tool::hdf5_loader::LoadResult LoadFile(
    const fs::path &path,
    const tool::hdf5_loader::Limits &limits = tool::hdf5_loader::Limits{}) {
  std::vector<std::uint8_t> bytes;
  if (!ReadFile(path, &bytes)) {
    tool::hdf5_loader::LoadResult result;
    result.classification =
        tool::hdf5_loader::Classification::kEnvironmentError;
    result.stage = "test_input";
    result.reason = "unavailable";
    return result;
  }
  return tool::hdf5_loader::LoadImage(bytes.data(), bytes.size(), limits);
}

bool Expect(const tool::hdf5_loader::LoadResult &result,
            tool::hdf5_loader::Classification classification,
            std::string_view stage) {
  return result.classification == classification && result.stage == stage;
}

int Generate(const fs::path &output) {
  std::error_code error;
  const fs::file_status status = fs::symlink_status(output, error);
  if (error || status.type() != fs::file_type::directory ||
      fs::is_symlink(status) || !fs::is_empty(output, error) || error) {
    std::cerr
        << "HDF5_TEST_ERROR output must be an empty non-symlink directory\n";
    return 1;
  }
  const std::array<std::pair<const char *, bool (*)(const fs::path &)>, 9>
      generators = {
          {{"large-bounded.h5", CreateLargeBounded},
           {"non-divisible-hyperslab.h5", CreateNonDivisibleHyperslab},
           {"too-many-datasets.h5", CreateTooManyDatasets},
           {"read-budget.h5", CreateReadBudget},
           {"rank-32.h5", CreateRank32},
           {"object-alias-cycle.h5", CreateObjectAliasCycle},
           {"object-reference.h5", CreateObjectReference},
           {"external-storage.h5", CreateExternalStorage},
           {"virtual-dataset.h5", CreateVirtualDataset}}};
  for (const auto &[name, generate] : generators) {
    if (!generate(output / name)) {
      std::cerr << "HDF5_TEST_ERROR generate=" << name << '\n';
      return 1;
    }
  }
  std::cout << "HDF5_TEST_GENERATED count=" << generators.size() << '\n';
  return 0;
}

int CheckLimits(const fs::path &fixtures, const fs::path &policies) {
  if (tool::hdf5_loader::kMaxInputBytes != 32U * 1024U * 1024U ||
      tool::hdf5_loader::kMaxDatasets != 4096U ||
      tool::hdf5_loader::kMaxRank != 32U ||
      tool::hdf5_loader::kMaxReadBytes != 1U * 1024U * 1024U ||
      H5S_MAX_RANK != 32) {
    std::cerr << "HDF5_TEST_ERROR default limits or HDF5 maximum rank differ\n";
    return 1;
  }

  tool::hdf5_loader::Limits rank_limits;
  rank_limits.max_rank = 1;
  if (!Expect(LoadFile(fixtures / "tensor-contiguous.h5", rank_limits),
              tool::hdf5_loader::Classification::kPolicyLimit, "rank")) {
    std::cerr << "HDF5_TEST_ERROR lowered rank limit did not fire\n";
    return 1;
  }
  tool::hdf5_loader::Limits dataset_limits;
  dataset_limits.max_datasets = 0;
  if (!Expect(LoadFile(fixtures / "scalar-numeric.h5", dataset_limits),
              tool::hdf5_loader::Classification::kPolicyLimit,
              "dataset_count")) {
    std::cerr << "HDF5_TEST_ERROR lowered dataset limit did not fire\n";
    return 1;
  }
  tool::hdf5_loader::Limits read_limits;
  read_limits.max_read_bytes = 8;
  if (!Expect(LoadFile(fixtures / "tensor-contiguous.h5", read_limits),
              tool::hdf5_loader::Classification::kPolicyLimit, "read_budget")) {
    std::cerr << "HDF5_TEST_ERROR lowered read limit did not fire\n";
    return 1;
  }
  std::vector<std::uint8_t> scalar;
  if (!ReadFile(fixtures / "scalar-numeric.h5", &scalar) || scalar.empty()) {
    std::cerr << "HDF5_TEST_ERROR scalar input unavailable\n";
    return 1;
  }
  tool::hdf5_loader::Limits input_limits;
  input_limits.max_input_bytes = scalar.size() - 1U;
  if (!Expect(tool::hdf5_loader::LoadImage(scalar.data(), scalar.size(),
                                           input_limits),
              tool::hdf5_loader::Classification::kPolicyLimit, "input_size")) {
    std::cerr << "HDF5_TEST_ERROR lowered input limit did not fire\n";
    return 1;
  }
  tool::hdf5_loader::Limits raised_input_limits;
  raised_input_limits.max_input_bytes = tool::hdf5_loader::kMaxInputBytes + 1U;
  if (!Expect(LoadFile(fixtures / "scalar-numeric.h5", raised_input_limits),
              tool::hdf5_loader::Classification::kEnvironmentError,
              "loader_config")) {
    std::cerr << "HDF5_TEST_ERROR raised input limit was accepted\n";
    return 1;
  }
  tool::hdf5_loader::Limits raised_dataset_limits;
  raised_dataset_limits.max_datasets = tool::hdf5_loader::kMaxDatasets + 1U;
  if (!Expect(LoadFile(fixtures / "scalar-numeric.h5", raised_dataset_limits),
              tool::hdf5_loader::Classification::kEnvironmentError,
              "loader_config")) {
    std::cerr << "HDF5_TEST_ERROR raised dataset limit was accepted\n";
    return 1;
  }
  if (!Expect(LoadFile(policies / "rank-32.h5"),
              tool::hdf5_loader::Classification::kAccepted, "complete")) {
    std::cerr << "HDF5_TEST_ERROR actual rank-32 dataset was not accepted\n";
    return 1;
  }
  std::cout << "HDF5_TEST_LIMITS_OK input=33554432 datasets=4096 rank=32 "
               "read=1048576\n";
  return 0;
}

int CheckHandles(const fs::path &fixtures, const fs::path &policies) {
  const std::vector<fs::path> paths = {
      fixtures / "scalar-numeric.h5",
      fixtures / "tensor-chunked.h5",
      fixtures / "missing-dataset.h5",
      fixtures / "invalid-metadata.h5",
      fixtures / "unsupported-filter.h5",
      fixtures / "unsupported-dtype.h5",
      fixtures / "external-link.h5",
      policies / "large-bounded.h5",
      policies / "non-divisible-hyperslab.h5",
      policies / "object-reference.h5",
      policies / "external-storage.h5",
      policies / "virtual-dataset.h5",
      policies / "object-alias-cycle.h5",
  };
  for (const fs::path &path : paths) {
    const tool::hdf5_loader::LoadResult result = LoadFile(path);
    if (result.classification ==
        tool::hdf5_loader::Classification::kEnvironmentError) {
      std::cerr << "HDF5_TEST_ERROR warmup failed for " << path << '\n';
      return 1;
    }
  }
  const ssize_t before = H5Fget_obj_count(H5F_OBJ_ALL, H5F_OBJ_ALL);
  if (before < 0) {
    std::cerr << "HDF5_TEST_ERROR initial handle count unavailable\n";
    return 1;
  }
  for (int round = 0; round < 10; ++round) {
    for (const fs::path &path : paths) {
      const tool::hdf5_loader::LoadResult result = LoadFile(path);
      if (result.classification ==
          tool::hdf5_loader::Classification::kEnvironmentError) {
        std::cerr << "HDF5_TEST_ERROR repeated load failed for " << path
                  << '\n';
        return 1;
      }
      if (path.filename() == "scalar-numeric.h5") {
        const bool accepted_value =
            result.classification ==
                tool::hdf5_loader::Classification::kAccepted &&
            result.summary.dataset_observations.size() == 1U &&
            result.summary.dataset_observations[0].values ==
                std::vector<double>{7.0};
        const bool injected_read_failure =
            result.classification ==
                tool::hdf5_loader::Classification::kTargetReject &&
            result.stage == "dataset_read" &&
            result.summary.dataset_observations.empty();
        if (!accepted_value && !injected_read_failure) {
          std::cerr
              << "HDF5_TEST_ERROR scalar oracle changed after prior inputs\n";
          return 1;
        }
      }
    }
  }
  const ssize_t after = H5Fget_obj_count(H5F_OBJ_ALL, H5F_OBJ_ALL);
  if (after < 0 || after != before) {
    std::cerr << "HDF5_TEST_ERROR handle count changed before=" << before
              << " after=" << after << '\n';
    return 1;
  }
  std::cout << "HDF5_TEST_HANDLES_OK before=" << before << " after=" << after
            << " calls=" << paths.size() * 10U << '\n';
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 3 && argc != 4) {
    std::cerr << "usage: hdf5_loader_test_tool <generate DIR|check-limits "
                 "FIXTURES POLICIES|check-handles FIXTURES POLICIES>\n";
    return 64;
  }
  const std::string_view command(argv[1]);
  if (command == "generate" && argc == 3) {
    return Generate(argv[2]);
  }
  if (command == "check-limits" && argc == 4) {
    return CheckLimits(argv[2], argv[3]);
  }
  if (command == "check-handles" && argc == 4) {
    return CheckHandles(argv[2], argv[3]);
  }
  std::cerr << "HDF5_TEST_ERROR invalid command or arguments\n";
  return 64;
}
