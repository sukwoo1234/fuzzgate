#include <hdf5.h>

#include <array>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

class Handle {
public:
  using Close = herr_t (*)(hid_t);

  Handle(hid_t id, Close close) : id_(id), close_(close) {}
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  ~Handle() {
    if (id_ >= 0) {
      (void)close_(id_);
    }
  }

  [[nodiscard]] hid_t get() const { return id_; }
  [[nodiscard]] bool valid() const { return id_ >= 0; }

private:
  hid_t id_;
  Close close_;
};

bool Generate(const std::filesystem::path &output) {
  if (output.empty() || std::filesystem::exists(output) ||
      !std::filesystem::exists(output.parent_path())) {
    std::cerr << "invalid or pre-existing output path\n";
    return false;
  }

  const Handle file(H5Fcreate(output.c_str(), H5F_ACC_EXCL, H5P_DEFAULT,
                              H5P_DEFAULT),
                    H5Fclose);
  if (!file.valid()) {
    std::cerr << "H5Fcreate failed\n";
    return false;
  }

  const std::array<hsize_t, 2> dimensions{4, 4};
  const Handle space(H5Screate_simple(2, dimensions.data(), nullptr), H5Sclose);
  const Handle properties(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
  const std::array<hsize_t, 2> chunk{2, 2};
  if (!space.valid() || !properties.valid() ||
      H5Pset_chunk(properties.get(), 2, chunk.data()) < 0 ||
      H5Pset_shuffle(properties.get()) < 0 ||
      H5Pset_fletcher32(properties.get()) < 0) {
    std::cerr << "filtered dataset properties failed\n";
    return false;
  }

  const Handle dataset(H5Dcreate2(file.get(), "/instrumented", H5T_STD_I32LE,
                                  space.get(), H5P_DEFAULT, properties.get(),
                                  H5P_DEFAULT),
                       H5Dclose);
  constexpr std::array<int, 16> values{
      1,  2,  3,  4,  5,  6,  7,  8,
      9,  10, 11, 12, 13, 14, 15, 16,
  };
  if (!dataset.valid() ||
      H5Dwrite(dataset.get(), H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT,
               values.data()) < 0 ||
      H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
    std::cerr << "filtered dataset write failed\n";
    return false;
  }

  std::cout << "HDF5_INSTRUMENTATION_FIXTURE_OK path=" << output.string()
            << " dataset=/instrumented filters=shuffle,fletcher32 values=16\n";
  return true;
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: hdf5_instrumentation_fixture_tool OUTPUT.h5\n";
    return 64;
  }
  H5Eset_auto2(H5E_DEFAULT, nullptr, nullptr);
  return Generate(argv[1]) ? 0 : 1;
}
