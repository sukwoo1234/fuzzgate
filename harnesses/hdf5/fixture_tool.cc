#include <hdf5.h>
#include <hdf5_hl.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;

constexpr H5Z_filter_t kUnsupportedFilter = 32024;

class Handle {
public:
  using Close = herr_t (*)(hid_t);

  Handle() = default;
  Handle(hid_t id, Close close, std::string label)
      : id_(id), close_(close), label_(std::move(label)) {}
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept
      : id_(other.id_), close_(other.close_), label_(std::move(other.label_)) {
    other.id_ = H5I_INVALID_HID;
  }
  Handle &operator=(Handle &&other) noexcept {
    if (this != &other) {
      CloseUnchecked();
      id_ = other.id_;
      close_ = other.close_;
      label_ = std::move(other.label_);
      other.id_ = H5I_INVALID_HID;
    }
    return *this;
  }
  ~Handle() { CloseUnchecked(); }

  [[nodiscard]] hid_t get() const { return id_; }
  [[nodiscard]] bool valid() const { return id_ >= 0; }

  bool CloseChecked(std::string *error) {
    if (!valid()) {
      return true;
    }
    const hid_t id = id_;
    id_ = H5I_INVALID_HID;
    if (close_ == nullptr || close_(id) < 0) {
      if (error->empty()) {
        *error = "failed to close " + label_;
      }
      return false;
    }
    return true;
  }

private:
  void CloseUnchecked() {
    if (valid()) {
      const hid_t id = id_;
      id_ = H5I_INVALID_HID;
      if (close_ != nullptr && close_(id) < 0) {
        std::cerr << "HDF5_FIXTURE_CLOSE_ERROR handle=" << label_ << '\n';
      }
    }
  }

  hid_t id_ = H5I_INVALID_HID;
  Close close_ = nullptr;
  std::string label_;
};

bool SetError(std::string *error, const std::string &message) {
  if (error->empty()) {
    *error = message;
  }
  return false;
}

bool CloseAll(std::string *error, std::initializer_list<Handle *> handles) {
  bool ok = true;
  for (Handle *handle : handles) {
    if (!handle->CloseChecked(error)) {
      ok = false;
    }
  }
  return ok;
}

struct FileContext {
  Handle fapl;
  Handle fcpl;
  Handle file;
  Handle group;

  bool Close(std::string *error) {
    return CloseAll(error, {&group, &file, &fcpl, &fapl});
  }
};

Handle CreateSpace(const std::vector<hsize_t> &shape) {
  if (shape.empty()) {
    return Handle(H5Screate(H5S_SCALAR), H5Sclose, "scalar dataspace");
  }
  return Handle(H5Screate_simple(static_cast<int>(shape.size()), shape.data(), nullptr),
                H5Sclose, "simple dataspace");
}

Handle CreateDatasetProperties() {
  Handle properties(H5Pcreate(H5P_DATASET_CREATE), H5Pclose,
                    "dataset creation properties");
  if (!properties.valid() || H5Pset_obj_track_times(properties.get(), false) < 0) {
    return Handle();
  }
  return properties;
}

bool CreateFileAndGroup(const fs::path &path, FileContext *context,
                        std::string *error) {
  context->fapl = Handle(H5Pcreate(H5P_FILE_ACCESS), H5Pclose,
                         "file access properties");
  if (!context->fapl.valid() ||
      H5Pset_libver_bounds(context->fapl.get(), H5F_LIBVER_LATEST,
                           H5F_LIBVER_LATEST) < 0) {
    return SetError(error, "could not create deterministic file access properties");
  }
  context->fcpl = Handle(H5Pcreate(H5P_FILE_CREATE), H5Pclose,
                         "file creation properties");
  if (!context->fcpl.valid() ||
      H5Pset_obj_track_times(context->fcpl.get(), false) < 0) {
    return SetError(error, "could not disable root object timestamp tracking");
  }
  context->file = Handle(
      H5Fcreate(path.c_str(), H5F_ACC_EXCL, context->fcpl.get(),
                context->fapl.get()),
      H5Fclose, "HDF5 file");
  if (!context->file.valid()) {
    return SetError(error, "could not create HDF5 file: " + path.string());
  }
  Handle properties(H5Pcreate(H5P_GROUP_CREATE), H5Pclose,
                    "group creation properties");
  if (!properties.valid() || H5Pset_obj_track_times(properties.get(), false) < 0) {
    return SetError(error, "could not disable group timestamp tracking");
  }
  context->group = Handle(
      H5Gcreate2(context->file.get(), "/weights", H5P_DEFAULT,
                 properties.get(), H5P_DEFAULT),
      H5Gclose, "weights group");
  if (!context->group.valid()) {
    return SetError(error, "could not create /weights group");
  }
  return properties.CloseChecked(error);
}

bool WriteIntAttribute(hid_t object, const char *name, std::int32_t value,
                       std::string *error) {
  Handle space(H5Screate(H5S_SCALAR), H5Sclose, "attribute dataspace");
  if (!space.valid()) {
    return SetError(error, std::string("could not create attribute space: ") + name);
  }
#if defined(HDF5_FIXTURE_MUTATE_ATTRIBUTE_DTYPE)
  const std::int64_t stored_value = value;
  const hid_t file_type = H5T_STD_I64LE;
  const hid_t memory_type = H5T_NATIVE_INT64;
  const void *value_pointer = &stored_value;
#else
  const hid_t file_type = H5T_STD_I32LE;
  const hid_t memory_type = H5T_NATIVE_INT32;
  const void *value_pointer = &value;
#endif
  Handle attribute(H5Acreate2(object, name, file_type, space.get(),
                              H5P_DEFAULT, H5P_DEFAULT),
                   H5Aclose, "attribute");
  if (!attribute.valid() ||
      H5Awrite(attribute.get(), memory_type, value_pointer) < 0) {
    return SetError(error, std::string("could not write attribute: ") + name);
  }
  return CloseAll(error, {&attribute, &space});
}

bool FinishFile(FileContext *context, std::string *error) {
  if (H5Fflush(context->file.get(), H5F_SCOPE_GLOBAL) < 0) {
    return SetError(error, "could not flush generated HDF5 file");
  }
  return context->Close(error);
}

template <typename Value, std::size_t Size>
bool CreateNumeric(const fs::path &path, const char *dataset_path, hid_t file_type,
                   hid_t memory_type, const std::vector<hsize_t> &shape,
                   const std::array<Value, Size> &values, bool chunked,
                   bool add_attributes, std::string *error) {
  FileContext context;
  if (!CreateFileAndGroup(path, &context, error)) {
    return false;
  }
  Handle space = CreateSpace(shape);
  Handle properties = CreateDatasetProperties();
  if (!space.valid() || !properties.valid()) {
    return SetError(error, "could not create numeric dataset properties");
  }
  if (chunked) {
#if defined(HDF5_FIXTURE_MUTATE_CHUNK_SHAPE)
    const std::array<hsize_t, 2> chunks = {1, 2};
#else
    const std::array<hsize_t, 2> chunks = {2, 2};
#endif
    if (shape.size() != chunks.size() ||
        H5Pset_chunk(properties.get(), static_cast<int>(chunks.size()),
                     chunks.data()) < 0) {
      return SetError(error, "could not set chunked dataset layout");
    }
  }
  Handle dataset(H5Dcreate2(context.file.get(), dataset_path, file_type,
                            space.get(), H5P_DEFAULT, properties.get(),
                            H5P_DEFAULT),
                 H5Dclose, "numeric dataset");
  if (!dataset.valid()) {
    return SetError(error, std::string("could not create dataset: ") + dataset_path);
  }
  if constexpr (Size > 0) {
    if (H5Dwrite(dataset.get(), memory_type, H5S_ALL, H5S_ALL, H5P_DEFAULT,
                 values.data()) < 0) {
      return SetError(error, std::string("could not write dataset: ") + dataset_path);
    }
  }
  if (add_attributes &&
      (!WriteIntAttribute(context.group.get(), "fixture_version", 1, error) ||
       !WriteIntAttribute(dataset.get(), "axis_count", 2, error))) {
    return false;
  }
  if (!CloseAll(error, {&dataset, &properties, &space})) {
    return false;
  }
  return FinishFile(&context, error);
}

bool CreateScalar(const fs::path &path, std::string *error) {
  const std::array<std::int64_t, 1> values = {7};
  return CreateNumeric(path, "/weights/scalar", H5T_STD_I64LE,
                       H5T_NATIVE_INT64, {}, values, false, false, error);
}

bool CreateEmpty(const fs::path &path, std::string *error) {
  const std::array<float, 0> values = {};
  return CreateNumeric(path, "/weights/empty", H5T_IEEE_F32LE,
                       H5T_NATIVE_FLOAT, {0, 3}, values, false, false, error);
}

bool CreateContiguous(const fs::path &path, std::string *error) {
  const std::array<float, 6> values = {1.25F, -2.0F, 3.5F, 4.25F, -5.75F, 6.0F};
  return CreateNumeric(path, "/weights/kernel", H5T_IEEE_F32LE,
                       H5T_NATIVE_FLOAT, {2, 3}, values, false, true, error);
}

bool CreateChunked(const fs::path &path, std::string *error) {
  const std::array<std::int16_t, 6> values = {-3, 0, 7, 11, 1024, -2048};
  return CreateNumeric(path, "/weights/chunked", H5T_STD_I16LE,
                       H5T_NATIVE_INT16, {3, 2}, values, true, false, error);
}

bool CreateMissing(const fs::path &path, std::string *error) {
  FileContext context;
  if (!CreateFileAndGroup(path, &context, error)) {
    return false;
  }
  return FinishFile(&context, error);
}

bool CreateTruncated(const fs::path &path, std::string *error) {
  if (!CreateContiguous(path, error)) {
    return false;
  }
  std::error_code filesystem_error;
  fs::resize_file(path, 64, filesystem_error);
  if (filesystem_error) {
    return SetError(error, "could not truncate HDF5 image: " + filesystem_error.message());
  }
  return true;
}

bool CreateInvalidMetadata(const fs::path &path, std::string *error) {
  const std::array<std::int32_t, 4> values = {1, 2, 3, 4};
  FileContext context;
  if (!CreateFileAndGroup(path, &context, error)) {
    return false;
  }
  Handle space = CreateSpace({2, 2});
  Handle properties = CreateDatasetProperties();
  Handle dataset;
  if (!space.valid() || !properties.valid()) {
    return SetError(error, "could not create invalid-metadata dataset properties");
  }
  dataset = Handle(H5Dcreate2(context.file.get(), "/weights/kernel",
                              H5T_STD_I32LE, space.get(), H5P_DEFAULT,
                              properties.get(), H5P_DEFAULT),
                   H5Dclose, "invalid-metadata dataset");
  if (!dataset.valid() ||
      H5Dwrite(dataset.get(), H5T_NATIVE_INT32, H5S_ALL, H5S_ALL,
               H5P_DEFAULT, values.data()) < 0) {
    return SetError(error, "could not create metadata-corruption source dataset");
  }
  H5O_info1_t object_info = {};
  if (H5Oget_info2(dataset.get(), &object_info, H5O_INFO_BASIC) < 0 ||
      object_info.addr == HADDR_UNDEF || object_info.addr == 0) {
    return SetError(error, "could not locate dataset object metadata");
  }
  const haddr_t object_header_address = object_info.addr;
  if (!CloseAll(error, {&dataset, &properties, &space})) {
    return false;
  }
  if (!FinishFile(&context, error)) {
    return false;
  }
  if (object_header_address >
      static_cast<haddr_t>(std::numeric_limits<std::streamoff>::max())) {
    return SetError(error, "dataset object metadata address is not representable");
  }
  std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
  const auto offset = static_cast<std::streamoff>(object_header_address);
  std::array<char, 4> signature = {};
  stream.seekg(offset, std::ios::beg);
  stream.read(signature.data(), static_cast<std::streamsize>(signature.size()));
  if (!stream || signature != std::array<char, 4>{'O', 'H', 'D', 'R'}) {
    return SetError(error, "dataset object header signature is unavailable");
  }
  signature[0] = 'X';
  stream.seekp(offset, std::ios::beg);
  stream.write(signature.data(), static_cast<std::streamsize>(signature.size()));
  stream.flush();
  if (!stream) {
    return SetError(error, "could not corrupt dataset object header signature");
  }
  stream.close();
  if (!stream) {
    return SetError(error, "could not close metadata-corruption fixture");
  }
  return true;
}

bool CreateUnsupportedFilter(const fs::path &path, std::string *error) {
  FileContext context;
  if (!CreateFileAndGroup(path, &context, error)) {
    return false;
  }
  Handle space = CreateSpace({4});
  Handle properties = CreateDatasetProperties();
  if (!space.valid() || !properties.valid() ||
      H5Pset_chunk(properties.get(), 1, std::array<hsize_t, 1>{4}.data()) < 0 ||
      H5Pset_filter(properties.get(), kUnsupportedFilter, H5Z_FLAG_OPTIONAL, 0,
                    nullptr) < 0) {
    return SetError(error, "could not declare unsupported filter pipeline");
  }
  Handle dataset(H5Dcreate2(context.file.get(), "/weights/filtered",
                            H5T_STD_I32LE, space.get(), H5P_DEFAULT,
                            properties.get(), H5P_DEFAULT),
                 H5Dclose, "unsupported-filter dataset");
  const std::array<hsize_t, 1> offset = {0};
  const std::array<std::int32_t, 4> encoded = {10, 20, 30, 40};
  if (!dataset.valid() ||
      H5Dwrite_chunk(dataset.get(), H5P_DEFAULT, 0, offset.data(),
                     sizeof(encoded), encoded.data()) < 0) {
    return SetError(error, "could not store an encoded chunk requiring the unsupported filter");
  }
  if (!CloseAll(error, {&dataset, &properties, &space})) {
    return false;
  }
  return FinishFile(&context, error);
}

bool CreateUnsupportedDtype(const fs::path &path, std::string *error) {
  FileContext context;
  if (!CreateFileAndGroup(path, &context, error)) {
    return false;
  }
  Handle space = CreateSpace({1});
  Handle properties = CreateDatasetProperties();
  Handle type(H5Tcopy(H5T_C_S1), H5Tclose, "variable-length string type");
  if (!space.valid() || !properties.valid() || !type.valid() ||
      H5Tset_size(type.get(), H5T_VARIABLE) < 0) {
    return SetError(error, "could not create variable-length string dtype");
  }
  Handle dataset(H5Dcreate2(context.file.get(), "/weights/vlen_text", type.get(),
                            space.get(), H5P_DEFAULT, properties.get(), H5P_DEFAULT),
                 H5Dclose, "unsupported-dtype dataset");
  if (!dataset.valid()) {
    return SetError(error, "could not create variable-length string dataset");
  }
  if (!CloseAll(error, {&dataset, &type, &properties, &space})) {
    return false;
  }
  return FinishFile(&context, error);
}

bool CreateExternalLink(const fs::path &path, std::string *error) {
  FileContext context;
  if (!CreateFileAndGroup(path, &context, error)) {
    return false;
  }
  if (H5Lcreate_external("outside-payload.h5", "/payload", context.file.get(),
                         "/weights/external", H5P_DEFAULT, H5P_DEFAULT) < 0) {
    return SetError(error, "could not create external link fixture");
  }
  return FinishFile(&context, error);
}

using CreateFunction = bool (*)(const fs::path &, std::string *);

struct FixtureDefinition {
  const char *id;
  const char *filename;
  const char *classification;
  const char *outcome;
  CreateFunction create;
};

const std::array<FixtureDefinition, 10> kFixtures = {{
    {"scalar-numeric", "scalar-numeric.h5", "normal", "accepted", CreateScalar},
    {"empty-numeric", "empty-numeric.h5", "normal", "accepted", CreateEmpty},
    {"tensor-contiguous", "tensor-contiguous.h5", "normal", "accepted", CreateContiguous},
    {"tensor-chunked", "tensor-chunked.h5", "normal", "accepted", CreateChunked},
    {"missing-dataset", "missing-dataset.h5", "reject", "absent", CreateMissing},
    {"truncated-image", "truncated-image.h5", "reject", "file_rejected", CreateTruncated},
    {"invalid-metadata", "invalid-metadata.h5", "reject", "metadata_rejected", CreateInvalidMetadata},
    {"unsupported-filter", "unsupported-filter.h5", "unsupported", "unsupported_filter", CreateUnsupportedFilter},
    {"unsupported-dtype", "unsupported-dtype.h5", "unsupported", "unsupported_dtype", CreateUnsupportedDtype},
    {"external-link", "external-link.h5", "unsupported", "external_reference", CreateExternalLink},
}};

bool ReadFile(const fs::path &path, std::vector<unsigned char> *bytes,
              std::string *error) {
  std::error_code filesystem_error;
  const fs::file_status status = fs::symlink_status(path, filesystem_error);
  if (filesystem_error || status.type() != fs::file_type::regular) {
    return SetError(error, "fixture is not a regular non-symlink file: " + path.string());
  }
  const std::uintmax_t size = fs::file_size(path, filesystem_error);
  if (filesystem_error || size == 0 ||
      size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
    return SetError(error, "fixture has an invalid size: " + path.string());
  }
  bytes->resize(static_cast<std::size_t>(size));
  std::ifstream stream(path, std::ios::binary);
  if (!stream || !stream.read(reinterpret_cast<char *>(bytes->data()),
                              static_cast<std::streamsize>(bytes->size()))) {
    return SetError(error, "could not read fixture bytes: " + path.string());
  }
  stream.close();
  if (!stream) {
    return SetError(error, "could not close fixture input: " + path.string());
  }
  return true;
}

bool OpenImage(const fs::path &path, std::vector<unsigned char> *bytes,
               Handle *file, std::string *error) {
  if (!ReadFile(path, bytes, error)) {
    return false;
  }
  *file = Handle(H5LTopen_file_image(bytes->data(), bytes->size(), 0), H5Fclose,
                 "file image");
  if (!file->valid()) {
    return SetError(error, "H5LTopen_file_image rejected fixture: " + path.string());
  }
  return true;
}

bool VerifyShape(hid_t dataset, const std::vector<hsize_t> &expected,
                 std::string *error) {
  Handle space(H5Dget_space(dataset), H5Sclose, "dataset dataspace");
  if (!space.valid()) {
    return SetError(error, "could not inspect dataset dataspace");
  }
  const int rank = H5Sget_simple_extent_ndims(space.get());
  if (rank < 0 || static_cast<std::size_t>(rank) != expected.size()) {
    return SetError(error, "dataset rank differs from the fixture contract");
  }
  std::vector<hsize_t> actual(expected.size());
  if (rank > 0 && H5Sget_simple_extent_dims(space.get(), actual.data(), nullptr) < 0) {
    return SetError(error, "could not read dataset dimensions");
  }
  if (actual != expected) {
    return SetError(error, "dataset shape differs from the fixture contract");
  }
  hssize_t expected_count = 1;
  if (!expected.empty()) {
    expected_count = 1;
    for (hsize_t dimension : expected) {
      expected_count *= static_cast<hssize_t>(dimension);
    }
  }
  const hssize_t actual_count = H5Sget_simple_extent_npoints(space.get());
  if (actual_count < 0 || actual_count != expected_count) {
    return SetError(error, "dataset element count differs from the fixture contract");
  }
  return space.CloseChecked(error);
}

bool VerifyType(hid_t dataset, hid_t expected_type, std::string *error) {
  Handle type(H5Dget_type(dataset), H5Tclose, "dataset datatype");
  if (!type.valid() || H5Tequal(type.get(), expected_type) != 1) {
    return SetError(error, "dataset dtype differs from the fixture contract");
  }
  return type.CloseChecked(error);
}

bool VerifyLayout(hid_t dataset, H5D_layout_t expected, int expected_filters,
                  const std::vector<hsize_t> &expected_chunks,
                  std::string *error) {
  Handle properties(H5Dget_create_plist(dataset), H5Pclose,
                    "dataset creation properties");
  if (!properties.valid() || H5Pget_layout(properties.get()) != expected ||
      H5Pget_nfilters(properties.get()) != expected_filters) {
    return SetError(error, "dataset layout/filter count differs from the fixture contract");
  }
  if (expected == H5D_CHUNKED) {
    std::vector<hsize_t> actual_chunks(expected_chunks.size());
    const int rank = H5Pget_chunk(properties.get(),
                                  static_cast<int>(actual_chunks.size()),
                                  actual_chunks.data());
    if (rank < 0 || static_cast<std::size_t>(rank) != expected_chunks.size() ||
        actual_chunks != expected_chunks) {
      return SetError(error, "dataset chunk shape differs from the fixture contract");
    }
  } else if (!expected_chunks.empty()) {
    return SetError(error, "non-chunked dataset has an expected chunk shape");
  }
  return properties.CloseChecked(error);
}

bool VerifyIntAttribute(hid_t object, const char *name, std::int32_t expected,
                        std::string *error) {
  const htri_t exists = H5Aexists(object, name);
  Handle attribute;
  if (exists != 1) {
    return SetError(error, std::string("required attribute is missing: ") + name);
  }
  attribute = Handle(H5Aopen(object, name, H5P_DEFAULT), H5Aclose, "attribute");
  Handle type;
  std::int32_t actual = 0;
  if (attribute.valid()) {
    type = Handle(H5Aget_type(attribute.get()), H5Tclose, "attribute datatype");
  }
  if (!attribute.valid() || !type.valid() ||
      H5Tequal(type.get(), H5T_STD_I32LE) != 1 ||
      H5Aread(attribute.get(), H5T_NATIVE_INT32, &actual) < 0 || actual != expected) {
    return SetError(error, std::string("attribute value differs: ") + name);
  }
  return CloseAll(error, {&type, &attribute});
}

template <typename Value, std::size_t Size>
bool VerifyNumeric(const fs::path &path, const char *dataset_path,
                   hid_t file_type, hid_t memory_type,
                   const std::vector<hsize_t> &shape,
                   const std::array<Value, Size> &expected_values,
                   H5D_layout_t layout,
                   const std::vector<hsize_t> &expected_chunks,
                   bool attributes, std::string *error) {
  std::vector<unsigned char> bytes;
  Handle file;
  if (!OpenImage(path, &bytes, &file, error)) {
    return false;
  }
  const htri_t group_exists = H5Lexists(file.get(), "/weights", H5P_DEFAULT);
  Handle group(H5Gopen2(file.get(), "/weights", H5P_DEFAULT), H5Gclose,
               "weights group");
  Handle dataset(H5Dopen2(file.get(), dataset_path, H5P_DEFAULT), H5Dclose,
                 "numeric dataset");
  if (group_exists != 1 || !group.valid() || !dataset.valid() ||
      !VerifyType(dataset.get(), file_type, error) ||
      !VerifyShape(dataset.get(), shape, error) ||
      !VerifyLayout(dataset.get(), layout, 0, expected_chunks, error)) {
    return SetError(error, "numeric fixture structure is invalid");
  }
  if constexpr (Size > 0) {
    std::array<Value, Size> actual = {};
    if (H5Dread(dataset.get(), memory_type, H5S_ALL, H5S_ALL, H5P_DEFAULT,
                actual.data()) < 0 || actual != expected_values) {
      return SetError(error, "numeric fixture values differ from the contract");
    }
  }
  if (attributes &&
      (!VerifyIntAttribute(group.get(), "fixture_version", 1, error) ||
       !VerifyIntAttribute(dataset.get(), "axis_count", 2, error))) {
    return false;
  }
  return CloseAll(error, {&dataset, &group, &file});
}

bool VerifyScalar(const fs::path &path, std::string *error) {
  return VerifyNumeric(path, "/weights/scalar", H5T_STD_I64LE,
                       H5T_NATIVE_INT64, {}, std::array<std::int64_t, 1>{7},
                       H5D_CONTIGUOUS, {}, false, error);
}

bool VerifyEmpty(const fs::path &path, std::string *error) {
  return VerifyNumeric(path, "/weights/empty", H5T_IEEE_F32LE,
                       H5T_NATIVE_FLOAT, {0, 3}, std::array<float, 0>{},
                       H5D_CONTIGUOUS, {}, false, error);
}

bool VerifyContiguous(const fs::path &path, std::string *error) {
  const std::array<float, 6> values = {1.25F, -2.0F, 3.5F, 4.25F, -5.75F, 6.0F};
  return VerifyNumeric(path, "/weights/kernel", H5T_IEEE_F32LE,
                       H5T_NATIVE_FLOAT, {2, 3}, values, H5D_CONTIGUOUS,
                       {}, true, error);
}

bool VerifyChunked(const fs::path &path, std::string *error) {
  const std::array<std::int16_t, 6> values = {-3, 0, 7, 11, 1024, -2048};
  return VerifyNumeric(path, "/weights/chunked", H5T_STD_I16LE,
                       H5T_NATIVE_INT16, {3, 2}, values, H5D_CHUNKED,
                       {2, 2}, false, error);
}

bool VerifyMissing(const fs::path &path, std::string *error) {
  std::vector<unsigned char> bytes;
  Handle file;
  if (!OpenImage(path, &bytes, &file, error)) {
    return false;
  }
  const htri_t group = H5Lexists(file.get(), "/weights", H5P_DEFAULT);
  const htri_t dataset = H5Lexists(file.get(), "/weights/missing", H5P_DEFAULT);
  if (group != 1 || dataset != 0) {
    return SetError(error, "missing fixture does not preserve actual dataset absence");
  }
  return file.CloseChecked(error);
}

bool VerifyTruncated(const fs::path &path, std::string *error) {
  std::vector<unsigned char> bytes;
  if (!ReadFile(path, &bytes, error)) {
    return false;
  }
  const hid_t opened = H5LTopen_file_image(bytes.data(), bytes.size(), 0);
  if (opened >= 0) {
    Handle unexpected(opened, H5Fclose, "unexpected truncated file image");
    if (!unexpected.CloseChecked(error)) {
      return false;
    }
    return SetError(error, "truncated HDF5 image was accepted");
  }
  return true;
}

bool VerifyInvalidMetadata(const fs::path &path, std::string *error) {
  std::vector<unsigned char> bytes;
  Handle file;
  if (!OpenImage(path, &bytes, &file, error)) {
    return false;
  }
  const htri_t link_exists =
      H5Lexists(file.get(), "/weights/kernel", H5P_DEFAULT);
  Handle dataset(H5Dopen2(file.get(), "/weights/kernel", H5P_DEFAULT), H5Dclose,
                 "invalid-metadata dataset");
  if (link_exists != 1) {
    return SetError(error, "corrupt dataset link is not present");
  }
  if (dataset.valid()) {
    if (!dataset.CloseChecked(error)) {
      return false;
    }
    return SetError(error, "corrupt dataset object metadata was accepted");
  }
  return file.CloseChecked(error);
}

bool VerifyUnsupportedFilter(const fs::path &path, std::string *error) {
  std::vector<unsigned char> bytes;
  Handle file;
  if (!OpenImage(path, &bytes, &file, error)) {
    return false;
  }
  Handle dataset(H5Dopen2(file.get(), "/weights/filtered", H5P_DEFAULT), H5Dclose,
                 "unsupported-filter dataset");
  Handle properties;
  if (!dataset.valid() || !VerifyType(dataset.get(), H5T_STD_I32LE, error) ||
      !VerifyShape(dataset.get(), {4}, error)) {
    return SetError(error, "unsupported-filter dataset is unavailable");
  }
  properties = Handle(H5Dget_create_plist(dataset.get()), H5Pclose,
                      "unsupported-filter properties");
  unsigned flags = 0;
  std::array<unsigned, 8> client_data = {};
  std::size_t client_count = client_data.size();
  std::array<char, 64> name = {};
  const H5Z_filter_t filter =
      properties.valid()
          ? H5Pget_filter2(properties.get(), 0, &flags, &client_count,
                           client_data.data(), name.size(), name.data(), nullptr)
          : H5Z_FILTER_ERROR;
  std::array<hsize_t, 1> chunk_shape = {0};
  if (!properties.valid() || H5Pget_nfilters(properties.get()) != 1 ||
      H5Pget_layout(properties.get()) != H5D_CHUNKED ||
      H5Pget_chunk(properties.get(), 1, chunk_shape.data()) != 1 ||
      chunk_shape != std::array<hsize_t, 1>{4} ||
      filter != kUnsupportedFilter || (flags & H5Z_FLAG_OPTIONAL) == 0U ||
      client_count != 0 || H5Zfilter_avail(kUnsupportedFilter) != 0) {
    return SetError(error, "unsupported filter declaration/availability differs");
  }
  const std::array<hsize_t, 1> offset = {0};
  std::uint32_t filter_mask = std::numeric_limits<std::uint32_t>::max();
  std::array<std::int32_t, 4> encoded = {};
  const std::array<std::int32_t, 4> expected_encoded = {10, 20, 30, 40};
  std::size_t encoded_size = sizeof(encoded);
  if (H5Dread_chunk(dataset.get(), H5P_DEFAULT, offset.data(), &filter_mask,
                    encoded.data(), &encoded_size) < 0 ||
      encoded_size != sizeof(encoded) || filter_mask != 0U ||
      encoded != expected_encoded) {
    return SetError(error, "stored unsupported-filter chunk metadata differs");
  }
  std::array<std::int32_t, 4> values = {};
  if (H5Dread(dataset.get(), H5T_NATIVE_INT32, H5S_ALL, H5S_ALL, H5P_DEFAULT,
              values.data()) >= 0) {
    return SetError(error, "dataset requiring unavailable filter was readable");
  }
  return CloseAll(error, {&properties, &dataset, &file});
}

bool VerifyUnsupportedDtype(const fs::path &path, std::string *error) {
  std::vector<unsigned char> bytes;
  Handle file;
  if (!OpenImage(path, &bytes, &file, error)) {
    return false;
  }
  Handle dataset(H5Dopen2(file.get(), "/weights/vlen_text", H5P_DEFAULT), H5Dclose,
                 "unsupported-dtype dataset");
  Handle type;
  if (!dataset.valid() || !VerifyShape(dataset.get(), {1}, error)) {
    return SetError(error, "unsupported-dtype dataset is unavailable");
  }
  type = Handle(H5Dget_type(dataset.get()), H5Tclose, "unsupported datatype");
  if (!type.valid() || H5Tget_class(type.get()) != H5T_STRING ||
      H5Tis_variable_str(type.get()) != 1 ||
      !VerifyLayout(dataset.get(), H5D_CONTIGUOUS, 0, {}, error)) {
    return SetError(error, "variable-length string dtype is not present");
  }
  return CloseAll(error, {&type, &dataset, &file});
}

bool VerifyExternalLink(const fs::path &path, std::string *error) {
  std::vector<unsigned char> bytes;
  Handle file;
  if (!OpenImage(path, &bytes, &file, error)) {
    return false;
  }
  H5L_info2_t info = {};
  if (H5Lget_info2(file.get(), "/weights/external", &info, H5P_DEFAULT) < 0 ||
      info.type != H5L_TYPE_EXTERNAL || info.u.val_size == 0) {
    return SetError(error, "external link metadata is unavailable");
  }
  std::vector<unsigned char> value(info.u.val_size);
  if (H5Lget_val(file.get(), "/weights/external", value.data(), value.size(),
                 H5P_DEFAULT) < 0) {
    return SetError(error, "could not read external link value");
  }
  unsigned flags = 0;
  const char *filename = nullptr;
  const char *object_path = nullptr;
  if (H5Lunpack_elink_val(value.data(), value.size(), &flags, &filename,
                          &object_path) < 0 ||
      filename == nullptr || object_path == nullptr ||
      std::string_view(filename) != "outside-payload.h5" ||
      std::string_view(object_path) != "/payload") {
    return SetError(error, "external link target differs from the fixture contract");
  }
  const hid_t external = H5Dopen2(file.get(), "/weights/external", H5P_DEFAULT);
  if (external >= 0) {
    Handle unexpected(external, H5Dclose, "unexpected external dataset");
    if (!unexpected.CloseChecked(error)) {
      return false;
    }
    return SetError(error, "external link unexpectedly resolved without outside storage");
  }
  return file.CloseChecked(error);
}

using VerifyFunction = bool (*)(const fs::path &, std::string *);

const std::array<VerifyFunction, 10> kVerifiers = {{
    VerifyScalar,
    VerifyEmpty,
    VerifyContiguous,
    VerifyChunked,
    VerifyMissing,
    VerifyTruncated,
    VerifyInvalidMetadata,
    VerifyUnsupportedFilter,
    VerifyUnsupportedDtype,
    VerifyExternalLink,
}};

bool ValidateRuntime(std::string *error) {
  unsigned major = 0;
  unsigned minor = 0;
  unsigned release = 0;
  if (H5Eset_auto2(H5E_DEFAULT, nullptr, nullptr) < 0 ||
      H5get_libversion(&major, &minor, &release) < 0 || major != 2U ||
      minor != 2U || release != 0U) {
    return SetError(error, "runtime library is not the pinned HDF5 2.2.0");
  }
  return true;
}

int Generate(const fs::path &output) {
  std::error_code filesystem_error;
  const fs::file_status status = fs::symlink_status(output, filesystem_error);
  if (filesystem_error || status.type() != fs::file_type::directory ||
      fs::is_symlink(status) || !fs::is_empty(output, filesystem_error) ||
      filesystem_error) {
    std::cerr << "HDF5_FIXTURE_ERROR output must be an empty non-symlink directory\n";
    return 1;
  }
  for (const FixtureDefinition &fixture : kFixtures) {
    std::string error;
    const fs::path path = output / fixture.filename;
    if (fs::exists(path) || !fixture.create(path, &error)) {
      std::cerr << "HDF5_FIXTURE_ERROR id=" << fixture.id << " error=" << error << '\n';
      return 1;
    }
  }
  std::cout << "HDF5_FIXTURE_GENERATED count=" << kFixtures.size() << '\n';
  return 0;
}

int Verify(const fs::path &output) {
  for (std::size_t index = 0; index < kFixtures.size(); ++index) {
    const FixtureDefinition &fixture = kFixtures[index];
    std::string error;
    if (!kVerifiers[index](output / fixture.filename, &error)) {
      std::cerr << "HDF5_FIXTURE_ERROR id=" << fixture.id << " error=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_FIXTURE id=" << fixture.id
              << " class=" << fixture.classification
              << " outcome=" << fixture.outcome << '\n';
  }
  std::cout << "HDF5_FIXTURE_SET_OK normal=4 reject=3 unsupported=3\n";
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  std::string error;
  if (!ValidateRuntime(&error)) {
    std::cerr << "HDF5_FIXTURE_ERROR error=" << error << '\n';
    return 1;
  }
  if (argc != 3) {
    std::cerr << "usage: hdf5_fixture_tool <generate|verify> OUTPUT_DIR\n";
    return 64;
  }
  const std::string_view command(argv[1]);
  const fs::path output(argv[2]);
  if (command == "generate") {
    return Generate(output);
  }
  if (command == "verify") {
    return Verify(output);
  }
  std::cerr << "HDF5_FIXTURE_ERROR unknown command\n";
  return 64;
}
