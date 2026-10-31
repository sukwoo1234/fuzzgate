#include <hdf5.h>
#include <hdf5_hl.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <locale>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;

class Handle {
public:
  using Close = herr_t (*)(hid_t);

  Handle() = default;
  Handle(hid_t id, Close close) : id_(id), close_(close) {}
  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;
  Handle(Handle &&other) noexcept : id_(other.id_), close_(other.close_) {
    other.id_ = H5I_INVALID_HID;
  }
  Handle &operator=(Handle &&other) noexcept {
    if (this != &other) {
      CloseUnchecked();
      id_ = other.id_;
      close_ = other.close_;
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
        *error = "handle_close_failed";
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
      if (close_ != nullptr) {
        static_cast<void>(close_(id));
      }
    }
  }

  hid_t id_ = H5I_INVALID_HID;
  Close close_ = nullptr;
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

bool ValidateRuntime(std::string *error) {
  unsigned major = 0;
  unsigned minor = 0;
  unsigned release = 0;
  if (H5Eset_auto2(H5E_DEFAULT, nullptr, nullptr) < 0 ||
      H5get_libversion(&major, &minor, &release) < 0 || major != 2U ||
      minor != 2U || release != 0U) {
    return SetError(error, "runtime_not_hdf5_2.2.0");
  }
  return true;
}

bool IsRegularNonSymlink(const fs::path &path, std::string *error) {
  std::error_code filesystem_error;
  const fs::file_status status = fs::symlink_status(path, filesystem_error);
  if (filesystem_error || status.type() != fs::file_type::regular) {
    return SetError(error, "input_not_regular_non_symlink");
  }
  return true;
}

bool IsFreshOutput(const fs::path &path, std::string *error) {
  std::error_code filesystem_error;
  const fs::file_status status = fs::symlink_status(path, filesystem_error);
  if ((!filesystem_error && status.type() != fs::file_type::not_found) ||
      (filesystem_error &&
       filesystem_error != std::errc::no_such_file_or_directory)) {
    return SetError(error, "output_not_fresh");
  }
  return true;
}

bool ReadRegularFile(const fs::path &path, std::vector<unsigned char> *bytes,
                     std::string *error) {
  if (!IsRegularNonSymlink(path, error)) {
    return false;
  }
  std::error_code filesystem_error;
  const std::uintmax_t size = fs::file_size(path, filesystem_error);
  const std::uintmax_t maximum_size = static_cast<std::uintmax_t>(
      std::min(std::numeric_limits<std::size_t>::max(),
               static_cast<std::size_t>(
                   std::numeric_limits<std::streamsize>::max())));
  if (filesystem_error || size == 0 || size > maximum_size) {
    return SetError(error, "input_size_invalid");
  }
  bytes->resize(static_cast<std::size_t>(size));
  std::ifstream stream(path, std::ios::binary);
  if (!stream ||
      !stream.read(reinterpret_cast<char *>(bytes->data()),
                   static_cast<std::streamsize>(bytes->size()))) {
    return SetError(error, "input_read_failed");
  }
  stream.close();
  if (!stream) {
    return SetError(error, "input_close_failed");
  }
  return true;
}

bool CopyFresh(const fs::path &input, const fs::path &output,
               std::string *error) {
  if (!IsRegularNonSymlink(input, error) || !IsFreshOutput(output, error)) {
    return false;
  }
  std::error_code filesystem_error;
  if (!fs::copy_file(input, output, fs::copy_options::none, filesystem_error) ||
      filesystem_error) {
    return SetError(error, "output_copy_failed");
  }
  return true;
}

void RemoveCreatedOutput(const fs::path &output) {
  std::error_code filesystem_error;
  static_cast<void>(fs::remove(output, filesystem_error));
}

bool UniqueLinkName(hid_t group, std::string *name, std::string *error) {
  H5G_info_t info = {};
  if (H5Gget_info(group, &info) < 0 || info.nlinks != 1U) {
    return SetError(error, "object_link_count_not_one");
  }
  const ssize_t length =
      H5Lget_name_by_idx(group, ".", H5_INDEX_NAME, H5_ITER_INC, 0, nullptr,
                         0, H5P_DEFAULT);
  if (length <= 0 ||
      static_cast<std::uintmax_t>(length) >=
          static_cast<std::uintmax_t>(
              std::numeric_limits<std::size_t>::max())) {
    return SetError(error, "object_name_unavailable");
  }
  const std::size_t size = static_cast<std::size_t>(length);
  std::vector<char> buffer(size + 1U, '\0');
  const ssize_t actual = H5Lget_name_by_idx(
      group, ".", H5_INDEX_NAME, H5_ITER_INC, 0, buffer.data(), buffer.size(),
      H5P_DEFAULT);
  if (actual != length) {
    return SetError(error, "object_name_read_failed");
  }
  name->assign(buffer.data(), size);
  return true;
}

bool UniqueAttributeName(hid_t object, std::string *name,
                         std::string *error) {
  H5O_info2_t info = {};
  if (H5Oget_info3(object, &info, H5O_INFO_NUM_ATTRS) < 0 ||
      info.num_attrs != 1U) {
    return SetError(error, "attribute_count_not_one");
  }
  const ssize_t length = H5Aget_name_by_idx(
      object, ".", H5_INDEX_NAME, H5_ITER_INC, 0, nullptr, 0, H5P_DEFAULT);
  if (length <= 0 ||
      static_cast<std::uintmax_t>(length) >=
          static_cast<std::uintmax_t>(
              std::numeric_limits<std::size_t>::max())) {
    return SetError(error, "attribute_name_unavailable");
  }
  const std::size_t size = static_cast<std::size_t>(length);
  std::vector<char> buffer(size + 1U, '\0');
  const ssize_t actual = H5Aget_name_by_idx(
      object, ".", H5_INDEX_NAME, H5_ITER_INC, 0, buffer.data(), buffer.size(),
      H5P_DEFAULT);
  if (actual != length) {
    return SetError(error, "attribute_name_read_failed");
  }
  name->assign(buffer.data(), size);
  return true;
}

bool ReadUniqueIntAttribute(hid_t object, std::string *name,
                            std::int32_t *value, std::string *error) {
  if (!UniqueAttributeName(object, name, error)) {
    return false;
  }
  Handle attribute(H5Aopen(object, name->c_str(), H5P_DEFAULT), H5Aclose);
  Handle type;
  Handle space;
  if (attribute.valid()) {
    type = Handle(H5Aget_type(attribute.get()), H5Tclose);
    space = Handle(H5Aget_space(attribute.get()), H5Sclose);
  }
  if (!attribute.valid() || !type.valid() || !space.valid() ||
      H5Tequal(type.get(), H5T_STD_I32LE) != 1 ||
      H5Sget_simple_extent_type(space.get()) != H5S_SCALAR ||
      H5Sget_simple_extent_npoints(space.get()) != 1 ||
      H5Aread(attribute.get(), H5T_NATIVE_INT32, value) < 0) {
    return SetError(error, "attribute_contract_invalid");
  }
  return CloseAll(error, {&space, &type, &attribute});
}

std::string Hex(const std::string &value) {
  constexpr std::array<char, 16> digits = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };
  std::string result;
  result.reserve(value.size() * 2U);
  for (const char character : value) {
    const auto byte = static_cast<unsigned char>(character);
    result.push_back(digits[static_cast<std::size_t>(byte >> 4U)]);
    result.push_back(digits[static_cast<std::size_t>(byte & 0x0FU)]);
  }
  return result;
}

bool CanonicalFloat(float value, std::string *result, std::string *error) {
  if (!std::isfinite(value)) {
    return SetError(error, "dataset_value_not_finite");
  }
  std::ostringstream output;
  output.imbue(std::locale::classic());
  output << std::setprecision(std::numeric_limits<float>::max_digits10)
         << value;
  if (!output) {
    return SetError(error, "dataset_value_format_failed");
  }
  std::string formatted = output.str();
  const std::size_t exponent_position = formatted.find_first_of("eE");
  if (exponent_position == std::string::npos) {
    *result = std::move(formatted);
    return true;
  }
  const std::string mantissa = formatted.substr(0, exponent_position);
  std::string exponent = formatted.substr(exponent_position + 1U);
  bool negative = false;
  if (!exponent.empty() && (exponent.front() == '+' || exponent.front() == '-')) {
    negative = exponent.front() == '-';
    exponent.erase(exponent.begin());
  }
  const std::size_t first_nonzero = exponent.find_first_not_of('0');
  if (first_nonzero == std::string::npos) {
    *result = mantissa;
    return true;
  }
  exponent.erase(0, first_nonzero);
  *result = mantissa + "e" + (negative ? "-" : "") + exponent;
  return true;
}

template <typename Value, std::size_t Size>
std::string JoinIntegers(const std::array<Value, Size> &values) {
  std::ostringstream output;
  output.imbue(std::locale::classic());
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U) {
      output << ',';
    }
    output << values[index];
  }
  return output.str();
}

bool JoinFloats(const std::array<float, 6> &values, std::string *result,
                std::string *error) {
  std::string joined;
  for (std::size_t index = 0; index < values.size(); ++index) {
    std::string formatted;
    if (!CanonicalFloat(values[index], &formatted, error)) {
      return false;
    }
    if (index != 0U) {
      joined.push_back(',');
    }
    joined += formatted;
  }
  *result = std::move(joined);
  return true;
}

struct Probe {
  std::string group;
  std::string dataset;
  std::string dtype;
  std::array<hsize_t, 2> shape = {};
  std::string layout;
  std::string chunks;
  std::string group_attribute;
  std::int32_t group_attribute_value = 0;
  std::string dataset_attribute;
  std::int32_t dataset_attribute_value = 0;
  std::string values;
};

bool Inspect(const fs::path &path, Probe *probe, std::string *error) {
  std::vector<unsigned char> bytes;
  if (!ReadRegularFile(path, &bytes, error)) {
    return false;
  }
  Handle file(H5LTopen_file_image(bytes.data(), bytes.size(), 0), H5Fclose);
  Handle root;
  Handle group;
  Handle dataset;
  if (file.valid()) {
    root = Handle(H5Gopen2(file.get(), "/", H5P_DEFAULT), H5Gclose);
  }
  H5O_info2_t root_info = {};
  if (!root.valid() ||
      H5Oget_info3(root.get(), &root_info, H5O_INFO_NUM_ATTRS) < 0 ||
      root_info.num_attrs != 0U) {
    return SetError(error, "root_attribute_contract_invalid");
  }
  std::string group_name;
  std::string dataset_name;
  if (!file.valid() || !root.valid() ||
      !UniqueLinkName(root.get(), &group_name, error)) {
    return SetError(error, "root_group_contract_invalid");
  }
  H5L_info2_t group_link_info = {};
  if (H5Lget_info2(root.get(), group_name.c_str(), &group_link_info,
                   H5P_DEFAULT) < 0 ||
      group_link_info.type != H5L_TYPE_HARD) {
    return SetError(error, "object_link_not_hard");
  }
  group = Handle(H5Gopen2(root.get(), group_name.c_str(), H5P_DEFAULT),
                 H5Gclose);
  if (!group.valid() || !UniqueLinkName(group.get(), &dataset_name, error)) {
    return SetError(error, "nested_group_contract_invalid");
  }
  H5L_info2_t dataset_link_info = {};
  if (H5Lget_info2(group.get(), dataset_name.c_str(), &dataset_link_info,
                   H5P_DEFAULT) < 0 ||
      dataset_link_info.type != H5L_TYPE_HARD) {
    return SetError(error, "object_link_not_hard");
  }
  dataset = Handle(H5Dopen2(group.get(), dataset_name.c_str(), H5P_DEFAULT),
                   H5Dclose);
  if (!dataset.valid()) {
    return SetError(error, "dataset_open_failed");
  }

  Handle type(H5Dget_type(dataset.get()), H5Tclose);
  Handle space(H5Dget_space(dataset.get()), H5Sclose);
  Handle properties(H5Dget_create_plist(dataset.get()), H5Pclose);
  if (!type.valid() || !space.valid() || !properties.valid() ||
      H5Sget_simple_extent_ndims(space.get()) != 2 ||
      H5Sget_simple_extent_dims(space.get(), probe->shape.data(), nullptr) < 0 ||
      H5Sget_simple_extent_npoints(space.get()) != 6) {
    return SetError(error, "dataset_shape_contract_invalid");
  }
  const int external_count = H5Pget_external_count(properties.get());
  if (external_count < 0) {
    return SetError(error, "external_storage_count_unavailable");
  }
  if (external_count != 0) {
    return SetError(error, "external_storage_unsupported");
  }
  const int filter_count = H5Pget_nfilters(properties.get());
  if (filter_count < 0) {
    return SetError(error, "dataset_filter_count_unavailable");
  }
  if (filter_count != 0) {
    return SetError(error, "dataset_filters_unsupported");
  }

  const htri_t is_float = H5Tequal(type.get(), H5T_IEEE_F32LE);
  const htri_t is_integer = H5Tequal(type.get(), H5T_STD_I32LE);
  if (is_float < 0 || is_integer < 0 || (is_float != 1 && is_integer != 1)) {
    return SetError(error, "dataset_dtype_unsupported");
  }
  if (is_float == 1) {
    std::array<float, 6> values = {};
    if (H5Dread(dataset.get(), H5T_NATIVE_FLOAT, H5S_ALL, H5S_ALL,
                H5P_DEFAULT, values.data()) < 0 ||
        !JoinFloats(values, &probe->values, error)) {
      return SetError(error, "dataset_float_read_failed");
    }
    probe->dtype = "float32-le";
  } else {
    std::array<std::int32_t, 6> values = {};
    if (H5Dread(dataset.get(), H5T_NATIVE_INT32, H5S_ALL, H5S_ALL,
                H5P_DEFAULT, values.data()) < 0) {
      return SetError(error, "dataset_integer_read_failed");
    }
    probe->values = JoinIntegers(values);
    probe->dtype = "int32-le";
  }

  const H5D_layout_t layout = H5Pget_layout(properties.get());
  if (layout == H5D_CONTIGUOUS) {
    probe->layout = "contiguous";
    probe->chunks = "none";
  } else if (layout == H5D_CHUNKED) {
    std::array<hsize_t, 2> chunks = {};
    if (H5Pget_chunk(properties.get(), static_cast<int>(chunks.size()),
                     chunks.data()) != static_cast<int>(chunks.size()) ||
        chunks[0] == 0U || chunks[1] == 0U) {
      return SetError(error, "dataset_chunk_contract_invalid");
    }
    std::ostringstream chunk_text;
    chunk_text.imbue(std::locale::classic());
    chunk_text << chunks[0] << 'x' << chunks[1];
    probe->layout = "chunked";
    probe->chunks = chunk_text.str();
  } else {
    return SetError(error, "dataset_layout_unsupported");
  }

  if (!ReadUniqueIntAttribute(group.get(), &probe->group_attribute,
                              &probe->group_attribute_value, error) ||
      !ReadUniqueIntAttribute(dataset.get(), &probe->dataset_attribute,
                              &probe->dataset_attribute_value, error)) {
    return false;
  }
  probe->group = "/" + group_name;
  probe->dataset = dataset_name;
  return CloseAll(error, {&properties, &space, &type, &dataset, &group, &root,
                          &file});
}

bool AddExtraToCopy(const fs::path &input, const fs::path &output,
                    std::string *error) {
  if (!CopyFresh(input, output, error)) {
    return false;
  }
  bool ok = false;
  {
    Handle file(H5Fopen(output.c_str(), H5F_ACC_RDWR, H5P_DEFAULT), H5Fclose);
    Handle group;
    Handle space;
    Handle properties;
    Handle dataset;
    if (file.valid()) {
      group = Handle(H5Gopen2(file.get(), "/weights", H5P_DEFAULT), H5Gclose);
    }
    if (group.valid()) {
      space = Handle(H5Screate(H5S_SCALAR), H5Sclose);
      properties = Handle(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
    }
    const htri_t exists =
        group.valid() ? H5Lexists(group.get(), "extra", H5P_DEFAULT) : -1;
    if (space.valid() && properties.valid() && exists == 0 &&
        H5Pset_obj_track_times(properties.get(), false) >= 0) {
      dataset = Handle(H5Dcreate2(group.get(), "extra", H5T_STD_I32LE,
                                  space.get(), H5P_DEFAULT, properties.get(),
                                  H5P_DEFAULT),
                       H5Dclose);
    }
    const std::int32_t value = 7;
    if (!file.valid() || !group.valid() || !space.valid() ||
        !properties.valid() || exists != 0 || !dataset.valid() ||
        H5Dwrite(dataset.get(), H5T_NATIVE_INT32, H5S_ALL, H5S_ALL,
                 H5P_DEFAULT, &value) < 0 ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "add_extra_failed");
    } else {
      ok = CloseAll(error,
                    {&dataset, &properties, &space, &group, &file});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
  }
  return ok;
}

bool WriteExistingIntAttribute(hid_t object, const char *name,
                               std::int32_t value, std::string *error) {
  Handle attribute(H5Aopen(object, name, H5P_DEFAULT), H5Aclose);
  Handle type;
  Handle space;
  if (attribute.valid()) {
    type = Handle(H5Aget_type(attribute.get()), H5Tclose);
    space = Handle(H5Aget_space(attribute.get()), H5Sclose);
  }
  if (!attribute.valid() || !type.valid() || !space.valid() ||
      H5Tequal(type.get(), H5T_STD_I32LE) != 1 ||
      H5Sget_simple_extent_type(space.get()) != H5S_SCALAR ||
      H5Sget_simple_extent_npoints(space.get()) != 1 ||
      H5Awrite(attribute.get(), H5T_NATIVE_INT32, &value) < 0) {
    return SetError(error, "attribute_update_failed");
  }
  return CloseAll(error, {&space, &type, &attribute});
}

bool SetAttributesOnCopy(const fs::path &input, const fs::path &output,
                         std::int32_t group_value,
                         std::int32_t dataset_value, std::string *error) {
  if (!CopyFresh(input, output, error)) {
    return false;
  }
  bool ok = false;
  {
    Handle file(H5Fopen(output.c_str(), H5F_ACC_RDWR, H5P_DEFAULT), H5Fclose);
    Handle group;
    Handle dataset;
    if (file.valid()) {
      group = Handle(H5Gopen2(file.get(), "/weights", H5P_DEFAULT), H5Gclose);
      dataset = Handle(H5Dopen2(file.get(), "/weights/kernel", H5P_DEFAULT),
                       H5Dclose);
    }
    if (!file.valid() || !group.valid() || !dataset.valid() ||
        !WriteExistingIntAttribute(group.get(), "fixture_version", group_value,
                                   error) ||
        !WriteExistingIntAttribute(dataset.get(), "axis_count", dataset_value,
                                   error) ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "set_attributes_failed");
    } else {
      ok = CloseAll(error, {&dataset, &group, &file});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
  }
  return ok;
}

bool WriteNewIntAttribute(hid_t object, const char *name, std::int32_t value,
                          std::string *error) {
  Handle space(H5Screate(H5S_SCALAR), H5Sclose);
  Handle attribute;
  if (space.valid()) {
    attribute = Handle(H5Acreate2(object, name, H5T_STD_I32LE, space.get(),
                                  H5P_DEFAULT, H5P_DEFAULT),
                       H5Aclose);
  }
  if (!space.valid() || !attribute.valid() ||
      H5Awrite(attribute.get(), H5T_NATIVE_INT32, &value) < 0) {
    return SetError(error, "attribute_create_failed");
  }
  return CloseAll(error, {&attribute, &space});
}

bool AddRootAttributeToCopy(const fs::path &input, const fs::path &output,
                            std::string *error) {
  if (!CopyFresh(input, output, error)) {
    return false;
  }
  bool ok = false;
  {
    Handle file(H5Fopen(output.c_str(), H5F_ACC_RDWR, H5P_DEFAULT), H5Fclose);
    Handle root;
    if (file.valid()) {
      root = Handle(H5Gopen2(file.get(), "/", H5P_DEFAULT), H5Gclose);
    }
    if (!file.valid() || !root.valid() ||
        !WriteNewIntAttribute(root.get(), "unexpected_root", 99, error) ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "add_root_attribute_failed");
    } else {
      ok = CloseAll(error, {&root, &file});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
  }
  return ok;
}

bool SetArrayAttributeOnCopy(const fs::path &input, const fs::path &output,
                             std::string *error) {
  if (!CopyFresh(input, output, error)) {
    return false;
  }
  bool ok = false;
  {
    Handle file(H5Fopen(output.c_str(), H5F_ACC_RDWR, H5P_DEFAULT), H5Fclose);
    Handle group;
    Handle space;
    Handle attribute;
    if (file.valid()) {
      group = Handle(H5Gopen2(file.get(), "/weights", H5P_DEFAULT), H5Gclose);
    }
    const std::array<hsize_t, 1> dimensions = {2};
    if (group.valid() && H5Adelete(group.get(), "fixture_version") >= 0) {
      space = Handle(H5Screate_simple(1, dimensions.data(), nullptr), H5Sclose);
    }
    if (space.valid()) {
      attribute = Handle(
          H5Acreate2(group.get(), "fixture_version", H5T_STD_I32LE,
                     space.get(), H5P_DEFAULT, H5P_DEFAULT),
          H5Aclose);
    }
    const std::array<std::int32_t, 2> values = {41, 42};
    if (!file.valid() || !group.valid() || !space.valid() ||
        !attribute.valid() ||
        H5Awrite(attribute.get(), H5T_NATIVE_INT32, values.data()) < 0 ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "set_array_attribute_failed");
    } else {
      ok = CloseAll(error, {&attribute, &space, &group, &file});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
  }
  return ok;
}

bool SetFirstPayloadOnCopy(const fs::path &input, const fs::path &output,
                           float first_value, std::string *error) {
  if (!CopyFresh(input, output, error)) {
    return false;
  }
  bool ok = false;
  {
    Handle file(H5Fopen(output.c_str(), H5F_ACC_RDWR, H5P_DEFAULT), H5Fclose);
    Handle dataset;
    if (file.valid()) {
      dataset = Handle(
          H5Dopen2(file.get(), "/weights/kernel", H5P_DEFAULT), H5Dclose);
    }
    std::array<float, 6> values = {};
    if (!file.valid() || !dataset.valid() ||
        H5Dread(dataset.get(), H5T_NATIVE_FLOAT, H5S_ALL, H5S_ALL,
                H5P_DEFAULT, values.data()) < 0) {
      SetError(error, "large_payload_read_failed");
    } else {
      values[0] = first_value;
      if (H5Dwrite(dataset.get(), H5T_NATIVE_FLOAT, H5S_ALL, H5S_ALL,
                   H5P_DEFAULT, values.data()) < 0 ||
          H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
        SetError(error, "large_payload_write_failed");
      } else {
        ok = CloseAll(error, {&dataset, &file});
      }
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
  }
  return ok;
}

bool CreateExternalStorageFixture(const fs::path &output,
                                  const fs::path &raw_output,
                                  std::string *error) {
  if (!IsFreshOutput(output, error) || !IsFreshOutput(raw_output, error)) {
    return false;
  }
  const std::array<float, 6> values = {
      1.25F, -2.0F, 3.5F, 4.25F, -5.75F, 6.0F};
  {
    std::ofstream raw(raw_output, std::ios::binary | std::ios::out);
    raw.write(reinterpret_cast<const char *>(values.data()),
              static_cast<std::streamsize>(sizeof(values)));
    raw.close();
    if (!raw) {
      RemoveCreatedOutput(raw_output);
      return SetError(error, "external_storage_raw_write_failed");
    }
  }
  std::error_code filesystem_error;
  const fs::path absolute_raw = fs::absolute(raw_output, filesystem_error);
  bool ok = false;
  {
    Handle fapl(H5Pcreate(H5P_FILE_ACCESS), H5Pclose);
    Handle fcpl(H5Pcreate(H5P_FILE_CREATE), H5Pclose);
    Handle file;
    Handle gcpl;
    Handle group;
    Handle space;
    Handle dcpl;
    Handle dataset;
    const std::array<hsize_t, 2> shape = {2, 3};
    if (!filesystem_error && fapl.valid() && fcpl.valid() &&
        H5Pset_libver_bounds(fapl.get(), H5F_LIBVER_LATEST,
                             H5F_LIBVER_LATEST) >= 0 &&
        H5Pset_obj_track_times(fcpl.get(), false) >= 0) {
      file = Handle(H5Fcreate(output.c_str(), H5F_ACC_EXCL, fcpl.get(),
                              fapl.get()),
                    H5Fclose);
    }
    if (file.valid()) {
      gcpl = Handle(H5Pcreate(H5P_GROUP_CREATE), H5Pclose);
    }
    if (gcpl.valid() && H5Pset_obj_track_times(gcpl.get(), false) >= 0) {
      group = Handle(H5Gcreate2(file.get(), "/weights", H5P_DEFAULT,
                                gcpl.get(), H5P_DEFAULT),
                     H5Gclose);
    }
    if (group.valid()) {
      space = Handle(H5Screate_simple(2, shape.data(), nullptr), H5Sclose);
      dcpl = Handle(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
    }
    if (dcpl.valid() && H5Pset_obj_track_times(dcpl.get(), false) >= 0 &&
        H5Pset_external(dcpl.get(), absolute_raw.c_str(), 0,
                        static_cast<hsize_t>(sizeof(values))) >= 0) {
      dataset = Handle(
          H5Dcreate2(file.get(), "/weights/kernel", H5T_IEEE_F32LE,
                     space.get(), H5P_DEFAULT, dcpl.get(), H5P_DEFAULT),
          H5Dclose);
    }
    if (!file.valid() || !group.valid() || !space.valid() || !dcpl.valid() ||
        !dataset.valid() ||
        !WriteNewIntAttribute(group.get(), "fixture_version", 1, error) ||
        !WriteNewIntAttribute(dataset.get(), "axis_count", 2, error) ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "external_storage_fixture_failed");
    } else {
      ok = CloseAll(error, {&dataset, &dcpl, &space, &group, &gcpl, &file,
                            &fcpl, &fapl});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
    RemoveCreatedOutput(raw_output);
  }
  return ok;
}

bool CreateFilteredFixture(const fs::path &output, std::string *error) {
  if (!IsFreshOutput(output, error)) {
    return false;
  }
  bool ok = false;
  {
    Handle fapl(H5Pcreate(H5P_FILE_ACCESS), H5Pclose);
    Handle fcpl(H5Pcreate(H5P_FILE_CREATE), H5Pclose);
    Handle file;
    Handle gcpl;
    Handle group;
    Handle space;
    Handle dcpl;
    Handle dataset;
    const std::array<hsize_t, 2> shape = {2, 3};
    const std::array<hsize_t, 2> chunks = {1, 3};
    const std::array<float, 6> values = {
        1.25F, -2.0F, 3.5F, 4.25F, -5.75F, 6.0F};
    if (fapl.valid() && fcpl.valid() &&
        H5Pset_libver_bounds(fapl.get(), H5F_LIBVER_LATEST,
                             H5F_LIBVER_LATEST) >= 0 &&
        H5Pset_obj_track_times(fcpl.get(), false) >= 0) {
      file = Handle(H5Fcreate(output.c_str(), H5F_ACC_EXCL, fcpl.get(),
                              fapl.get()),
                    H5Fclose);
    }
    if (file.valid()) {
      gcpl = Handle(H5Pcreate(H5P_GROUP_CREATE), H5Pclose);
    }
    if (gcpl.valid() && H5Pset_obj_track_times(gcpl.get(), false) >= 0) {
      group = Handle(H5Gcreate2(file.get(), "/weights", H5P_DEFAULT,
                                gcpl.get(), H5P_DEFAULT),
                     H5Gclose);
    }
    if (group.valid()) {
      space = Handle(H5Screate_simple(2, shape.data(), nullptr), H5Sclose);
      dcpl = Handle(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
    }
    if (dcpl.valid() && H5Pset_obj_track_times(dcpl.get(), false) >= 0 &&
        H5Pset_chunk(dcpl.get(), static_cast<int>(chunks.size()),
                     chunks.data()) >= 0 &&
        H5Pset_fletcher32(dcpl.get()) >= 0) {
      dataset = Handle(
          H5Dcreate2(file.get(), "/weights/kernel", H5T_IEEE_F32LE,
                     space.get(), H5P_DEFAULT, dcpl.get(), H5P_DEFAULT),
          H5Dclose);
    }
    if (!file.valid() || !group.valid() || !space.valid() || !dcpl.valid() ||
        !dataset.valid() ||
        H5Dwrite(dataset.get(), H5T_NATIVE_FLOAT, H5S_ALL, H5S_ALL,
                 H5P_DEFAULT, values.data()) < 0 ||
        !WriteNewIntAttribute(group.get(), "fixture_version", 1, error) ||
        !WriteNewIntAttribute(dataset.get(), "axis_count", 2, error) ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "filtered_fixture_failed");
    } else {
      ok = CloseAll(error, {&dataset, &dcpl, &space, &group, &gcpl, &file,
                            &fcpl, &fapl});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
  }
  return ok;
}

bool CreateExternalLinkFixture(const fs::path &input, const fs::path &output,
                               const fs::path &target,
                               std::string *error) {
  if (!CopyFresh(input, target, error) || !IsFreshOutput(output, error)) {
    RemoveCreatedOutput(target);
    return false;
  }
  std::error_code filesystem_error;
  const fs::path absolute_target = fs::absolute(target, filesystem_error);
  bool ok = false;
  {
    Handle fapl(H5Pcreate(H5P_FILE_ACCESS), H5Pclose);
    Handle fcpl(H5Pcreate(H5P_FILE_CREATE), H5Pclose);
    Handle file;
    Handle gcpl;
    Handle group;
    if (!filesystem_error && fapl.valid() && fcpl.valid() &&
        H5Pset_libver_bounds(fapl.get(), H5F_LIBVER_LATEST,
                             H5F_LIBVER_LATEST) >= 0 &&
        H5Pset_obj_track_times(fcpl.get(), false) >= 0) {
      file = Handle(H5Fcreate(output.c_str(), H5F_ACC_EXCL, fcpl.get(),
                              fapl.get()),
                    H5Fclose);
    }
    if (file.valid()) {
      gcpl = Handle(H5Pcreate(H5P_GROUP_CREATE), H5Pclose);
    }
    if (gcpl.valid() && H5Pset_obj_track_times(gcpl.get(), false) >= 0) {
      group = Handle(H5Gcreate2(file.get(), "/weights", H5P_DEFAULT,
                                gcpl.get(), H5P_DEFAULT),
                     H5Gclose);
    }
    if (!file.valid() || !group.valid() ||
        !WriteNewIntAttribute(group.get(), "fixture_version", 1, error) ||
        H5Lcreate_external(absolute_target.c_str(), "/weights/kernel",
                           group.get(), "kernel", H5P_DEFAULT, H5P_DEFAULT) <
            0 ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "external_link_fixture_failed");
    } else {
      ok = CloseAll(error, {&group, &gcpl, &file, &fcpl, &fapl});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
    RemoveCreatedOutput(target);
  }
  return ok;
}

bool CreateExternalGroupFixture(const fs::path &input, const fs::path &output,
                                const fs::path &target,
                                std::string *error) {
  if (!CopyFresh(input, target, error) || !IsFreshOutput(output, error)) {
    RemoveCreatedOutput(target);
    return false;
  }
  std::error_code filesystem_error;
  const fs::path absolute_target = fs::absolute(target, filesystem_error);
  bool ok = false;
  {
    Handle fapl(H5Pcreate(H5P_FILE_ACCESS), H5Pclose);
    Handle fcpl(H5Pcreate(H5P_FILE_CREATE), H5Pclose);
    Handle file;
    if (!filesystem_error && fapl.valid() && fcpl.valid() &&
        H5Pset_libver_bounds(fapl.get(), H5F_LIBVER_LATEST,
                             H5F_LIBVER_LATEST) >= 0 &&
        H5Pset_obj_track_times(fcpl.get(), false) >= 0) {
      file = Handle(H5Fcreate(output.c_str(), H5F_ACC_EXCL, fcpl.get(),
                              fapl.get()),
                    H5Fclose);
    }
    if (!file.valid() ||
        H5Lcreate_external(absolute_target.c_str(), "/weights", file.get(),
                           "/weights", H5P_DEFAULT, H5P_DEFAULT) < 0 ||
        H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0) {
      SetError(error, "external_group_fixture_failed");
    } else {
      ok = CloseAll(error, {&file, &fcpl, &fapl});
    }
  }
  if (!ok) {
    RemoveCreatedOutput(output);
    RemoveCreatedOutput(target);
  }
  return ok;
}

bool ParseInt32(const char *text, std::int32_t *value) {
  const std::string input(text);
  if (input.empty()) {
    return false;
  }
  std::int32_t parsed = 0;
  const auto result =
      std::from_chars(input.data(), input.data() + input.size(), parsed, 10);
  if (result.ec != std::errc{} || result.ptr != input.data() + input.size()) {
    return false;
  }
  *value = parsed;
  return true;
}

void PrintProbe(const Probe &probe) {
  std::cout << "HDF5_MUTATION_INSPECT_OK"
            << " group_hex=" << Hex(probe.group)
            << " dataset_hex=" << Hex(probe.dataset)
            << " dtype=" << probe.dtype << " shape=" << probe.shape[0] << 'x'
            << probe.shape[1] << " layout=" << probe.layout
            << " chunks=" << probe.chunks
            << " group_attr_name_hex=" << Hex(probe.group_attribute)
            << " group_attr_value=" << probe.group_attribute_value
            << " dataset_attr_name_hex=" << Hex(probe.dataset_attribute)
            << " dataset_attr_value=" << probe.dataset_attribute_value
            << " values=" << probe.values << '\n';
}

} // namespace

int main(int argc, char **argv) {
  std::string error;
  if (!ValidateRuntime(&error)) {
    std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
    return 1;
  }

  if (argc == 3 && std::string(argv[1]) == "inspect") {
    Probe probe;
    if (!Inspect(argv[2], &probe, &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    PrintProbe(probe);
    return 0;
  }

  if (argc == 4 && std::string(argv[1]) == "add-extra") {
    if (!AddExtraToCopy(argv[2], argv[3], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_MUTATION_TEST_TOOL_OK command=add-extra\n";
    return 0;
  }

  if (argc == 4 && std::string(argv[1]) == "add-root-attribute") {
    if (!AddRootAttributeToCopy(argv[2], argv[3], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout
        << "HDF5_MUTATION_TEST_TOOL_OK command=add-root-attribute\n";
    return 0;
  }

  if (argc == 4 && std::string(argv[1]) == "set-array-attribute") {
    if (!SetArrayAttributeOnCopy(argv[2], argv[3], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout
        << "HDF5_MUTATION_TEST_TOOL_OK command=set-array-attribute\n";
    return 0;
  }

  if (argc == 4 && std::string(argv[1]) == "set-large-payload") {
    if (!SetFirstPayloadOnCopy(argv[2], argv[3], 1.0e30F, &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_MUTATION_TEST_TOOL_OK command=set-large-payload\n";
    return 0;
  }

  if (argc == 4 && std::string(argv[1]) == "set-nonfinite-payload") {
    if (!SetFirstPayloadOnCopy(argv[2], argv[3],
                               std::numeric_limits<float>::quiet_NaN(),
                               &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout
        << "HDF5_MUTATION_TEST_TOOL_OK command=set-nonfinite-payload\n";
    return 0;
  }

  if (argc == 4 && std::string(argv[1]) == "make-external-storage") {
    if (!CreateExternalStorageFixture(argv[2], argv[3], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout
        << "HDF5_MUTATION_TEST_TOOL_OK command=make-external-storage\n";
    return 0;
  }

  if (argc == 3 && std::string(argv[1]) == "make-filtered") {
    if (!CreateFilteredFixture(argv[2], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_MUTATION_TEST_TOOL_OK command=make-filtered\n";
    return 0;
  }

  if (argc == 5 && std::string(argv[1]) == "make-external-link") {
    if (!CreateExternalLinkFixture(argv[2], argv[3], argv[4], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_MUTATION_TEST_TOOL_OK command=make-external-link\n";
    return 0;
  }

  if (argc == 5 && std::string(argv[1]) == "make-external-group") {
    if (!CreateExternalGroupFixture(argv[2], argv[3], argv[4], &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_MUTATION_TEST_TOOL_OK command=make-external-group\n";
    return 0;
  }

  if (argc == 6 && std::string(argv[1]) == "set-attributes") {
    std::int32_t group_value = 0;
    std::int32_t dataset_value = 0;
    if (!ParseInt32(argv[4], &group_value) ||
        !ParseInt32(argv[5], &dataset_value)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=invalid_int32\n";
      return 1;
    }
    if (!SetAttributesOnCopy(argv[2], argv[3], group_value, dataset_value,
                             &error)) {
      std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=" << error << '\n';
      return 1;
    }
    std::cout << "HDF5_MUTATION_TEST_TOOL_OK command=set-attributes\n";
    return 0;
  }

  std::cerr << "HDF5_MUTATION_TEST_TOOL_FAIL reason=usage\n";
  return 1;
}
