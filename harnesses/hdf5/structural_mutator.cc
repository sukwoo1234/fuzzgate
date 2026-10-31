#include <hdf5.h>
#include <hdf5_hl.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <locale>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;

constexpr std::uintmax_t kMaxInputBytes = 32U * 1024U * 1024U;
constexpr std::array<hsize_t, 2> kSourceShape = {2, 3};
constexpr std::array<float, 6> kSourceValues = {
    1.25F, -2.0F, 3.5F, 4.25F, -5.75F, 6.0F};

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

bool SetError(std::string *error, std::string message) {
  if (error->empty()) {
    *error = std::move(message);
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

struct Options {
  fs::path input;
  fs::path output;
  std::string operation;
  std::uint64_t seed = 0;
};

struct SourceData {
  std::array<float, 6> values{};
  std::int32_t group_attribute = 0;
  std::int32_t dataset_attribute = 0;
};

struct MutationPlan {
  std::string group_name = "/weights";
  std::string dataset_name = "kernel";
  std::string group_attribute_name = "fixture_version";
  std::string dataset_attribute_name = "axis_count";
  std::int32_t group_attribute = 1;
  std::int32_t dataset_attribute = 2;
  std::array<hsize_t, 2> shape = kSourceShape;
  std::array<float, 6> float_values = kSourceValues;
  std::array<std::int32_t, 6> integer_values{};
  bool integer_type = false;
  bool chunked = false;
  bool corrupt_object_header = false;
  std::string mutation_class = "structure_preserving";
  std::string field;
  std::string before;
  std::string after;
  std::string fixups;
  std::string expected_loader = "accept";
  std::string writer = "official-hdf5-2.2.0";
};

enum class ReadStatus { kOk, kInapplicable, kError };

std::optional<std::uint64_t> ParseUnsigned(const std::string &value) {
  if (value.empty() ||
      value.find_first_not_of("0123456789") != std::string::npos) {
    return std::nullopt;
  }
  try {
    std::size_t consumed = 0;
    const std::uint64_t parsed = std::stoull(value, &consumed, 10);
    if (consumed != value.size()) {
      return std::nullopt;
    }
    return parsed;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Options> ParseOptions(int argc, char **argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    if (index + 1 >= argc) {
      return std::nullopt;
    }
    const std::string flag(argv[index]);
    const std::string value(argv[++index]);
    if (flag == "--input") {
      options.input = value;
    } else if (flag == "--output") {
      options.output = value;
    } else if (flag == "--operator") {
      options.operation = value;
    } else if (flag == "--seed") {
      const auto seed = ParseUnsigned(value);
      if (!seed.has_value()) {
        return std::nullopt;
      }
      options.seed = *seed;
    } else {
      return std::nullopt;
    }
  }
  if (options.input.empty() || options.output.empty() ||
      options.operation.empty()) {
    return std::nullopt;
  }
  return options;
}

bool IsKnownOperator(std::string_view operation) {
  return operation == "object_names" || operation == "shape_dtype" ||
         operation == "payload" || operation == "chunk_layout" ||
         operation == "attributes" || operation == "raw_object_header";
}

bool ReadRegularFile(const fs::path &path, std::vector<unsigned char> *bytes,
                     std::string *error) {
  std::error_code filesystem_error;
  const fs::file_status status = fs::symlink_status(path, filesystem_error);
  if (filesystem_error || status.type() != fs::file_type::regular ||
      fs::is_symlink(status)) {
    return SetError(error, "input_not_regular");
  }
  const std::uintmax_t size = fs::file_size(path, filesystem_error);
  if (filesystem_error || size == 0 || size > kMaxInputBytes) {
    return SetError(error, size > kMaxInputBytes ? "input_exceeds_33554432_bytes"
                                                : "input_size_invalid");
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

bool ReadIntAttribute(hid_t object, const char *name, std::int32_t *value,
                      std::string *error) {
  if (H5Aexists(object, name) != 1) {
    return SetError(error, std::string("attribute_missing_") + name);
  }
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
      H5Aread(attribute.get(), H5T_NATIVE_INT32, value) < 0) {
    return SetError(error, std::string("attribute_invalid_") + name);
  }
  return CloseAll(error, {&space, &type, &attribute});
}

ReadStatus ReadSource(const std::vector<unsigned char> &bytes,
                      std::string_view operation, SourceData *source,
                      std::string *reason) {
  Handle file(H5LTopen_file_image(const_cast<unsigned char *>(bytes.data()),
                                  bytes.size(), 0),
              H5Fclose);
  if (!file.valid()) {
    SetError(reason, "file_image_rejected");
    return ReadStatus::kError;
  }
  const htri_t group_exists = H5Lexists(file.get(), "/weights", H5P_DEFAULT);
  if (group_exists < 0) {
    SetError(reason, "object_lookup_failed");
    return ReadStatus::kError;
  }
  if (group_exists == 0) {
    SetError(reason, "no_supported_dataset");
    return ReadStatus::kInapplicable;
  }
  H5L_info2_t group_link_info = {};
  if (H5Lget_info2(file.get(), "/weights", &group_link_info, H5P_DEFAULT) <
      0) {
    SetError(reason, "object_link_inspection_failed");
    return ReadStatus::kError;
  }
  if (group_link_info.type != H5L_TYPE_HARD) {
    SetError(reason, "object_link_not_hard");
    return ReadStatus::kInapplicable;
  }
  Handle group(H5Gopen2(file.get(), "/weights", H5P_DEFAULT), H5Gclose);
  if (!group.valid()) {
    SetError(reason, "unsupported_dataset_contract");
    return ReadStatus::kInapplicable;
  }
  const htri_t dataset_exists =
      H5Lexists(group.get(), "kernel", H5P_DEFAULT);
  if (dataset_exists < 0) {
    SetError(reason, "object_lookup_failed");
    return ReadStatus::kError;
  }
  if (dataset_exists == 0) {
    if (operation == "payload" &&
        H5Lexists(group.get(), "empty", H5P_DEFAULT) == 1) {
      SetError(reason, "payload_empty");
    } else if (operation == "attributes" &&
               H5Lexists(group.get(), "scalar", H5P_DEFAULT) == 1) {
      SetError(reason, "required_attributes_absent");
    } else {
      SetError(reason, "no_supported_dataset");
    }
    return ReadStatus::kInapplicable;
  }
  H5L_info2_t dataset_link_info = {};
  if (H5Lget_info2(group.get(), "kernel", &dataset_link_info, H5P_DEFAULT) <
      0) {
    SetError(reason, "object_link_inspection_failed");
    return ReadStatus::kError;
  }
  if (dataset_link_info.type != H5L_TYPE_HARD) {
    SetError(reason, "object_link_not_hard");
    return ReadStatus::kInapplicable;
  }
  Handle dataset(H5Dopen2(group.get(), "kernel", H5P_DEFAULT), H5Dclose);
  Handle root(H5Gopen2(file.get(), "/", H5P_DEFAULT), H5Gclose);
  if (!root.valid() || !group.valid() || !dataset.valid()) {
    SetError(reason, "unsupported_dataset_contract");
    return ReadStatus::kInapplicable;
  }
  H5G_info_t root_group_info = {};
  H5G_info_t weights_group_info = {};
  H5O_info2_t root_object_info = {};
  H5O_info2_t group_object_info = {};
  H5O_info2_t dataset_object_info = {};
  if (H5Gget_info(root.get(), &root_group_info) < 0 ||
      H5Gget_info(group.get(), &weights_group_info) < 0 ||
      H5Oget_info3(root.get(), &root_object_info, H5O_INFO_NUM_ATTRS) < 0 ||
      H5Oget_info3(group.get(), &group_object_info, H5O_INFO_NUM_ATTRS) < 0 ||
      H5Oget_info3(dataset.get(), &dataset_object_info, H5O_INFO_NUM_ATTRS) <
          0) {
    SetError(reason, "source_inventory_inspection_failed");
    return ReadStatus::kError;
  }
  if (root_group_info.nlinks != 1 || root_object_info.num_attrs != 0 ||
      weights_group_info.nlinks != 1 || group_object_info.num_attrs != 1 ||
      dataset_object_info.num_attrs != 1) {
    SetError(reason, "source_inventory_not_exact");
    return ReadStatus::kInapplicable;
  }
  Handle type;
  Handle space;
  Handle properties;
  if (dataset.valid()) {
    type = Handle(H5Dget_type(dataset.get()), H5Tclose);
    space = Handle(H5Dget_space(dataset.get()), H5Sclose);
    properties = Handle(H5Dget_create_plist(dataset.get()), H5Pclose);
  }
  std::array<hsize_t, 2> dimensions{};
  if (!type.valid() || !space.valid() || !properties.valid() ||
      H5Tequal(type.get(), H5T_IEEE_F32LE) != 1 ||
      H5Sget_simple_extent_ndims(space.get()) != 2 ||
      H5Sget_simple_extent_dims(space.get(), dimensions.data(), nullptr) < 0 ||
      dimensions != kSourceShape ||
      H5Pget_layout(properties.get()) != H5D_CONTIGUOUS) {
    SetError(reason, "unsupported_dataset_contract");
    return ReadStatus::kInapplicable;
  }
  const int external_count = H5Pget_external_count(properties.get());
  if (external_count < 0) {
    SetError(reason, "external_storage_count_unavailable");
    return ReadStatus::kError;
  }
  if (external_count != 0) {
    SetError(reason, "external_storage_unsupported");
    return ReadStatus::kInapplicable;
  }
  const int filter_count = H5Pget_nfilters(properties.get());
  if (filter_count < 0) {
    SetError(reason, "dataset_filter_count_unavailable");
    return ReadStatus::kError;
  }
  if (filter_count != 0) {
    SetError(reason, "dataset_filters_unsupported");
    return ReadStatus::kInapplicable;
  }
  if (H5Dread(dataset.get(), H5T_NATIVE_FLOAT, H5S_ALL, H5S_ALL,
              H5P_DEFAULT, source->values.data()) < 0) {
    SetError(reason, "dataset_read_failed");
    return ReadStatus::kError;
  }
  for (const float value : source->values) {
    if (!std::isfinite(value)) {
      SetError(reason, "nonfinite_payload_unsupported");
      return ReadStatus::kInapplicable;
    }
  }
  std::string attribute_error;
  if (!ReadIntAttribute(group.get(), "fixture_version",
                        &source->group_attribute, &attribute_error) ||
      !ReadIntAttribute(dataset.get(), "axis_count",
                        &source->dataset_attribute, &attribute_error)) {
    SetError(reason, attribute_error);
    return ReadStatus::kInapplicable;
  }
  if (!CloseAll(reason,
                {&properties, &space, &type, &dataset, &group, &root, &file})) {
    return ReadStatus::kError;
  }
  return ReadStatus::kOk;
}

std::string FloatValue(float value) {
  std::ostringstream output;
  output.imbue(std::locale::classic());
  output << std::setprecision(std::numeric_limits<float>::max_digits10) << value;
  std::string formatted = output.str();
  const std::size_t exponent_position = formatted.find_first_of("eE");
  if (exponent_position == std::string::npos) {
    return formatted;
  }
  const std::string mantissa = formatted.substr(0, exponent_position);
  std::string exponent = formatted.substr(exponent_position + 1U);
  bool negative = false;
  if (!exponent.empty() &&
      (exponent.front() == '+' || exponent.front() == '-')) {
    negative = exponent.front() == '-';
    exponent.erase(exponent.begin());
  }
  const std::size_t first_nonzero = exponent.find_first_not_of('0');
  if (first_nonzero == std::string::npos) {
    return mantissa;
  }
  exponent.erase(0, first_nonzero);
  return mantissa + "e" + (negative ? "-" : "") + exponent;
}

MutationPlan MakePlan(const Options &options, const SourceData &source) {
  MutationPlan plan;
  plan.float_values = source.values;
  plan.group_attribute = source.group_attribute;
  plan.dataset_attribute = source.dataset_attribute;
  const std::string suffix = "_m" + std::to_string(options.seed % 10007U);
  if (options.operation == "object_names") {
    plan.group_name += suffix;
    plan.dataset_name += suffix;
    plan.field = "object.group_dataset_names";
    plan.before = "group:/weights;dataset:kernel";
    plan.after = "group:" + plan.group_name + ";dataset:" + plan.dataset_name;
    plan.fixups =
        "official_writer_reserialize,rewrite_group_path,rewrite_dataset_path";
  } else if (options.operation == "shape_dtype") {
    plan.integer_type = true;
    plan.shape = {3, 2};
    const std::int32_t base =
        static_cast<std::int32_t>(1U + options.seed % 1000000U);
    for (std::size_t index = 0; index < plan.integer_values.size(); ++index) {
      const auto delta = static_cast<std::int32_t>(index);
      plan.integer_values[index] = (index % 2U == 0U) ? base + delta
                                                      : -(base + delta);
    }
    plan.field = "dataset.shape_dtype";
    plan.before = "dtype:float32-le;shape:2x3";
    plan.after = "dtype:int32-le;shape:3x2";
    plan.fixups =
        "official_writer_reserialize,recreate_dataspace,recreate_datatype,rewrite_payload";
  } else if (options.operation == "payload") {
    const std::size_t index =
        static_cast<std::size_t>(options.seed % plan.float_values.size());
    const float before = plan.float_values[index];
    const float direction = before == 0.0F ? 1.0F : 0.0F;
    plan.float_values[index] = std::nextafter(before, direction);
    plan.field = "dataset.payload";
    plan.before = "index:" + std::to_string(index) + ";value:" +
                  FloatValue(before);
    plan.after = "index:" + std::to_string(index) + ";value:" +
                 FloatValue(plan.float_values[index]);
    plan.fixups = "official_writer_reserialize,rewrite_numeric_payload";
  } else if (options.operation == "chunk_layout") {
    plan.chunked = true;
    plan.field = "dataset.chunk_layout";
    plan.before = "layout:contiguous;chunks:none";
    plan.after = "layout:chunked;chunks:1x3";
    plan.fixups =
        "official_writer_reserialize,recreate_dcpl,rewrite_chunk_index";
  } else if (options.operation == "attributes") {
    plan.group_attribute =
        static_cast<std::int32_t>(100U + options.seed % 1000000U);
    plan.dataset_attribute =
        static_cast<std::int32_t>(200U + options.seed % 1000000U);
    if (plan.group_attribute == source.group_attribute) {
      ++plan.group_attribute;
    }
    if (plan.dataset_attribute == source.dataset_attribute) {
      ++plan.dataset_attribute;
    }
    plan.field = "object.attributes";
    plan.before = "group:fixture_version:" +
                  std::to_string(source.group_attribute) +
                  ";dataset:axis_count:" +
                  std::to_string(source.dataset_attribute);
    plan.after = "group:" + plan.group_attribute_name + ":" +
                 std::to_string(plan.group_attribute) + ";dataset:" +
                 plan.dataset_attribute_name + ":" +
                 std::to_string(plan.dataset_attribute);
    plan.fixups =
        "official_writer_reserialize,recreate_group_attribute,recreate_dataset_attribute";
  } else {
    plan.corrupt_object_header = true;
    plan.mutation_class = "raw_corruption";
    plan.field = "dataset.object_header";
    plan.before = "signature:OHDR";
    plan.after = "signature:XHDR";
    plan.fixups =
        "official_writer_reserialize,intentional_raw_corruption";
    plan.expected_loader = "reject";
    plan.writer = "raw-byte-corruption";
  }
  return plan;
}

Handle CreateSpace(const std::array<hsize_t, 2> &shape) {
  return Handle(H5Screate_simple(static_cast<int>(shape.size()), shape.data(),
                                 nullptr),
                H5Sclose);
}

bool WriteIntAttribute(hid_t object, const std::string &name,
                       std::int32_t value, std::string *error) {
  Handle space(H5Screate(H5S_SCALAR), H5Sclose);
  Handle attribute;
  if (space.valid()) {
    attribute = Handle(
        H5Acreate2(object, name.c_str(), H5T_STD_I32LE, space.get(),
                   H5P_DEFAULT, H5P_DEFAULT),
        H5Aclose);
  }
  if (!space.valid() || !attribute.valid() ||
      H5Awrite(attribute.get(), H5T_NATIVE_INT32, &value) < 0) {
    return SetError(error, "attribute_write_failed_" + name);
  }
  return CloseAll(error, {&attribute, &space});
}

bool WriteImage(const fs::path &output, const MutationPlan &plan,
                haddr_t *object_header_address, bool *output_created,
                std::string *error) {
  *output_created = false;
  Handle fapl(H5Pcreate(H5P_FILE_ACCESS), H5Pclose);
  Handle fcpl(H5Pcreate(H5P_FILE_CREATE), H5Pclose);
  if (!fapl.valid() || !fcpl.valid() ||
      H5Pset_fapl_sec2(fapl.get()) < 0 ||
      H5Pset_libver_bounds(fapl.get(), H5F_LIBVER_LATEST,
                           H5F_LIBVER_LATEST) < 0 ||
      H5Pset_obj_track_times(fcpl.get(), false) < 0) {
    return SetError(error, "file_properties_failed");
  }
  Handle file(H5Fcreate(output.c_str(), H5F_ACC_EXCL, fcpl.get(), fapl.get()),
              H5Fclose);
  if (!file.valid()) {
    return SetError(error, "output_create_failed");
  }
  *output_created = true;
  Handle gcpl(H5Pcreate(H5P_GROUP_CREATE), H5Pclose);
  if (!gcpl.valid() || H5Pset_obj_track_times(gcpl.get(), false) < 0) {
    return SetError(error, "group_properties_failed");
  }
  Handle group(H5Gcreate2(file.get(), plan.group_name.c_str(), H5P_DEFAULT,
                          gcpl.get(), H5P_DEFAULT),
               H5Gclose);
  if (!group.valid()) {
    return SetError(error, "group_create_failed");
  }
  Handle space = CreateSpace(plan.shape);
  Handle dcpl(H5Pcreate(H5P_DATASET_CREATE), H5Pclose);
  if (!space.valid() || !dcpl.valid() ||
      H5Pset_obj_track_times(dcpl.get(), false) < 0) {
    return SetError(error, "dataset_properties_failed");
  }
  const std::array<hsize_t, 2> chunks = {1, 3};
  if (plan.chunked &&
      H5Pset_chunk(dcpl.get(), static_cast<int>(chunks.size()), chunks.data()) <
          0) {
    return SetError(error, "chunk_properties_failed");
  }
  const hid_t file_type =
      plan.integer_type ? H5T_STD_I32LE : H5T_IEEE_F32LE;
  const hid_t memory_type =
      plan.integer_type ? H5T_NATIVE_INT32 : H5T_NATIVE_FLOAT;
  const std::string dataset_path = plan.group_name + "/" + plan.dataset_name;
  Handle dataset(H5Dcreate2(file.get(), dataset_path.c_str(), file_type,
                            space.get(), H5P_DEFAULT, dcpl.get(), H5P_DEFAULT),
                 H5Dclose);
  const void *values = plan.integer_type
                           ? static_cast<const void *>(plan.integer_values.data())
                           : static_cast<const void *>(plan.float_values.data());
  if (!dataset.valid() ||
      H5Dwrite(dataset.get(), memory_type, H5S_ALL, H5S_ALL, H5P_DEFAULT,
               values) < 0 ||
      !WriteIntAttribute(group.get(), plan.group_attribute_name,
                         plan.group_attribute, error) ||
      !WriteIntAttribute(dataset.get(), plan.dataset_attribute_name,
                         plan.dataset_attribute, error)) {
    return SetError(error, "dataset_or_attribute_write_failed");
  }
  H5O_info1_t object_info = {};
  if (H5Oget_info2(dataset.get(), &object_info, H5O_INFO_BASIC) < 0 ||
      object_info.addr == HADDR_UNDEF || object_info.addr == 0) {
    return SetError(error, "object_header_address_unavailable");
  }
  *object_header_address = object_info.addr;
  if (H5Fflush(file.get(), H5F_SCOPE_GLOBAL) < 0 ||
      !CloseAll(error, {&dataset, &dcpl, &space, &group, &gcpl, &file,
                        &fcpl, &fapl})) {
    return SetError(error, "output_flush_or_close_failed");
  }
  return true;
}

bool VerifyAttribute(hid_t object, const std::string &name,
                     std::int32_t expected, std::string *error) {
  std::int32_t actual = 0;
  return ReadIntAttribute(object, name.c_str(), &actual, error) &&
         (actual == expected ||
          SetError(error, "attribute_value_mismatch_" + name));
}

bool VerifyImage(const fs::path &output, const MutationPlan &plan,
                 std::string *error) {
  std::vector<unsigned char> bytes;
  if (!ReadRegularFile(output, &bytes, error)) {
    return false;
  }
  Handle file(H5LTopen_file_image(bytes.data(), bytes.size(), 0), H5Fclose);
  const std::string dataset_path = plan.group_name + "/" + plan.dataset_name;
  Handle group;
  Handle dataset;
  if (file.valid()) {
    group = Handle(H5Gopen2(file.get(), plan.group_name.c_str(), H5P_DEFAULT),
                   H5Gclose);
    dataset = Handle(
        H5Dopen2(file.get(), dataset_path.c_str(), H5P_DEFAULT), H5Dclose);
  }
  Handle type;
  Handle space;
  Handle properties;
  if (dataset.valid()) {
    type = Handle(H5Dget_type(dataset.get()), H5Tclose);
    space = Handle(H5Dget_space(dataset.get()), H5Sclose);
    properties = Handle(H5Dget_create_plist(dataset.get()), H5Pclose);
  }
  std::array<hsize_t, 2> dimensions{};
  const hid_t expected_type =
      plan.integer_type ? H5T_STD_I32LE : H5T_IEEE_F32LE;
  const H5D_layout_t expected_layout =
      plan.chunked ? H5D_CHUNKED : H5D_CONTIGUOUS;
  if (!file.valid() || !group.valid() || !dataset.valid() || !type.valid() ||
      !space.valid() || !properties.valid() ||
      H5Tequal(type.get(), expected_type) != 1 ||
      H5Sget_simple_extent_ndims(space.get()) != 2 ||
      H5Sget_simple_extent_dims(space.get(), dimensions.data(), nullptr) < 0 ||
      dimensions != plan.shape ||
      H5Pget_layout(properties.get()) != expected_layout) {
    return SetError(error, "output_structure_mismatch");
  }
  if (plan.chunked) {
    std::array<hsize_t, 2> chunks{};
    if (H5Pget_chunk(properties.get(), static_cast<int>(chunks.size()),
                     chunks.data()) != static_cast<int>(chunks.size()) ||
        chunks != std::array<hsize_t, 2>{1, 3}) {
      return SetError(error, "output_chunk_layout_mismatch");
    }
  }
  if (plan.integer_type) {
    std::array<std::int32_t, 6> values{};
    if (H5Dread(dataset.get(), H5T_NATIVE_INT32, H5S_ALL, H5S_ALL,
                H5P_DEFAULT, values.data()) < 0 ||
        values != plan.integer_values) {
      return SetError(error, "output_integer_payload_mismatch");
    }
  } else {
    std::array<float, 6> values{};
    if (H5Dread(dataset.get(), H5T_NATIVE_FLOAT, H5S_ALL, H5S_ALL,
                H5P_DEFAULT, values.data()) < 0 ||
        values != plan.float_values) {
      return SetError(error, "output_float_payload_mismatch");
    }
  }
  if (!VerifyAttribute(group.get(), plan.group_attribute_name,
                       plan.group_attribute, error) ||
      !VerifyAttribute(dataset.get(), plan.dataset_attribute_name,
                       plan.dataset_attribute, error)) {
    return false;
  }
  return CloseAll(error,
                  {&properties, &space, &type, &dataset, &group, &file});
}

bool CorruptObjectHeader(const fs::path &output, haddr_t address,
                         std::string *error) {
  if (address >
      static_cast<haddr_t>(std::numeric_limits<std::streamoff>::max())) {
    return SetError(error, "object_header_address_not_representable");
  }
  std::fstream stream(output, std::ios::in | std::ios::out | std::ios::binary);
  const auto offset = static_cast<std::streamoff>(address);
  std::array<char, 4> signature{};
  stream.seekg(offset, std::ios::beg);
  stream.read(signature.data(), static_cast<std::streamsize>(signature.size()));
  if (!stream || signature != std::array<char, 4>{'O', 'H', 'D', 'R'}) {
    return SetError(error, "object_header_signature_unavailable");
  }
  signature[0] = 'X';
  stream.seekp(offset, std::ios::beg);
  stream.write(signature.data(), static_cast<std::streamsize>(signature.size()));
  stream.flush();
  if (!stream) {
    return SetError(error, "object_header_corruption_failed");
  }
  stream.close();
  if (!stream) {
    return SetError(error, "corrupt_output_close_failed");
  }
  return true;
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

void RemoveOutput(const fs::path &output) {
  std::error_code error;
  static_cast<void>(fs::remove(output, error));
}

} // namespace

int main(int argc, char **argv) {
  const auto options = ParseOptions(argc, argv);
  if (!options.has_value()) {
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=usage\n";
    return 1;
  }
  if (!IsKnownOperator(options->operation)) {
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=unknown_operator\n";
    return 1;
  }
  std::error_code filesystem_error;
  const fs::file_status output_status =
      fs::symlink_status(options->output, filesystem_error);
  if ((!filesystem_error && output_status.type() != fs::file_type::not_found) ||
      (filesystem_error && filesystem_error != std::errc::no_such_file_or_directory)) {
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=output_not_fresh\n";
    return 1;
  }

  std::string error;
  if (!ValidateRuntime(&error)) {
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=" << error << '\n';
    return 1;
  }
  std::vector<unsigned char> input;
  if (!ReadRegularFile(options->input, &input, &error)) {
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=" << error << '\n';
    return 1;
  }
  SourceData source;
  const ReadStatus read_status =
      ReadSource(input, options->operation, &source, &error);
  if (read_status == ReadStatus::kInapplicable) {
    std::cerr << "HDF5_NATIVE_MUTATION_INAPPLICABLE operator="
              << options->operation << " reason=" << error << '\n';
    return 3;
  }
  if (read_status == ReadStatus::kError) {
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=" << error << '\n';
    return 1;
  }

  const MutationPlan plan = MakePlan(*options, source);
  haddr_t object_header_address = HADDR_UNDEF;
  bool output_created = false;
  if (!WriteImage(options->output, plan, &object_header_address,
                  &output_created, &error)) {
    if (output_created) {
      RemoveOutput(options->output);
    }
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=" << error << '\n';
    return 1;
  }
  if (plan.corrupt_object_header) {
    if (!CorruptObjectHeader(options->output, object_header_address, &error)) {
      if (output_created) {
        RemoveOutput(options->output);
      }
      std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=" << error << '\n';
      return 1;
    }
  } else if (!VerifyImage(options->output, plan, &error)) {
    if (output_created) {
      RemoveOutput(options->output);
    }
    std::cerr << "HDF5_NATIVE_MUTATION_FAIL reason=" << error << '\n';
    return 1;
  }

  std::cout << "HDF5_NATIVE_MUTATION_OK"
            << " operator=" << options->operation
            << " mutation_class=" << plan.mutation_class
            << " field=" << plan.field << " before=" << plan.before
            << " after=" << plan.after << " fixups=" << plan.fixups
            << " expected_loader=" << plan.expected_loader
            << " writer=" << plan.writer << '\n';
  return 0;
}
