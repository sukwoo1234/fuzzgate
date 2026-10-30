#include "loader.h"

#include <hdf5.h>
#include <hdf5_hl.h>

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace tool::hdf5_loader {
namespace {

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

LoadResult Result(Classification classification, std::string stage,
                  std::string reason) {
  LoadResult result;
  result.classification = classification;
  result.stage = std::move(stage);
  result.reason = std::move(reason);
  return result;
}

std::string JoinPath(const std::string &parent, const std::string &name) {
  return parent == "/" ? "/" + name : parent + "/" + name;
}

std::string OrderName(H5T_order_t order) {
  switch (order) {
  case H5T_ORDER_LE:
    return "le";
  case H5T_ORDER_BE:
    return "be";
  case H5T_ORDER_NONE:
    return "none";
  case H5T_ORDER_VAX:
    return "vax";
  case H5T_ORDER_MIXED:
    return "mixed";
  case H5T_ORDER_ERROR:
    break;
  }
  return "error";
}

class Loader {
public:
  Loader(const std::uint8_t *data, std::size_t size, const Limits &limits)
      : data_(data), size_(size), limits_(limits) {}

  LoadResult Run() {
    if (data_ == nullptr || size_ == 0) {
      return Result(Classification::kTargetReject, "input", "empty_input");
    }
    if (size_ > limits_.max_input_bytes) {
      return Result(Classification::kPolicyLimit, "input_size",
                    "input_exceeds_limit");
    }
    if (limits_.max_input_bytes == 0 ||
        limits_.max_input_bytes > kMaxInputBytes ||
        limits_.max_datasets > kMaxDatasets || limits_.max_rank > kMaxRank ||
        limits_.max_read_bytes > kMaxReadBytes) {
      return Result(Classification::kEnvironmentError, "loader_config",
                    "invalid_limits");
    }

    unsigned major = 0;
    unsigned minor = 0;
    unsigned release = 0;
    if (H5get_libversion(&major, &minor, &release) < 0 || major != 2U ||
        minor != 2U || release != 0U) {
      return Result(Classification::kEnvironmentError, "library_identity",
                    "runtime_is_not_hdf5_2_2_0");
    }

    file_ =
        Handle(H5LTopen_file_image(const_cast<std::uint8_t *>(data_), size_, 0),
               H5Fclose);
    if (!file_.valid()) {
      return Result(Classification::kTargetReject, "file_image_open",
                    "H5LTopen_file_image_rejected_input");
    }

    group_queue_.push_back("/");
    while (!group_queue_.empty()) {
      std::string path = std::move(group_queue_.back());
      group_queue_.pop_back();
      if (!VisitGroup(path)) {
        return std::move(failure_);
      }
    }
    if (summary_.datasets == 0) {
      return Result(Classification::kTargetReject, "dataset_lookup",
                    "required_dataset_absent");
    }

    LoadResult accepted =
        Result(Classification::kAccepted, "complete", "loaded");
    accepted.summary = std::move(summary_);
    return accepted;
  }

private:
  bool Fail(Classification classification, std::string stage,
            std::string reason) {
    failure_ = Result(classification, std::move(stage), std::move(reason));
    return false;
  }

  bool MarkObject(const H5O_token_t &token, bool *is_new) {
    for (const H5O_token_t &seen : tokens_) {
      int comparison = 0;
      if (H5Otoken_cmp(file_.get(), &seen, &token, &comparison) < 0) {
        return Fail(Classification::kTargetReject, "object_identity",
                    "H5Otoken_cmp_failed");
      }
      if (comparison == 0) {
        *is_new = false;
        return true;
      }
    }
    tokens_.push_back(token);
    summary_.visited_objects = tokens_.size();
    *is_new = true;
    return true;
  }

  bool NumericType(hid_t type, std::string *name) {
    const htri_t contains_vlen = H5Tdetect_class(type, H5T_VLEN);
    const htri_t contains_reference = H5Tdetect_class(type, H5T_REFERENCE);
    if (contains_vlen < 0 || contains_reference < 0) {
      return Fail(Classification::kTargetReject, "dtype_inspect",
                  "H5Tdetect_class_failed");
    }
    if (contains_vlen > 0) {
      return Fail(Classification::kUnsupportedFeature, "dtype_policy",
                  "variable_length_dtype");
    }
    if (contains_reference > 0) {
      return Fail(Classification::kUnsupportedFeature, "dtype_policy",
                  "reference_dtype");
    }

    const H5T_class_t type_class = H5Tget_class(type);
    if (type_class != H5T_INTEGER && type_class != H5T_FLOAT) {
      return Fail(Classification::kUnsupportedFeature, "dtype_policy",
                  "non_numeric_dtype");
    }
    const size_t precision = H5Tget_precision(type);
    const H5T_order_t order = H5Tget_order(type);
    if (precision == 0 || order == H5T_ORDER_ERROR) {
      return Fail(Classification::kTargetReject, "dtype_inspect",
                  "numeric_dtype_metadata_invalid");
    }
    if (type_class == H5T_FLOAT) {
      *name = "float" + std::to_string(precision) + "-" + OrderName(order);
      return true;
    }
    const H5T_sign_t sign = H5Tget_sign(type);
    if (sign == H5T_SGN_ERROR) {
      return Fail(Classification::kTargetReject, "dtype_inspect",
                  "integer_sign_invalid");
    }
    *name = (sign == H5T_SGN_NONE ? "uint" : "int") +
            std::to_string(precision) + "-" + OrderName(order);
    return true;
  }

  bool InspectSpace(hid_t space, std::vector<std::uint64_t> *shape,
                    std::uint64_t *elements) {
    const H5S_class_t space_class = H5Sget_simple_extent_type(space);
    if (space_class == H5S_NO_CLASS) {
      return Fail(Classification::kTargetReject, "dataspace_inspect",
                  "dataspace_class_invalid");
    }
    if (space_class == H5S_NULL) {
      *elements = 0;
      return true;
    }
    if (space_class != H5S_SCALAR && space_class != H5S_SIMPLE) {
      return Fail(Classification::kUnsupportedFeature, "dataspace_policy",
                  "unsupported_dataspace_class");
    }
    const int rank = H5Sget_simple_extent_ndims(space);
    if (rank < 0) {
      return Fail(Classification::kTargetReject, "dataspace_inspect",
                  "rank_unavailable");
    }
    if (static_cast<std::size_t>(rank) > limits_.max_rank) {
      return Fail(Classification::kPolicyLimit, "rank", "rank_exceeds_limit");
    }
    std::vector<hsize_t> dimensions(static_cast<std::size_t>(rank));
    if (rank > 0 &&
        H5Sget_simple_extent_dims(space, dimensions.data(), nullptr) < 0) {
      return Fail(Classification::kTargetReject, "dataspace_inspect",
                  "dimensions_unavailable");
    }
    shape->reserve(dimensions.size());
    for (hsize_t dimension : dimensions) {
      shape->push_back(static_cast<std::uint64_t>(dimension));
    }
    const hssize_t points = H5Sget_simple_extent_npoints(space);
    if (points < 0) {
      return Fail(Classification::kTargetReject, "dataspace_inspect",
                  "element_count_unavailable");
    }
    *elements = static_cast<std::uint64_t>(points);
    return true;
  }

  bool ReserveRead(std::size_t bytes) {
    if (bytes > limits_.max_read_bytes - summary_.read_bytes) {
      return Fail(Classification::kPolicyLimit, "read_budget",
                  "total_read_exceeds_limit");
    }
    summary_.read_bytes += bytes;
    return true;
  }

  bool VisitAttributes(hid_t object, const std::string &object_path) {
    H5O_info2_t object_info = {};
    if (H5Oget_info3(object, &object_info, H5O_INFO_NUM_ATTRS) < 0) {
      return Fail(Classification::kTargetReject, "attribute_inspect",
                  "attribute_count_unavailable");
    }
    for (hsize_t index = 0; index < object_info.num_attrs; ++index) {
      Handle attribute(H5Aopen_by_idx(object, ".", H5_INDEX_NAME, H5_ITER_INC,
                                      index, H5P_DEFAULT, H5P_DEFAULT),
                       H5Aclose);
      if (!attribute.valid()) {
        return Fail(Classification::kTargetReject, "attribute_open",
                    "H5Aopen_by_idx_failed");
      }
      const ssize_t name_size = H5Aget_name(attribute.get(), 0, nullptr);
      if (name_size < 0) {
        return Fail(Classification::kTargetReject, "attribute_inspect",
                    "attribute_name_unavailable");
      }
      std::vector<char> name_buffer(static_cast<std::size_t>(name_size) + 1U);
      if (H5Aget_name(attribute.get(), name_buffer.size(),
                      name_buffer.data()) != name_size) {
        return Fail(Classification::kTargetReject, "attribute_inspect",
                    "attribute_name_changed");
      }

      Handle type(H5Aget_type(attribute.get()), H5Tclose);
      Handle space(H5Aget_space(attribute.get()), H5Sclose);
      if (!type.valid() || !space.valid()) {
        return Fail(Classification::kTargetReject, "attribute_inspect",
                    "attribute_type_or_space_unavailable");
      }
      AttributeObservation observation;
      observation.object_path = object_path;
      observation.name.assign(name_buffer.data(),
                              static_cast<std::size_t>(name_size));
      if (!NumericType(type.get(), &observation.dtype) ||
          !InspectSpace(space.get(), &observation.shape,
                        &observation.elements)) {
        return false;
      }
      if (observation.elements >
          static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() /
                                     sizeof(double))) {
        return Fail(Classification::kPolicyLimit, "read_budget",
                    "attribute_size_not_representable");
      }
      const std::size_t value_count =
          static_cast<std::size_t>(observation.elements);
      const std::size_t bytes = value_count * sizeof(double);
      if (!ReserveRead(bytes)) {
        return false;
      }
      std::vector<double> values(value_count,
                                 std::numeric_limits<double>::quiet_NaN());
      double empty_value = 0.0;
      void *buffer = values.empty() ? static_cast<void *>(&empty_value)
                                    : static_cast<void *>(values.data());
      if (H5Aread(attribute.get(), H5T_NATIVE_DOUBLE, buffer) < 0) {
        return Fail(Classification::kTargetReject, "attribute_read",
                    "H5Aread_failed");
      }
      observation.values = std::move(values);
      summary_.attribute_observations.push_back(std::move(observation));
      ++summary_.attributes;
    }
    return true;
  }

  bool InspectDataset(hid_t group, const std::string &name,
                      const std::string &path) {
    if (summary_.datasets >= limits_.max_datasets) {
      return Fail(Classification::kPolicyLimit, "dataset_count",
                  "dataset_count_exceeds_limit");
    }
    ++summary_.datasets;

    Handle dataset(H5Dopen2(group, name.c_str(), H5P_DEFAULT), H5Dclose);
    if (!dataset.valid()) {
      return Fail(Classification::kTargetReject, "dataset_open",
                  "H5Dopen2_failed");
    }
    Handle properties(H5Dget_create_plist(dataset.get()), H5Pclose);
    Handle type(H5Dget_type(dataset.get()), H5Tclose);
    Handle file_space(H5Dget_space(dataset.get()), H5Sclose);
    if (!properties.valid() || !type.valid() || !file_space.valid()) {
      return Fail(Classification::kTargetReject, "dataset_inspect",
                  "dataset_properties_type_or_space_unavailable");
    }

    const int external_count = H5Pget_external_count(properties.get());
    if (external_count < 0) {
      return Fail(Classification::kTargetReject, "storage_inspect",
                  "external_storage_count_unavailable");
    }
    if (external_count > 0) {
      return Fail(Classification::kUnsupportedFeature, "storage_policy",
                  "external_storage");
    }
    const H5D_layout_t layout = H5Pget_layout(properties.get());
    if (layout == H5D_LAYOUT_ERROR) {
      return Fail(Classification::kTargetReject, "layout_inspect",
                  "dataset_layout_unavailable");
    }
    if (layout == H5D_VIRTUAL) {
      return Fail(Classification::kUnsupportedFeature, "layout_policy",
                  "virtual_dataset");
    }
    const int filter_count = H5Pget_nfilters(properties.get());
    if (filter_count < 0) {
      return Fail(Classification::kTargetReject, "filter_inspect",
                  "filter_count_unavailable");
    }
    for (int index = 0; index < filter_count; ++index) {
      unsigned flags = 0;
      std::size_t client_count = 0;
      unsigned filter_config = 0;
      const H5Z_filter_t filter =
          H5Pget_filter2(properties.get(), static_cast<unsigned>(index), &flags,
                         &client_count, nullptr, 0, nullptr, &filter_config);
      if (filter == H5Z_FILTER_ERROR) {
        return Fail(Classification::kTargetReject, "filter_inspect",
                    "filter_metadata_unavailable");
      }
      const htri_t available = H5Zfilter_avail(filter);
      if (available < 0) {
        return Fail(Classification::kTargetReject, "filter_inspect",
                    "filter_availability_unavailable");
      }
      if (available == 0 || H5Zget_filter_info(filter, &filter_config) < 0 ||
          (filter_config & H5Z_FILTER_CONFIG_DECODE_ENABLED) == 0U) {
        return Fail(Classification::kUnsupportedFeature, "filter_policy",
                    "filter_unavailable_for_decode");
      }
    }

    DatasetObservation observation;
    observation.path = path;
    if (!NumericType(type.get(), &observation.dtype) ||
        !InspectSpace(file_space.get(), &observation.shape,
                      &observation.elements)) {
      return false;
    }
    observation.state =
        observation.elements == 0 ? "present_empty" : "present_nonempty";
    const std::size_t sample_limit = kMaxDatasetReadBytes / sizeof(double);
    const std::uint64_t sample_elements_u64 =
        std::min<std::uint64_t>(observation.elements, sample_limit);
    observation.read_elements = static_cast<std::size_t>(sample_elements_u64);

    Handle memory_space;
    if (observation.elements == 0) {
      if (H5Sselect_none(file_space.get()) < 0) {
        return Fail(Classification::kTargetReject, "hyperslab_select",
                    "empty_file_selection_failed");
      }
      memory_space = Handle(H5Screate(H5S_NULL), H5Sclose);
    } else if (observation.shape.empty()) {
      memory_space = Handle(H5Screate(H5S_SCALAR), H5Sclose);
    } else {
      std::vector<hsize_t> start(observation.shape.size(), 0);
      std::vector<hsize_t> count(observation.shape.size(), 1);
      std::size_t product = 1;
      std::size_t remaining = observation.read_elements;
      for (std::size_t offset = observation.shape.size(); offset > 0;
           --offset) {
        const std::size_t index = offset - 1;
        const auto dimension = static_cast<hsize_t>(observation.shape[index]);
        count[index] =
            std::min<hsize_t>(dimension, static_cast<hsize_t>(remaining));
        product *= static_cast<std::size_t>(count[index]);
        remaining /= static_cast<std::size_t>(count[index]);
      }
      observation.read_elements = product;
      if (H5Sselect_hyperslab(file_space.get(), H5S_SELECT_SET, start.data(),
                              nullptr, count.data(), nullptr) < 0) {
        return Fail(Classification::kTargetReject, "hyperslab_select",
                    "bounded_hyperslab_selection_failed");
      }
      memory_space = Handle(H5Screate_simple(static_cast<int>(count.size()),
                                             count.data(), nullptr),
                            H5Sclose);
    }
    if (!memory_space.valid()) {
      return Fail(Classification::kTargetReject, "hyperslab_select",
                  "memory_dataspace_creation_failed");
    }
    const std::size_t read_bytes = observation.read_elements * sizeof(double);
    if (!ReserveRead(read_bytes)) {
      return false;
    }

    std::vector<double> values(observation.read_elements,
                               std::numeric_limits<double>::quiet_NaN());
    double empty_value = 0.0;
    void *buffer = values.empty() ? static_cast<void *>(&empty_value)
                                  : static_cast<void *>(values.data());
    const herr_t read_status =
        H5Dread(dataset.get(), H5T_NATIVE_DOUBLE, memory_space.get(),
                file_space.get(), H5P_DEFAULT, buffer);
    if (read_status < 0) {
      return Fail(Classification::kTargetReject, "dataset_read",
                  "H5Dread_failed");
    }
    observation.values = std::move(values);
    ++summary_.h5dread_calls;
    summary_.dataset_observations.push_back(std::move(observation));
    return VisitAttributes(dataset.get(), path);
  }

  bool VisitGroup(const std::string &path) {
    Handle group(H5Gopen2(file_.get(), path.c_str(), H5P_DEFAULT), H5Gclose);
    if (!group.valid()) {
      return Fail(Classification::kTargetReject, "group_open",
                  "H5Gopen2_failed");
    }
    H5O_info2_t group_object = {};
    if (H5Oget_info3(group.get(), &group_object, H5O_INFO_BASIC) < 0) {
      return Fail(Classification::kTargetReject, "object_lookup",
                  "group_identity_unavailable");
    }
    bool is_new = false;
    if (!MarkObject(group_object.token, &is_new) || !is_new) {
      return failure_.stage.empty();
    }
    ++summary_.groups;
    if (!VisitAttributes(group.get(), path)) {
      return false;
    }

    H5G_info_t group_info = {};
    if (H5Gget_info(group.get(), &group_info) < 0) {
      return Fail(Classification::kTargetReject, "group_iterate",
                  "group_link_count_unavailable");
    }
    for (hsize_t index = 0; index < group_info.nlinks; ++index) {
      const ssize_t name_size =
          H5Lget_name_by_idx(group.get(), ".", H5_INDEX_NAME, H5_ITER_INC,
                             index, nullptr, 0, H5P_DEFAULT);
      if (name_size < 0) {
        return Fail(Classification::kTargetReject, "group_iterate",
                    "link_name_unavailable");
      }
      std::vector<char> name_buffer(static_cast<std::size_t>(name_size) + 1U);
      if (H5Lget_name_by_idx(group.get(), ".", H5_INDEX_NAME, H5_ITER_INC,
                             index, name_buffer.data(), name_buffer.size(),
                             H5P_DEFAULT) != name_size) {
        return Fail(Classification::kTargetReject, "group_iterate",
                    "link_name_changed");
      }
      const std::string name(name_buffer.data(),
                             static_cast<std::size_t>(name_size));
      H5L_info2_t link_info = {};
      if (H5Lget_info2(group.get(), name.c_str(), &link_info, H5P_DEFAULT) <
          0) {
        return Fail(Classification::kTargetReject, "link_inspect",
                    "H5Lget_info2_failed");
      }
      if (link_info.type != H5L_TYPE_HARD) {
        return Fail(Classification::kUnsupportedFeature, "link_policy",
                    link_info.type == H5L_TYPE_EXTERNAL ? "external_link"
                                                        : "non_hard_link");
      }

      H5O_info2_t object_info = {};
      if (H5Oget_info_by_name3(group.get(), name.c_str(), &object_info,
                               H5O_INFO_BASIC, H5P_DEFAULT) < 0) {
        return Fail(Classification::kTargetReject, "object_lookup",
                    "hard_link_target_unavailable");
      }
      const std::string child_path = JoinPath(path, name);
      if (object_info.type == H5O_TYPE_GROUP) {
        group_queue_.push_back(child_path);
        continue;
      }
      bool object_is_new = false;
      if (!MarkObject(object_info.token, &object_is_new)) {
        return false;
      }
      if (!object_is_new) {
        continue;
      }
      if (object_info.type == H5O_TYPE_DATASET) {
        if (!InspectDataset(group.get(), name, child_path)) {
          return false;
        }
        continue;
      }
      return Fail(Classification::kUnsupportedFeature, "object_policy",
                  object_info.type == H5O_TYPE_NAMED_DATATYPE
                      ? "named_datatype"
                      : "unsupported_object_type");
    }
    return true;
  }

  const std::uint8_t *data_;
  std::size_t size_;
  Limits limits_;
  Handle file_;
  LoadSummary summary_;
  LoadResult failure_;
  std::vector<H5O_token_t> tokens_;
  std::vector<std::string> group_queue_;
};

} // namespace

const char *ClassificationName(Classification classification) {
  switch (classification) {
  case Classification::kAccepted:
    return "accepted";
  case Classification::kTargetReject:
    return "target_reject";
  case Classification::kPolicyLimit:
    return "policy_limit";
  case Classification::kUnsupportedFeature:
    return "unsupported_feature";
  case Classification::kEnvironmentError:
    return "environment_error";
  }
  return "environment_error";
}

int ExitCode(Classification classification) {
  switch (classification) {
  case Classification::kAccepted:
    return 0;
  case Classification::kTargetReject:
  case Classification::kPolicyLimit:
  case Classification::kUnsupportedFeature:
    return 9;
  case Classification::kEnvironmentError:
    return 10;
  }
  return 10;
}

LoadResult LoadImage(const std::uint8_t *data, std::size_t size,
                     const Limits &limits) {
  Loader loader(data, size, limits);
  return loader.Run();
}

} // namespace tool::hdf5_loader
