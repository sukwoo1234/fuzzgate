#include "loader.h"

#include "harnesses/common/model_bundle.h"

#include <openvino/openvino.hpp>
#include <openvino/op/constant.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tool::openvino_loader {

namespace {

int Reject(std::string_view stage, std::string message, std::string* error) {
  *error = std::string(stage) + ": " + std::move(message);
  return 9;
}

std::string PortDescription(const ov::element::Type& type,
                            const ov::PartialShape& shape) {
  std::ostringstream output;
  output << type.get_type_name() << ':' << shape;
  return output.str();
}

}  // namespace

int LoadBundle(const std::uint8_t* data, std::size_t size,
               LoadSummary* summary, std::string* error) {
  if (summary == nullptr || error == nullptr) {
    return 10;
  }
  *summary = {};
  error->clear();

  std::vector<model_bundle::EntryView> entries;
  const std::vector<std::string_view> allowlist = {"model.bin", "model.xml"};
  std::string bundle_error;
  if (!model_bundle::DecodeWithAllowlist(data, size, allowlist, &entries,
                                          &bundle_error)) {
    return Reject("bundle", std::move(bundle_error), error);
  }

  const model_bundle::EntryView* xml = nullptr;
  const model_bundle::EntryView* weights_entry = nullptr;
  for (const model_bundle::EntryView& entry : entries) {
    if (entry.name == "model.xml") {
      xml = &entry;
    } else if (entry.name == "model.bin") {
      weights_entry = &entry;
    }
  }
  if (xml == nullptr || weights_entry == nullptr) {
    return Reject("bundle", "required model.xml/model.bin pair is absent", error);
  }
  if (xml->size > kMaxXmlBytes) {
    return Reject("policy_limit", "model.xml exceeds 8 MiB", error);
  }

  try {
    // Declaration order is a lifetime contract. Destruction is reversed:
    // model, Core, weights, model text, then the caller-owned FZB1 bytes.
    const std::string model_text(reinterpret_cast<const char*>(xml->data), xml->size);
    ov::Tensor weights;
    if (weights_entry->size != 0) {
      weights = ov::Tensor(ov::element::u8, ov::Shape{weights_entry->size},
                           weights_entry->data);
    }
    ov::Core core;
    const std::shared_ptr<ov::Model> model = core.read_model(model_text, weights);
    if (!model) {
      return Reject("frontend", "IR frontend returned a null model", error);
    }
    model->validate_nodes_and_infer_types();

    const ov::NodeVector operations = model->get_ordered_ops();
    if (operations.size() > kMaxNodes) {
      return Reject("policy_limit", "ordered operation count exceeds 4096", error);
    }
    summary->nodes = operations.size();
    summary->parameters = model->get_parameters().size();
    summary->results = model->get_results().size();
    summary->operations.reserve(operations.size());

    for (std::size_t index = 0; index < operations.size(); ++index) {
      const std::shared_ptr<ov::Node>& node = operations[index];
      OperationObservation operation;
      operation.index = index;
      operation.name = node->get_friendly_name();
      operation.type = node->get_type_name();
      operation.inputs.reserve(node->get_input_size());
      for (std::size_t port = 0; port < node->get_input_size(); ++port) {
        operation.inputs.push_back(PortDescription(
            node->get_input_element_type(port), node->get_input_partial_shape(port)));
      }
      operation.outputs.reserve(node->get_output_size());
      for (std::size_t port = 0; port < node->get_output_size(); ++port) {
        operation.outputs.push_back(PortDescription(
            node->get_output_element_type(port), node->get_output_partial_shape(port)));
      }
      summary->operations.push_back(std::move(operation));

      const auto constant = std::dynamic_pointer_cast<ov::op::v0::Constant>(node);
      if (!constant) {
        continue;
      }
      const std::size_t constant_size = constant->get_byte_size();
      if (constant_size > kMaxConstantPayloadBytes - summary->constant_bytes) {
        return Reject("policy_limit", "Constant payload scan exceeds 1 MiB", error);
      }
      const auto* constant_data =
          static_cast<const std::uint8_t*>(constant->get_data_ptr());
      if (constant_size != 0 && constant_data == nullptr) {
        return Reject("oracle", "Constant has a null data pointer", error);
      }

      ConstantObservation observation;
      observation.operation_index = index;
      observation.name = constant->get_friendly_name();
      observation.dtype = constant->get_element_type().get_type_name();
      {
        std::ostringstream shape;
        shape << constant->get_output_partial_shape(0);
        observation.shape = shape.str();
      }
      observation.bytes = constant_size;
      if (constant_size != 0) {
        observation.payload.assign(constant_data, constant_data + constant_size);
      }
      summary->constant_bytes += constant_size;
      summary->constant_observations.push_back(std::move(observation));
    }
    summary->constants = summary->constant_observations.size();
    return 0;
  } catch (const ov::Exception& exception) {
    return Reject("frontend", exception.what(), error);
  }
}

}  // namespace tool::openvino_loader
