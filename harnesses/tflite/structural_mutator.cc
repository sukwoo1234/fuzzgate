#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "tensorflow/compiler/mlir/lite/schema/schema_generated.h"

namespace {

constexpr std::size_t kMaxInputBytes = 16 * 1024 * 1024;

struct Options {
  std::string input;
  std::string output;
  std::string operation;
  std::uint64_t seed = 0;
};

struct Evidence {
  const char* mode;
  const char* field;
  const char* expected_loader;
  std::string before;
  std::string after;
};

struct MutationResult {
  bool applicable = false;
  bool corrupt_payload = false;
  bool corrupt_name = false;
  Evidence evidence{};
};

bool ParseUnsigned(const std::string& value, std::uint64_t* output) {
  try {
    std::size_t consumed = 0;
    const auto parsed = std::stoull(value, &consumed, 10);
    if (consumed != value.size()) return false;
    *output = parsed;
    return true;
  } catch (...) {
    return false;
  }
}

std::optional<Options> ParseOptions(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    if (i + 1 >= argc) return std::nullopt;
    const std::string flag(argv[i]);
    const std::string value(argv[++i]);
    if (flag == "--input") {
      options.input = value;
    } else if (flag == "--output") {
      options.output = value;
    } else if (flag == "--operator") {
      options.operation = value;
    } else if (flag == "--seed") {
      if (!ParseUnsigned(value, &options.seed)) return std::nullopt;
    } else {
      return std::nullopt;
    }
  }
  if (options.input.empty() || options.output.empty() || options.operation.empty()) {
    return std::nullopt;
  }
  return options;
}

bool ReadFile(const std::string& path, std::vector<std::uint8_t>* bytes) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) return false;
  const auto end = stream.tellg();
  if (end <= 0 || static_cast<std::uint64_t>(end) > kMaxInputBytes) return false;
  bytes->resize(static_cast<std::size_t>(end));
  stream.seekg(0, std::ios::beg);
  return static_cast<bool>(stream.read(
      reinterpret_cast<char*>(bytes->data()), static_cast<std::streamsize>(bytes->size())));
}

bool WriteFile(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(stream);
}

tflite::SubGraphT* FirstSubgraph(tflite::ModelT* model) {
  if (model->subgraphs.empty() || !model->subgraphs[0]) return nullptr;
  return model->subgraphs[0].get();
}

std::optional<std::pair<std::size_t, std::size_t>> FindConstantTensor(
    const tflite::ModelT& model, const tflite::SubGraphT& graph) {
  for (std::size_t tensor_index = 0; tensor_index < graph.tensors.size(); ++tensor_index) {
    const auto& tensor = graph.tensors[tensor_index];
    if (!tensor || tensor->buffer >= model.buffers.size() ||
        !model.buffers[tensor->buffer] || model.buffers[tensor->buffer]->data.empty()) {
      continue;
    }
    return std::make_pair(tensor_index, static_cast<std::size_t>(tensor->buffer));
  }
  return std::nullopt;
}

bool IsSimpleFloatAdd(const tflite::ModelT& model, const tflite::SubGraphT& graph) {
  if (graph.tensors.empty() || graph.operators.empty() || model.operator_codes.empty()) {
    return false;
  }
  const auto& operation = graph.operators[0];
  if (!operation || operation->opcode_index >= model.operator_codes.size() ||
      !model.operator_codes[operation->opcode_index]) {
    return false;
  }
  if (model.operator_codes[operation->opcode_index]->builtin_code !=
          tflite::BuiltinOperator_ADD ||
      operation->builtin_options.type != tflite::BuiltinOptions_AddOptions) {
    return false;
  }
  return std::all_of(graph.tensors.begin(), graph.tensors.end(), [](const auto& tensor) {
    return tensor && tensor->type == tflite::TensorType_FLOAT32 &&
           tensor->shape.size() == 1 && tensor->shape[0] > 0;
  });
}

std::string ShapeSummary(const tflite::SubGraphT& graph, std::size_t buffer_size) {
  std::string result = "shapes=";
  for (std::size_t index = 0; index < graph.tensors.size(); ++index) {
    if (index != 0) result += ',';
    if (!graph.tensors[index] || graph.tensors[index]->shape.empty()) {
      result += "none";
    } else {
      result += std::to_string(graph.tensors[index]->shape[0]);
    }
  }
  result += ";buffer_bytes=" + std::to_string(buffer_size);
  return result;
}

bool ResizeSimpleAdd(tflite::ModelT* model, std::int32_t elements,
                     std::string* before, std::string* after) {
  auto* graph = FirstSubgraph(model);
  if (!graph || !IsSimpleFloatAdd(*model, *graph)) return false;
  const auto constant = FindConstantTensor(*model, *graph);
  if (!constant) return false;
  auto& buffer = model->buffers[constant->second]->data;
  const auto& tensor = graph->tensors[constant->first];
  const auto old_elements = tensor->shape[0];
  if (old_elements <= 0 || buffer.size() % static_cast<std::size_t>(old_elements) != 0) {
    return false;
  }
  const std::size_t element_size = buffer.size() / static_cast<std::size_t>(old_elements);
  if (element_size != sizeof(float)) return false;
  *before = ShapeSummary(*graph, buffer.size());
  const std::vector<std::uint8_t> first_element(buffer.begin(), buffer.begin() + element_size);
  buffer.clear();
  for (std::int32_t i = 0; i < elements; ++i) {
    buffer.insert(buffer.end(), first_element.begin(), first_element.end());
  }
  for (auto& candidate : graph->tensors) {
    candidate->shape[0] = elements;
    if (!candidate->shape_signature.empty()) candidate->shape_signature[0] = elements;
  }
  *after = ShapeSummary(*graph, buffer.size());
  return true;
}

MutationResult MutateTensorShape(tflite::ModelT* model, std::uint64_t seed,
                                 bool reject) {
  auto* graph = FirstSubgraph(model);
  if (!graph || !IsSimpleFloatAdd(*model, *graph)) return {};
  const auto constant = FindConstantTensor(*model, *graph);
  if (!constant) return {};
  auto& tensor = graph->tensors[constant->first];
  auto& buffer = model->buffers[constant->second]->data;
  MutationResult result;
  result.applicable = true;
  result.evidence = {reject ? "reject" : "structural",
                     reject ? "tensor.shape_buffer" : "tensor.shape",
                     reject ? "reject" : "accept", "", ""};
  if (reject) {
    result.evidence.before = "shape=" + std::to_string(tensor->shape[0]) +
                             ";buffer_bytes=" + std::to_string(buffer.size());
    const auto delta = static_cast<std::int32_t>(1 + seed % 3);
    if (tensor->shape[0] > std::numeric_limits<std::int32_t>::max() - delta) {
      tensor->shape[0] = -2;
    } else {
      tensor->shape[0] += delta;
    }
    result.evidence.after = "shape=" + std::to_string(tensor->shape[0]) +
                            ";buffer_bytes=" + std::to_string(buffer.size());
  } else {
    result.applicable = ResizeSimpleAdd(model, static_cast<std::int32_t>(2 + seed % 3),
                                        &result.evidence.before, &result.evidence.after);
  }
  return result;
}

MutationResult MutateDtypeQuantization(tflite::ModelT* model, std::uint64_t seed,
                                       bool reject) {
  auto* graph = FirstSubgraph(model);
  if (!graph || !IsSimpleFloatAdd(*model, *graph)) return {};
  const auto constant = FindConstantTensor(*model, *graph);
  if (!constant) return {};
  MutationResult result;
  result.applicable = true;
  result.evidence = {reject ? "reject" : "structural", "tensor.dtype_quantization",
                     reject ? "reject" : "accept", "dtype=float32;quant=none",
                     reject ? "dtype=mixed_float32_int8;quant=constant_only"
                            : "dtype=int8;quant=scale_zero_point"};
  if (reject) {
    auto& tensor = graph->tensors[constant->first];
    tensor->type = tflite::TensorType_INT8;
    tensor->quantization = std::make_unique<tflite::QuantizationParametersT>();
    tensor->quantization->scale = {0.5F};
    tensor->quantization->zero_point = {0};
    model->buffers[constant->second]->data.assign(1, 3);
    return result;
  }
  for (auto& tensor : graph->tensors) {
    tensor->type = tflite::TensorType_INT8;
    tensor->quantization = std::make_unique<tflite::QuantizationParametersT>();
    const float scale = (seed & 1U) == 0 ? 0.5F : 0.25F;
    tensor->quantization->min = {-32.0F};
    tensor->quantization->max = {31.5F};
    tensor->quantization->scale = {scale};
    tensor->quantization->zero_point = {0};
    tensor->quantization->quantized_dimension = 0;
  }
  auto& buffer = model->buffers[constant->second]->data;
  const std::size_t elements = buffer.size() / sizeof(float);
  buffer.assign(elements, static_cast<std::uint8_t>(3 + seed % 5));
  const auto opcode_index = graph->operators[0]->opcode_index;
  model->operator_codes[opcode_index]->version = 2;
  return result;
}

MutationResult MutateBufferPayload(tflite::ModelT* model, std::uint64_t seed,
                                   bool reject) {
  auto* graph = FirstSubgraph(model);
  if (!graph || !IsSimpleFloatAdd(*model, *graph)) return {};
  const auto constant = FindConstantTensor(*model, *graph);
  if (!constant) return {};
  MutationResult result;
  result.applicable = true;
  result.evidence = {reject ? "reject" : "structural", "buffer.data",
                     reject ? "reject" : "accept", "", ""};
  const auto old_size = model->buffers[constant->second]->data.size();
  if (reject) {
    result.corrupt_payload = true;
    result.evidence.before = "payload_bytes=" + std::to_string(old_size);
    result.evidence.after = "payload_bytes=" + std::to_string(old_size - 1) + ";truncated=1";
  } else {
    result.applicable = ResizeSimpleAdd(model, static_cast<std::int32_t>(3 + seed % 2),
                                        &result.evidence.before, &result.evidence.after);
  }
  return result;
}

MutationResult MutateOperatorOptions(tflite::ModelT* model, std::uint64_t seed,
                                     bool reject) {
  auto* graph = FirstSubgraph(model);
  if (!graph || graph->operators.empty() || !graph->operators[0]) return {};
  auto& operation = graph->operators[0];
  if (operation->opcode_index >= model->operator_codes.size() ||
      !model->operator_codes[operation->opcode_index] ||
      model->operator_codes[operation->opcode_index]->builtin_code !=
          tflite::BuiltinOperator_ADD ||
      operation->builtin_options.type != tflite::BuiltinOptions_AddOptions) {
    return {};
  }
  auto* add = operation->builtin_options.AsAddOptions();
  if (!add) return {};
  MutationResult result;
  result.applicable = true;
  result.evidence = {reject ? "reject" : "structural",
                     reject ? "operator.opcode_options" : "operator.builtin_options",
                     reject ? "reject" : "accept", "opcode=ADD;options=AddOptions", ""};
  if (reject) {
    auto& code = model->operator_codes[operation->opcode_index];
    code->builtin_code = tflite::BuiltinOperator_CONV_2D;
    code->deprecated_builtin_code = static_cast<std::int8_t>(tflite::BuiltinOperator_CONV_2D);
    result.evidence.after = "opcode=CONV_2D;options=AddOptions";
  } else {
    add->fused_activation_function = (seed & 1U) == 0
                                         ? tflite::ActivationFunctionType_RELU
                                         : tflite::ActivationFunctionType_RELU6;
    result.evidence.after = std::string("opcode=ADD;options=AddOptions;") +
                            ((seed & 1U) == 0 ? "activation=RELU" : "activation=RELU6");
  }
  return result;
}

void RemapIndex(std::int32_t* value, std::int32_t first, std::int32_t second) {
  if (*value == first) {
    *value = second;
  } else if (*value == second) {
    *value = first;
  }
}

void RemapVector(std::vector<std::int32_t>* values, std::int32_t first,
                 std::int32_t second) {
  for (auto& value : *values) RemapIndex(&value, first, second);
}

MutationResult MutateGraphReferences(tflite::ModelT* model, std::uint64_t seed,
                                     bool reject) {
  auto* graph = FirstSubgraph(model);
  if (!graph || graph->tensors.size() < 2 || graph->operators.empty() ||
      !graph->operators[0] || graph->operators[0]->inputs.empty()) {
    return {};
  }
  MutationResult result;
  result.applicable = true;
  result.evidence = {reject ? "reject" : "structural", "graph.tensor_indices",
                     reject ? "reject" : "accept", "", ""};
  if (reject) {
    const auto before = graph->operators[0]->inputs[0];
    const auto after = static_cast<std::int32_t>(graph->tensors.size() + 1 + seed % 7);
    graph->operators[0]->inputs[0] = after;
    result.evidence.before = "operator_input=" + std::to_string(before);
    result.evidence.after = "operator_input=" + std::to_string(after) + ";tensor_count=" +
                            std::to_string(graph->tensors.size());
    return result;
  }

  const std::int32_t first = 0;
  const std::int32_t second = 1;
  result.evidence.before = "tensor0=" + graph->tensors[0]->name + ";tensor1=" +
                           graph->tensors[1]->name + ";refs=original";
  std::swap(graph->tensors[0], graph->tensors[1]);
  RemapVector(&graph->inputs, first, second);
  RemapVector(&graph->outputs, first, second);
  for (auto& operation : graph->operators) {
    if (!operation) continue;
    RemapVector(&operation->inputs, first, second);
    RemapVector(&operation->outputs, first, second);
    RemapVector(&operation->intermediates, first, second);
  }
  for (auto& signature : model->signature_defs) {
    if (!signature || signature->subgraph_index != 0) continue;
    for (auto& map : signature->inputs) {
      if (map) {
        auto index = static_cast<std::int32_t>(map->tensor_index);
        RemapIndex(&index, first, second);
        map->tensor_index = static_cast<std::uint32_t>(index);
      }
    }
    for (auto& map : signature->outputs) {
      if (map) {
        auto index = static_cast<std::int32_t>(map->tensor_index);
        RemapIndex(&index, first, second);
        map->tensor_index = static_cast<std::uint32_t>(index);
      }
    }
  }
  result.evidence.after = "tensor0=" + graph->tensors[0]->name + ";tensor1=" +
                          graph->tensors[1]->name + ";refs=remapped";
  return result;
}

MutationResult MutateNamesMetadata(tflite::ModelT* model, std::uint64_t seed,
                                   bool reject) {
  auto* graph = FirstSubgraph(model);
  if (!graph || graph->tensors.empty() || !graph->tensors[0]) return {};
  const std::string suffix = "_m" + std::to_string(seed);
  MutationResult result;
  result.applicable = true;
  result.evidence = {reject ? "reject" : "structural", "model.names_metadata",
                     reject ? "reject" : "accept", "", ""};
  const auto old_length = graph->tensors[0]->name.size();
  result.evidence.before = "tensor_name_bytes=" + std::to_string(old_length) +
                           ";description_bytes=" + std::to_string(model->description.size());
  graph->tensors[0]->name += suffix;
  graph->name += suffix;
  model->description += suffix;
  if (reject) {
    result.corrupt_name = true;
    result.evidence.after = "tensor_name_length=4294967295;corrupt=1";
  } else {
    result.evidence.after = "tensor_name_bytes=" + std::to_string(graph->tensors[0]->name.size()) +
                            ";description_bytes=" + std::to_string(model->description.size());
  }
  return result;
}

MutationResult ApplyMutation(tflite::ModelT* model, const std::string& operation,
                             std::uint64_t seed) {
  if (operation == "tensor_shape") return MutateTensorShape(model, seed, false);
  if (operation == "tensor_shape_reject") return MutateTensorShape(model, seed, true);
  if (operation == "dtype_quantization") return MutateDtypeQuantization(model, seed, false);
  if (operation == "dtype_quantization_reject") {
    return MutateDtypeQuantization(model, seed, true);
  }
  if (operation == "buffer_payload") return MutateBufferPayload(model, seed, false);
  if (operation == "buffer_payload_reject") return MutateBufferPayload(model, seed, true);
  if (operation == "operator_options") return MutateOperatorOptions(model, seed, false);
  if (operation == "operator_options_reject") return MutateOperatorOptions(model, seed, true);
  if (operation == "graph_references") return MutateGraphReferences(model, seed, false);
  if (operation == "graph_references_reject") return MutateGraphReferences(model, seed, true);
  if (operation == "names_metadata") return MutateNamesMetadata(model, seed, false);
  if (operation == "names_metadata_reject") return MutateNamesMetadata(model, seed, true);
  return {};
}

std::vector<std::uint8_t> Serialize(const tflite::ModelT& model) {
  flatbuffers::FlatBufferBuilder builder;
  const auto root = tflite::Model::Pack(builder, &model);
  tflite::FinishModelBuffer(builder, root);
  return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}

bool TruncatePayload(std::vector<std::uint8_t>* bytes) {
  const auto* model = tflite::GetModel(bytes->data());
  if (!model || !model->buffers()) return false;
  for (const auto* buffer : *model->buffers()) {
    if (!buffer || !buffer->data() || buffer->data()->size() < 2) continue;
    const auto* data = buffer->data()->Data();
    const auto offset = static_cast<std::size_t>(data - bytes->data());
    bytes->resize(offset + buffer->data()->size() - 1);
    return true;
  }
  return false;
}

bool CorruptNameLength(std::vector<std::uint8_t>* bytes) {
  const auto* model = tflite::GetModel(bytes->data());
  if (!model || !model->subgraphs() || model->subgraphs()->size() == 0) return false;
  const auto* graph = model->subgraphs()->Get(0);
  if (!graph || !graph->tensors() || graph->tensors()->size() == 0) return false;
  const auto* tensor = graph->tensors()->Get(0);
  if (!tensor || !tensor->name() || tensor->name()->size() == 0) return false;
  auto* data = const_cast<std::uint8_t*>(tensor->name()->Data());
  const auto invalid_length = std::numeric_limits<std::uint32_t>::max();
  std::memcpy(data - sizeof(invalid_length), &invalid_length, sizeof(invalid_length));
  return true;
}

bool IsVerified(const std::vector<std::uint8_t>& bytes) {
  flatbuffers::Verifier verifier(bytes.data(), bytes.size());
  return tflite::VerifyModelBuffer(verifier);
}

}  // namespace

int main(int argc, char** argv) {
  const auto options = ParseOptions(argc, argv);
  if (!options) {
    std::cerr << "usage: tflite_structural_mutator --input FILE --output FILE "
                 "--operator NAME --seed N\n";
    return 2;
  }

  std::vector<std::uint8_t> input;
  if (!ReadFile(options->input, &input) || !IsVerified(input)) {
    std::cerr << "TFLITE_MUTATION_ERROR reason=invalid_input\n";
    return 2;
  }
  auto model = tflite::UnPackModel(input.data());
  if (!model) {
    std::cerr << "TFLITE_MUTATION_ERROR reason=unpack_failed\n";
    return 2;
  }

  auto result = ApplyMutation(model.get(), options->operation, options->seed);
  if (!result.applicable) {
    std::cerr << "TFLITE_MUTATION_NO_APPLICABLE operator=" << options->operation << '\n';
    return 3;
  }

  auto output = Serialize(*model);
  if (result.corrupt_payload && !TruncatePayload(&output)) {
    std::cerr << "TFLITE_MUTATION_ERROR reason=payload_not_found\n";
    return 2;
  }
  if (result.corrupt_name && !CorruptNameLength(&output)) {
    std::cerr << "TFLITE_MUTATION_ERROR reason=name_not_found\n";
    return 2;
  }

  const bool expected_verified = !result.corrupt_payload && !result.corrupt_name;
  if (output == input || IsVerified(output) != expected_verified) {
    std::cerr << "TFLITE_MUTATION_ERROR reason=noop_or_verifier_mismatch\n";
    return 2;
  }
  if (!WriteFile(options->output, output)) {
    std::cerr << "TFLITE_MUTATION_ERROR reason=write_failed\n";
    return 2;
  }

  std::cout << "TFLITE_MUTATION_OK"
            << " operator=" << options->operation
            << " mode=" << result.evidence.mode
            << " field=" << result.evidence.field
            << " before=" << result.evidence.before
            << " after=" << result.evidence.after
            << " expected_loader=" << result.evidence.expected_loader << '\n';
  return 0;
}
