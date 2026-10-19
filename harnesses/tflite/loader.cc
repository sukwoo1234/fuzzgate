#include "loader.h"

#include <algorithm>
#include <memory>

#include "tensorflow/lite/core/interpreter_builder.h"
#include "tensorflow/lite/interpreter.h"
#include "tensorflow/lite/kernels/register.h"
#include "tensorflow/lite/model_builder.h"

namespace tool::tflite_loader {

namespace {

std::string TensorTypeName(TfLiteType type) {
  switch (type) {
    case kTfLiteFloat32:
      return "float32";
    case kTfLiteInt8:
      return "int8";
    case kTfLiteUInt8:
      return "uint8";
    case kTfLiteInt16:
      return "int16";
    case kTfLiteInt32:
      return "int32";
    case kTfLiteInt64:
      return "int64";
    case kTfLiteBool:
      return "bool";
    case kTfLiteString:
      return "string";
    default:
      return "type_" + std::to_string(static_cast<int>(type));
  }
}

bool Contains(const std::vector<int>& indices, int index) {
  return std::find(indices.begin(), indices.end(), index) != indices.end();
}

}  // namespace

int LoadAndAllocate(const std::uint8_t* data, std::size_t size,
                    LoadSummary* summary, std::string* error) {
  if (summary == nullptr || error == nullptr) {
    return 10;
  }
  *summary = {};
  error->clear();
  if (data == nullptr || size == 0) {
    *error = "empty input";
    return 9;
  }
  if (size > kMaxInputBytes) {
    *error = "input exceeds 16 MiB limit";
    return 9;
  }

  // Declaration order is intentional. Destruction runs in reverse order:
  // Interpreter, builder/resolver, model, then the caller releases `data`.
  auto model = ::tflite::FlatBufferModel::VerifyAndBuildFromBuffer(
      reinterpret_cast<const char*>(data), size);
  if (!model) {
    *error = "VerifyAndBuildFromBuffer rejected input";
    return 9;
  }

  ::tflite::ops::builtin::BuiltinOpResolver resolver;
  ::tflite::InterpreterBuilder builder(*model, resolver);
  if (builder.SetNumThreads(1) != kTfLiteOk) {
    *error = "InterpreterBuilder::SetNumThreads(1) failed";
    return 9;
  }
  std::unique_ptr<::tflite::Interpreter> interpreter;
  if (builder(&interpreter) != kTfLiteOk || !interpreter) {
    *error = "InterpreterBuilder failed";
    return 9;
  }
  if (interpreter->AllocateTensors() != kTfLiteOk) {
    *error = "AllocateTensors failed";
    return 9;
  }

  summary->inputs = static_cast<int>(interpreter->inputs().size());
  summary->outputs = static_cast<int>(interpreter->outputs().size());
  summary->tensors = interpreter->tensors_size();
  if (summary->tensors < 0 || summary->tensors > kMaxTensors) {
    *error = "tensor count exceeds 4096 limit";
    return 9;
  }
  summary->observations.reserve(static_cast<std::size_t>(summary->tensors));
  for (int index = 0; index < summary->tensors; ++index) {
    const TfLiteTensor* tensor = interpreter->tensor(index);
    if (tensor == nullptr) {
      *error = "Interpreter::tensor returned null";
      return 9;
    }
    const bool is_input = Contains(interpreter->inputs(), index);
    const bool is_output = Contains(interpreter->outputs(), index);
    const bool is_constant = tensor->allocation_type == kTfLiteMmapRo;

    TensorObservation observation;
    observation.index = index;
    if (is_input && is_output) {
      observation.role = "input_output";
    } else if (is_input) {
      observation.role = "input";
    } else if (is_output) {
      observation.role = "output";
    } else if (is_constant) {
      observation.role = "constant";
    } else {
      observation.role = "intermediate";
    }
    observation.name = tensor->name == nullptr ? "" : tensor->name;
    observation.dtype = TensorTypeName(tensor->type);
    observation.bytes = tensor->bytes;
    if (tensor->dims != nullptr) {
      observation.shape.reserve(static_cast<std::size_t>(tensor->dims->size));
      for (int dimension = 0; dimension < tensor->dims->size; ++dimension) {
        observation.shape.push_back(tensor->dims->data[dimension]);
      }
    }
    if (is_constant) {
      if (tensor->data.raw_const == nullptr && tensor->bytes != 0) {
        *error = "constant tensor has no payload";
        return 9;
      }
      if (tensor->bytes > kMaxConstantPayloadBytes - summary->constant_bytes) {
        *error = "constant payload scan exceeds 1 MiB limit";
        return 9;
      }
      const auto* begin = reinterpret_cast<const std::uint8_t*>(tensor->data.raw_const);
      if (tensor->bytes != 0) {
        observation.constant_payload.assign(begin, begin + tensor->bytes);
      }
      summary->constants += 1;
      summary->constant_bytes += tensor->bytes;
    }
    summary->observations.push_back(std::move(observation));
  }
  return 0;
}

}  // namespace tool::tflite_loader
