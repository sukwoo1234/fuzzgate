cmake_minimum_required(VERSION 3.16)
project(tool_tflite_loader C CXX)

if(NOT TENSORFLOW_SOURCE_DIR)
  message(FATAL_ERROR "TENSORFLOW_SOURCE_DIR must name the pinned TensorFlow source tree")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(
  "${TENSORFLOW_SOURCE_DIR}/tensorflow/lite"
  "${CMAKE_BINARY_DIR}/tensorflow-lite"
  EXCLUDE_FROM_ALL
)

add_library(tool_tflite_loader STATIC loader.cc)
target_include_directories(tool_tflite_loader PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(tool_tflite_loader PUBLIC tensorflow-lite)

add_executable(tflite_loader_replay replay.cc)
target_link_libraries(tflite_loader_replay PRIVATE tool_tflite_loader)

add_executable(tflite_structural_mutator structural_mutator.cc)
target_link_libraries(tflite_structural_mutator PRIVATE tensorflow-lite)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "tflite_loader_fuzzer requires Clang libFuzzer support")
endif()
add_executable(tflite_loader_fuzzer fuzzer.cc)
target_compile_options(tflite_loader_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(tflite_loader_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_libraries(tflite_loader_fuzzer PRIVATE tool_tflite_loader)
