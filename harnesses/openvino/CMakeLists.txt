cmake_minimum_required(VERSION 3.26)
project(tool_openvino_profile_probe LANGUAGES CXX)

find_package(OpenVINO REQUIRED COMPONENTS Runtime)

add_executable(openvino_ir_frontend_probe profile_probe.cc)
target_compile_features(openvino_ir_frontend_probe PRIVATE cxx_std_17)
target_compile_options(openvino_ir_frontend_probe PRIVATE -O1 -g -DNDEBUG)
target_link_libraries(openvino_ir_frontend_probe PRIVATE openvino::runtime)

option(OPENVINO_BUILD_FIXTURE_PROBE "Build the OVI-02 fixture probe" OFF)
option(OPENVINO_BUILD_LOADER "Build the OVI-03 shared loader wrappers" OFF)

set(OPENVINO_HARNESS_WARNINGS
  -Wall -Wextra -Wconversion -Wsign-conversion -Wpedantic -Werror)

if(OPENVINO_BUILD_FIXTURE_PROBE OR OPENVINO_BUILD_LOADER)
  add_library(tool_openvino_loader STATIC loader.cc)
  target_compile_features(tool_openvino_loader PUBLIC cxx_std_17)
  target_compile_options(tool_openvino_loader PRIVATE
    -O1 -g -DNDEBUG ${OPENVINO_HARNESS_WARNINGS})
  target_include_directories(tool_openvino_loader PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../..")
  target_link_libraries(tool_openvino_loader PUBLIC openvino::runtime)
endif()

if(OPENVINO_BUILD_FIXTURE_PROBE)
  add_executable(openvino_ir_fixture_probe fixture_probe.cc)
  target_compile_features(openvino_ir_fixture_probe PRIVATE cxx_std_17)
  target_compile_options(openvino_ir_fixture_probe PRIVATE
    -O1 -g -DNDEBUG ${OPENVINO_HARNESS_WARNINGS})
  target_link_libraries(openvino_ir_fixture_probe PRIVATE tool_openvino_loader)
endif()

if(OPENVINO_BUILD_LOADER)
  add_executable(openvino_ir_loader_replay replay.cc)
  target_compile_features(openvino_ir_loader_replay PRIVATE cxx_std_17)
  target_compile_options(openvino_ir_loader_replay PRIVATE
    -O1 -g -DNDEBUG ${OPENVINO_HARNESS_WARNINGS})
  target_link_libraries(openvino_ir_loader_replay PRIVATE tool_openvino_loader)

  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "openvino_ir_loader_fuzzer requires Clang libFuzzer support")
  endif()
  add_executable(openvino_ir_loader_fuzzer fuzzer.cc)
  target_compile_features(openvino_ir_loader_fuzzer PRIVATE cxx_std_17)
  target_compile_options(openvino_ir_loader_fuzzer PRIVATE
    -O1 -g -DNDEBUG ${OPENVINO_HARNESS_WARNINGS} -fsanitize=fuzzer)
  target_link_options(openvino_ir_loader_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_libraries(openvino_ir_loader_fuzzer PRIVATE tool_openvino_loader)
endif()
