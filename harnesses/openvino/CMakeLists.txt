cmake_minimum_required(VERSION 3.26)
project(tool_openvino_profile_probe LANGUAGES CXX)

find_package(OpenVINO REQUIRED COMPONENTS Runtime)

add_executable(openvino_ir_frontend_probe profile_probe.cc)
target_compile_features(openvino_ir_frontend_probe PRIVATE cxx_std_17)
target_compile_options(openvino_ir_frontend_probe PRIVATE -O1 -g -DNDEBUG)
target_link_libraries(openvino_ir_frontend_probe PRIVATE openvino::runtime)

option(OPENVINO_BUILD_FIXTURE_PROBE "Build the OVI-02 fixture probe" OFF)
if(OPENVINO_BUILD_FIXTURE_PROBE)
  add_executable(openvino_ir_fixture_probe fixture_probe.cc)
  target_compile_features(openvino_ir_fixture_probe PRIVATE cxx_std_17)
  target_compile_options(openvino_ir_fixture_probe PRIVATE
    -O1 -g -DNDEBUG -Wall -Wextra -Wconversion -Wsign-conversion -Wpedantic -Werror)
  target_include_directories(openvino_ir_fixture_probe PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../..")
  target_link_libraries(openvino_ir_fixture_probe PRIVATE openvino::runtime)
endif()
