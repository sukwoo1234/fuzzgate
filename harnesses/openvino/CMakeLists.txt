cmake_minimum_required(VERSION 3.26)
project(tool_openvino_profile_probe LANGUAGES CXX)

find_package(OpenVINO REQUIRED COMPONENTS Runtime)

add_executable(openvino_ir_frontend_probe profile_probe.cc)
target_compile_features(openvino_ir_frontend_probe PRIVATE cxx_std_17)
target_compile_options(openvino_ir_frontend_probe PRIVATE -O1 -g -DNDEBUG)
target_link_libraries(openvino_ir_frontend_probe PRIVATE openvino::runtime)
