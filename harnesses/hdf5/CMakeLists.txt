cmake_minimum_required(VERSION 3.26)
project(tool_hdf5_profile_probe LANGUAGES CXX)

find_package(HDF5 CONFIG REQUIRED COMPONENTS C HL shared)

if(NOT HDF5_C_SHARED_LIBRARY OR NOT HDF5_HL_SHARED_LIBRARY)
  message(FATAL_ERROR "HDF5 shared C and HL imported targets are required")
endif()

add_executable(hdf5_file_image_probe profile_probe.cc)
target_compile_features(hdf5_file_image_probe PRIVATE cxx_std_17)
target_compile_options(hdf5_file_image_probe PRIVATE
  -O1 -g -DNDEBUG -Wall -Wextra -Wconversion -Wsign-conversion -Wpedantic -Werror)
target_include_directories(hdf5_file_image_probe PRIVATE "${HDF5_INCLUDE_DIR}")
target_link_libraries(hdf5_file_image_probe PRIVATE
  ${HDF5_HL_SHARED_LIBRARY}
  ${HDF5_C_SHARED_LIBRARY})
