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

function(configure_hdf5_fixture_target target_name)
  target_compile_features(${target_name} PRIVATE cxx_std_17)
  target_compile_options(${target_name} PRIVATE
    -O1 -g -DNDEBUG -Wall -Wextra -Wconversion -Wsign-conversion -Wpedantic -Werror)
  target_include_directories(${target_name} PRIVATE "${HDF5_INCLUDE_DIR}")
  target_link_libraries(${target_name} PRIVATE
    ${HDF5_HL_SHARED_LIBRARY}
    ${HDF5_C_SHARED_LIBRARY})
endfunction()

option(HDF5_BUILD_FIXTURE_TOOL "Build the HDF-02 fixture generator/verifier" OFF)
if(HDF5_BUILD_FIXTURE_TOOL)
  add_executable(hdf5_fixture_tool fixture_tool.cc)
  configure_hdf5_fixture_target(hdf5_fixture_tool)
endif()

option(HDF5_BUILD_FIXTURE_TEST_MUTANTS "Build HDF-02 negative-control writers" OFF)
if(HDF5_BUILD_FIXTURE_TEST_MUTANTS)
  add_executable(hdf5_fixture_chunk_mutant fixture_tool.cc)
  target_compile_definitions(hdf5_fixture_chunk_mutant PRIVATE
    HDF5_FIXTURE_MUTATE_CHUNK_SHAPE=1)
  configure_hdf5_fixture_target(hdf5_fixture_chunk_mutant)

  add_executable(hdf5_fixture_attribute_mutant fixture_tool.cc)
  target_compile_definitions(hdf5_fixture_attribute_mutant PRIVATE
    HDF5_FIXTURE_MUTATE_ATTRIBUTE_DTYPE=1)
  configure_hdf5_fixture_target(hdf5_fixture_attribute_mutant)
endif()
