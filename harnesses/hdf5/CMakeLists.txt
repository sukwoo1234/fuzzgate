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

function(configure_hdf5_loader_target target_name)
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

option(HDF5_BUILD_LOADER "Build the HDF-03 shared loader wrappers" OFF)
option(HDF5_BUILD_LOADER_TESTS "Build HDF-03 policy and handle probes" OFF)

if(HDF5_BUILD_LOADER OR HDF5_BUILD_LOADER_TESTS)
  add_library(tool_hdf5_loader STATIC loader.cc)
  target_compile_features(tool_hdf5_loader PUBLIC cxx_std_17)
  target_compile_options(tool_hdf5_loader PRIVATE
    -O1 -g -DNDEBUG -Wall -Wextra -Wconversion -Wsign-conversion -Wpedantic -Werror)
  target_include_directories(tool_hdf5_loader PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${HDF5_INCLUDE_DIR}")
  target_link_libraries(tool_hdf5_loader PUBLIC
    ${HDF5_HL_SHARED_LIBRARY}
    ${HDF5_C_SHARED_LIBRARY})
endif()

if(HDF5_BUILD_LOADER)
  add_executable(hdf5_loader_replay replay.cc)
  configure_hdf5_loader_target(hdf5_loader_replay)
  target_link_libraries(hdf5_loader_replay PRIVATE tool_hdf5_loader)

  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "hdf5_loader_fuzzer requires Clang libFuzzer support")
  endif()
  add_executable(hdf5_loader_fuzzer fuzzer.cc)
  configure_hdf5_loader_target(hdf5_loader_fuzzer)
  target_compile_options(hdf5_loader_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_options(hdf5_loader_fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_libraries(hdf5_loader_fuzzer PRIVATE tool_hdf5_loader)
endif()

if(HDF5_BUILD_LOADER_TESTS)
  add_executable(hdf5_loader_test_tool loader_test_tool.cc)
  configure_hdf5_loader_target(hdf5_loader_test_tool)
  target_link_libraries(hdf5_loader_test_tool PRIVATE tool_hdf5_loader)
endif()
