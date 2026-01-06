cmake_minimum_required(VERSION 3.10)
project(svf-tools)

# --- Dependencies ---
# 1. LLVM
# We assume LLVM_DIR is set in environment or command line
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

# 2. SVF
# We assume SVF_DIR is set to the *Build* directory of SVF (where SVFConfig.cmake is)
# or installed location.
if(NOT DEFINED SVF_DIR)
    message(FATAL_ERROR "Please set SVF_DIR to the SVF build directory containing SVFConfig.cmake")
endif()
find_package(SVF REQUIRED CONFIG PATHS ${SVF_DIR} NO_DEFAULT_PATH)
message(STATUS "Found SVF at ${SVF_DIR}")
include_directories(${SVF_INCLUDE_DIRS})

# Add SVF Library Directory
link_directories(${SVF_DIR}/../../) # Release-build/lib

# FIX: SVFConfig.cmake often misses source headers if not installed to system.
# We infer the source root relative to the build directory.
# SVF_DIR = .../SVF/Release-build/lib/cmake/SVF
# We want .../SVF
get_filename_component(SVF_BUILD_ROOT "${SVF_DIR}/../../.." ABSOLUTE)
get_filename_component(SVF_SOURCE_ROOT "${SVF_BUILD_ROOT}/.." ABSOLUTE)

message(STATUS "Inferred SVF Source Root: ${SVF_SOURCE_ROOT}")

include_directories(${SVF_BUILD_ROOT}/include)               # Generated headers (config.h)
include_directories(${SVF_SOURCE_ROOT}/svf/include)          # SVF Core
include_directories(${SVF_SOURCE_ROOT}/svf-llvm/include)     # SVF LLVM


# 3. Z3 (Required by SVF)
find_package(Z3 REQUIRED)
include_directories(${Z3_INCLUDE_DIR})

# --- Subprojects ---
add_subdirectory(svf-checker) # Legacy Tool
add_subdirectory(lto-plugin)  # New In-Process Tool
