# CMakeLists.txt : Project CMake for rainbow, attack, gen_passwd, and check_passwd.

cmake_minimum_required(VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project("rainbow_attack_rust_cpp_cuda")

# Set C++ standard to C++20 for all executables
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED True)
endif()

# Add option to use portable SHA256
option(USE_PORTABLE_SHA256 "Use portable SHA256 implementation" OFF)

# Include directories
include_directories(${PROJECT_SOURCE_DIR})

# Common sources used in multiple executables
set(SOURCES_COMMON "constants.hpp" "utils/system-info.hpp" "utils/system-info.cpp" "utils/welcome.cpp" "utils/welcome.hpp")

# Determine the SHA256 implementation to use
if (USE_PORTABLE_SHA256)
  message(STATUS "Using portable SHA256 implementation")
  set(SOURCES_SHA256 "utils/sha256_portable.cpp" "utils/sha256_portable.h")
else()
  # Determine the architecture and select the appropriate SHA256 implementation
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    message(STATUS "Compiling for x86_64 architecture")
    set(SOURCES_SHA256 "utils/sha256_x64.cpp" "utils/sha256.h")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    message(STATUS "Compiling for ARM architecture")
    set(SOURCES_SHA256 "utils/sha256_arm.cpp" "utils/sha256.h")
  else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
  endif()
endif()

# Add definition for USE_PORTABLE_SHA256 to use in code
if (USE_PORTABLE_SHA256)
  add_definitions(-DUSE_PORTABLE_SHA256=1)
else()
  # Only add these compiler options when not using the portable SHA256 implementation
  if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
      # For x86 architecture, use SHA instructions and Haswell optimizations
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.2 -msha -march=native")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
      # For ARM architecture (e.g., macOS ARM), use ARM-specific optimizations
      add_compile_options(-march=armv8-a+crypto)
    endif()
  elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # MSVC supports SHA intrinsics without additional flags
  endif()
endif()

# Define architecture or portable based on compilation
if (USE_PORTABLE_SHA256)
  add_definitions(-DARCHITECTURE=\"portable\")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
  add_definitions(-DARCHITECTURE=\"x86_64\")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  add_definitions(-DARCHITECTURE=\"arm\")
else()
  add_definitions(-DARCHITECTURE=\"undefined\")
endif()

# Executable for rainbow
add_executable(rainbow "rainbow.cpp" ${SOURCES_COMMON} ${SOURCES_SHA256})

# Threads library for rainbow
find_package(Threads REQUIRED)
target_link_libraries(rainbow Threads::Threads)

# Executable for attack
add_executable(attack "attack.cpp" ${SOURCES_COMMON} ${SOURCES_SHA256})

# Threads library for attack
target_link_libraries(attack Threads::Threads)

# Executable for gen_passwd
add_executable(gen_passwd "utils/gen-passwd.cpp" "utils/passwd-utils.hpp" ${SOURCES_COMMON} "utils/sha256_portable.cpp" "utils/sha256_portable.h")

# Executable for check_passwd
add_executable(check_passwd "utils/check-passwd.cpp" "utils/passwd-utils.hpp" ${SOURCES_COMMON} "utils/sha256_portable.cpp" "utils/sha256_portable.h")
