cmake_minimum_required(VERSION 3.10)

project(SnakeUserModule VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Adding the directory for the SnakeUserModule source code.
add_subdirectory(src)

#
# Setting up Unit Tests
#

# Fetching google test library, used to facilitate unit tests. 
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Telling CMake that there are tests to look for.
enable_testing()

# Adding the header files needed for the source files
include_directories(${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/tests $ENV{MINGW64_ROOT}/include/cryptopp)

# MINGW64 directory for crypto++ library
file(TO_CMAKE_PATH "$ENV{MINGW64_ROOT}" ENV_MINGW64_ROOT)
link_directories(${ENV_MINGW64_ROOT}/lib)

# Creating the test executable
add_executable(
  unit_tests
  src/comms_http.cpp
  src/instruction.cpp
  src/core.cpp
  src/execute.cpp
  src/execute_token.cpp
  src/file_handler.cpp
  src/logging.cpp
  src/enc_handler.cpp
  src/comms_pipe.cpp
  src/util.cpp
  src/api_wrappers.cpp
  tests/comms_http_test.cpp
  tests/comms_pipe_test.cpp
  tests/instruction_test.cpp
  tests/execute_test.cpp
  tests/logging_test.cpp
  tests/enc_handler_test.cpp
  tests/core_test.cpp
  tests/util_test.cpp
)
# Link test executable with google test and other libraries

target_link_libraries(
  unit_tests
  WinInet
  cryptopp
  GTest::gtest
  GTest::gtest_main
  GTest::gmock
)

# Call the google test CMake framework, then call the gtest command.
include(GoogleTest)
gtest_discover_tests(unit_tests)