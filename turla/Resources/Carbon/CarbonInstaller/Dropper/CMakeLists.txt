cmake_minimum_required(VERSION 3.10)

project(CarbonDropper VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Adding the directory for the CarbonDropper source code.
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
include_directories(${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/tests)

# Creating the test executable
add_executable(
  unit_tests
  tests/dummy_components.cpp
  src/file_handler.cpp
  src/service_handler.cpp
  tests/file_handler_test.cpp
  tests/service_handler_test.cpp
)
# Link test executable with google test
target_link_libraries(
  unit_tests
  GTest::gtest
  GTest::gtest_main
  GTest::gmock
)

# Call the google test CMake framework, then call the gtest command.
include(GoogleTest)
gtest_discover_tests(unit_tests)
