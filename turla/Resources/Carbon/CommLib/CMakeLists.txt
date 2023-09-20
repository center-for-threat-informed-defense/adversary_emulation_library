# For now, we will require cmake 3.10
cmake_minimum_required(VERSION 3.10)

set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")

# For now, the project version is 1.0 TODO in future- update to better version
project(CommLib VERSION 0.1.0)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Creating header to pass version into code
configure_file(CommLibVersion.h.in CommLibVersion.h)

# Telling CMake the target is windows
if (WIN32)
  set (UNICODE_DEFAULT ON)
endif(WIN32)

# Adding the directory for the CommLibDLL library.
add_subdirectory(src)

#
# Setting up Unit Tests
#

# Fetching google test library, used to facilitate unittests. 
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
include_directories(${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/test)

# Adding the dummy configuration file for testing into the build folder.
configure_file(${PROJECT_SOURCE_DIR}/test/dummyConfigFile.txt ${CMAKE_CURRENT_BINARY_DIR}/dummyConfigFile.txt COPYONLY)
# Removing any left over generated encrypted files. Regenerated at testing.
file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/encryptedDummyConfigFile.txt)

# Creating the test executable
add_executable(
  unit_tests
  test/testing.h
  test/testingUtils.cpp
  test/utils_test.cc
  test/commlib_test.cc
  test/http_test.cc
  test/enc_utils_test.cc
  test/tasks_test.cc
  test/named_pipe_p2p_test.cc
  test/logging_test.cpp
)
# Link test executable with google test and the CommLib DLL.
target_link_libraries(
  unit_tests
  GTest::gtest
  GTest::gtest_main
  GTest::gmock
  CommLibDLLTest
)

# Call the google test CMake framework, then call the gtest command.
include(GoogleTest)
gtest_discover_tests(unit_tests)