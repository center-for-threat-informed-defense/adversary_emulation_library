# For now, we will require cmake 3.10
cmake_minimum_required(VERSION 3.10)

# For now, the project version is 1.0 TODO in the future - update to better version
project(Orchestrator VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Creating header to pass version into code
configure_file(OrchestratorVersion.h.in OrchestratorVersion.h)

# Adding the directory for the OrchestratorDLL library
add_subdirectory(src)

#
# Setting up Unit Tests
#

# Fetching google test library, used to facilitate unit tests
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Telling CMake that there are tests to look for
enable_testing()

# Adding the header files needed for the source files
include_directories(${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/unittest)

# Adding the dummy configuration file for testing into the build folder
configure_file(${PROJECT_SOURCE_DIR}/bin/dummyConfigFile.txt COPYONLY)

# Creating the test executable
add_executable(
    unit_tests
    src/injection.cpp
    unittest/injection_test.cpp
    src/mutex.cpp
    unittest/mutex_test.cpp
    src/tasking.cpp
    unittest/tasking_test.cpp
    unittest/main_test.cpp
)

# Link test executable with google test
target_link_libraries(
    unit_tests
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
)

# Call the google test CMake framework, then call the gtest command
include(GoogleTest)
gtest_discover_tests(unit_tests)