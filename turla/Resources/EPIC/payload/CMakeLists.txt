# change this to res2 for use with HTTPS
if(NOT DEFINED BINARY_NAME)
    set(BINARY_NAME "res")
endif()

cmake_minimum_required (VERSION 3.8)

set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
set(VCPKG_TARGET_TRIPLET x64-windows-static)

project ("payload")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Os /MT")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO")

# Include sub-projects.
add_subdirectory ("src")

# Adding the header files needed for the source files
include_directories(
    ${PROJECT_SOURCE_DIR}/include 
    ${PROJECT_SOURCE_DIR}/tests
    # Uncomment if manually downloading and compiling BZip2
    #${PROJECT_SOURCE_DIR}/libs/include
)

include("$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

find_package(BZip2)
# Uncomment if manually downloading and compiling BZip2, comment out or delete line above
#find_library(BZIP bzlib ${PROJECT_SOURCE_DIR}/libs/lib)
find_package(cryptopp)

add_definitions(-DC2_ADDRESS="${C2_ADDRESS}" -DC2_PORT=${C2_PORT} -DUSE_HTTPS=${USE_HTTPS})

# Creating EPIC executable for quick testing
add_executable(
    test_${BINARY_NAME}
    src/epic.cpp
    src/comms.cpp
    src/base64_y.cpp
    src/file_ops.cpp
)

# Creates EPIC payload (worker) DLL, used in actual scenario
add_library(
    ${BINARY_NAME}
    SHARED
    src/epic.cpp
    src/comms.cpp
    src/base64_y.cpp
    src/file_ops.cpp
)

target_link_libraries(
    test_${BINARY_NAME}
    PUBLIC
    WinInet
    BZip2::BZip2
    # Uncomment for BZip2 manual download, comment out or delete line above
    #${BZIP}
    cryptopp::cryptopp
)

target_link_libraries(
    ${BINARY_NAME}
    PUBLIC
    WinInet
    BZip2::BZip2
    # Uncomment for BZip2 manual download, comment out or delete line above
    #${BZIP}
    cryptopp::cryptopp
)

set_target_properties(${BINARY_NAME} test_${BINARY_NAME} PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/bin
)

# Setting up Unit Tests

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Creating the test executable
    add_executable(
        unit_tests
        src/comms.cpp
        src/file_ops.cpp
        src/base64_y.cpp
        tests/comms_test.cpp
    )

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

    # Link test executable with google test
    target_link_libraries(
        unit_tests
        WinInet
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        ${BZIP}
        cryptopp::cryptopp
    )

    # Call the google test CMake framework, then call the gtest command
    include(GoogleTest)
    gtest_discover_tests(unit_tests)
endif ()
