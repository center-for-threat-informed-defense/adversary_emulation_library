cmake_minimum_required(VERSION 3.10)


set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")

set(VCPKG_TARGET_TRIPLET x64-mingw-dynamic)
set(VCPKG_DEFAULT_HOST_TRIPLET x64-mingw-dynamic)
project(CompanionDLL VERSION 1.0)


set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CRYPTOPP "cryptopp::cryptopp")

include("$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
find_package(cryptopp CONFIG REQUIRED)



if (CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/data)

  add_subdirectory(src)

  include_directories(
      ${PROJECT_SOURCE_DIR}/include
  )

  

  add_library(
      exdbdata
      SHARED
      src/exdbdata.cpp
      src/stego.cpp
      src/base64.cpp
      src/pugixml.cpp
  )

  target_link_libraries(
    exdbdata
      cryptopp::cryptopp # If there are issues targeting cryptopp change line to "cryptopp::cryptopp"
  )

  set_target_properties(
    exdbdata PROPERTIES PREFIX ""
  )
endif ()


#
# Setting up Unit Tests
#

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
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
    include_directories(
      ${PROJECT_SOURCE_DIR}/include 
      ${PROJECT_SOURCE_DIR}/tests 
      ${PROJECT_SOURCE_DIR}/util
    )

    # Creating the test executable
    add_executable(
      unit_tests
      src/exdbdata.cpp
      src/stego.cpp
      src/base64.cpp
      src/pugixml.cpp
      tests/tests.cpp
    )
    # Link test executable with google test
    target_link_libraries(
      unit_tests
      ${CRYPTOPP}
      GTest::gtest
      GTest::gtest_main
      GTest::gmock
    )

    add_executable(
        analyze_image
        src/exdbdata.cpp
        src/stego.cpp
        src/base64.cpp
        src/pugixml.cpp
        util/analyze_image.cpp
    )

    set_target_properties(
      analyze_image PROPERTIES
          RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/util"
    )
    
    target_link_libraries(
      analyze_image
        cryptopp::cryptopp 
    )

    # Call the google test CMake framework, then call the gtest command.
    include(GoogleTest)
    gtest_discover_tests(unit_tests)
endif ()