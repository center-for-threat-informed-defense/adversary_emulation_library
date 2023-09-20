# CMakeList.txt : CMake project for TestIngestStruct, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("TestIngestStruct")

set(CMAKE_STATIC_LIBRARY_PREFIX "")

# Add source to this project's executable.
add_library (TestIngestStruct SHARED "TestIngestStruct.cpp" "TestIngestStruct.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET TestIngestStruct PROPERTY CXX_STANDARD 20)
endif()
