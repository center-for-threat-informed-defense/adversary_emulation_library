# Adding the header files needed for the source files
include_directories(${PROJECT_SOURCE_DIR}/include)

# Adding all files to this library group
add_library(OrchestratorDll SHARED injection.cpp mutex.cpp tasking.cpp)