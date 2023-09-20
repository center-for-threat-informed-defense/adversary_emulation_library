# Adding the header files needed for the source files
include_directories(${PROJECT_SOURCE_DIR}/include $ENV{MINGW64_ROOT}/include/cryptopp ${PROJECT_SOURCE_DIR}/tests)

# MINGW64 directory for crypto++ library
file(TO_CMAKE_PATH "$ENV{MINGW64_ROOT}" ENV_MINGW64_ROOT)
link_directories(${ENV_MINGW64_ROOT}/lib)

# Adding all files to this library group
add_library(
    UserModuleDll 
    SHARED
    core.cpp
    comms_http.cpp
    instruction.cpp
    execute.cpp
    execute_token.cpp
    file_handler.cpp
    logging.cpp
    enc_handler.cpp
    comms_pipe.cpp
    util.cpp
    api_wrappers.cpp
)

target_link_libraries(UserModuleDll WinInet cryptopp)