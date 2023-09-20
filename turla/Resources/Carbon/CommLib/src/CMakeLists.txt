find_package(cryptopp CONFIG REQUIRED)
include(GenerateExportHeader)

# Adding the header files needed for the source files
include_directories( ${PROJECT_SOURCE_DIR}/include ${cryptopp_SOURCE_DIR})

# static DLL
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

# For preprocessor directives
SET(CARBON_HOME_DIR "C:\\\\Users\\\\Public" CACHE STRING "Path to Carbon home directory")
SET(CONFIG_FILE_PATH "C:\\\\Users\\\\Public\\\\dummyConfigFile.txt" CACHE STRING "Path to Carbon configuration file")
SET(FINISHED_TASKS_PATH "C:\\\\Users\\\\Public\\\\finishedTasks.txt" CACHE STRING "Path to finished tasks file")

# Adding all files to this library group
# Create commlib.dll as release DLL and CommLibDllTest.lib for unit tests
add_library(commlib SHARED configFileUtils.cpp HttpClient.cpp CommLib.cpp Tasks.cpp EncUtils.cpp Locker.cpp NamedPipeP2p.cpp Util.cpp dllmain.cpp WindowsWrappers.cpp Logging.cpp)
add_library(CommLibDLLTest configFileUtils.cpp HttpClient.cpp CommLib.cpp Tasks.cpp EncUtils.cpp Locker.cpp NamedPipeP2p.cpp Util.cpp dllmain.cpp WindowsWrappers.cpp Logging.cpp)
target_compile_definitions(
  commlib PUBLIC 
  #CARBON_HOME_DIR="C:\\\\Program Files\\\\Windows NT" 
  #CONFIG_FILE_PATH=""C:\\\\Program Files\\\\Windows NT\\\\setuplst.xml"" 
  #FINISHED_TASKS_PATH="C:\\\\Program Files\\\\Windows NT\\\\2028\\\\traverse.gif"
  CARBON_HOME_DIR="${CARBON_HOME_DIR}"
  CONFIG_FILE_PATH="${CONFIG_FILE_PATH}"
  FINISHED_TASKS_PATH="${FINISHED_TASKS_PATH}"
)
if(MSVC)
  target_compile_options(commlib PRIVATE /W4) # /WX
else()
  target_compile_options(commlib PRIVATE -Wall -Wextra -Werror)
endif()

if(WIN32)
  target_link_libraries(commlib PUBLIC ws2_32 wininet)
  target_link_libraries(commlib PUBLIC cryptopp::cryptopp)
  target_link_libraries(CommLibDLLTest PUBLIC ws2_32 wininet)
  target_link_libraries(CommLibDLLTest PUBLIC cryptopp::cryptopp)
endif()