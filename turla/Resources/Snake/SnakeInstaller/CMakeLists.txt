# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.23)

project (
	"SnakeInstaller"
    VERSION 0.0.1
    LANGUAGES C CXX
    DESCRIPTION "Rootkit installer for Snake"
)

add_subdirectory("src")
