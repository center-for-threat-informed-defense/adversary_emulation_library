add_executable(
	installer
	"main.cpp"
	"common/error.cpp"
	"common/error.hpp"
	"common/string.cpp"
	"common/string.hpp"
	"common/handle.hpp"
	"ci/ci.cpp"
	"ci/ci.hpp"
	"ci/nt.cpp"
	"ci/nt.hpp"
	"driver/driver.cpp"
	"driver/driver.hpp"
	"driver/gb.hpp"
	"privesc/privesc.cpp"
	"privesc/privesc.hpp"
	"resource/resource.cpp"
	"resource/resource.hpp"
	"../external/hde64/hde64.c"
	"../external/hde64/hde64.h"
	"../external/hde64/table64.h"
 )

target_include_directories(installer PRIVATE "${PROJECT_SOURCE_DIR}" )
target_sources(installer PRIVATE "resource/resource.rc")

find_package(cxxopts CONFIG REQUIRED)

target_link_libraries(
	installer
	PRIVATE
	cxxopts::cxxopts
)

target_compile_features(installer PRIVATE cxx_std_23)
target_link_options(installer PRIVATE /PDBALTPATH:$<TARGET_PDB_FILE_NAME:installer>)
set_target_properties(installer PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
