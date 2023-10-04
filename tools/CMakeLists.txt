project(darlingserver-tools)

cmake_minimum_required(VERSION 3.13)

set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/../src/rpc.c" PROPERTIES
	GENERATED TRUE
)

add_library(dserverdbg_dserver_rpc STATIC "${CMAKE_CURRENT_BINARY_DIR}/../src/rpc.c")

add_dependencies(dserverdbg_dserver_rpc generate_dserver_rpc_wrappers)

target_compile_options(dserverdbg_dserver_rpc PRIVATE -include "${CMAKE_CURRENT_SOURCE_DIR}/dserverdbg-rpc-defs.h")
add_dependencies(dserverdbg_dserver_rpc rtsig_h)
target_include_directories(dserverdbg_dserver_rpc PRIVATE
	"${CMAKE_BINARY_DIR}/src/startup" # for `rtsig.h`
)
target_include_directories(dserverdbg_dserver_rpc PUBLIC
	"${CMAKE_CURRENT_BINARY_DIR}/../include"
	../include
)

add_executable(dserverdbg dserverdbg.c)

target_link_libraries(dserverdbg PRIVATE dserverdbg_dserver_rpc)

install(
	TARGETS dserverdbg
	DESTINATION bin
	PERMISSIONS
		OWNER_READ OWNER_WRITE OWNER_EXECUTE
		GROUP_READ GROUP_EXECUTE
		WORLD_READ WORLD_EXECUTE
		SETUID
)
