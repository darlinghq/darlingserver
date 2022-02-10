project(darlingserver)

cmake_minimum_required(VERSION 3.10)

add_subdirectory(duct-tape)

set(DARLINGSERVER_INIT_PROCESS "/sbin/launchd" CACHE STRING "The init process darlingserver should execute (default is \"/sbin/launchd\")")

include_directories(
	include
	internal-include
	${CMAKE_CURRENT_BINARY_DIR}/include
	${CMAKE_CURRENT_BINARY_DIR}/internal-include
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/include/darlingserver/rpc.h
		${CMAKE_CURRENT_BINARY_DIR}/internal-include/darlingserver/rpc.internal.h
		${CMAKE_CURRENT_BINARY_DIR}/src/rpc.c
	COMMAND
		${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-rpc-wrappers.py
		${CMAKE_CURRENT_BINARY_DIR}/include/darlingserver/rpc.h
		${CMAKE_CURRENT_BINARY_DIR}/internal-include/darlingserver/rpc.internal.h
		${CMAKE_CURRENT_BINARY_DIR}/src/rpc.c
		\"../include/darlingserver/rpc.h\"
	VERBATIM
	MAIN_DEPENDENCY
		${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-rpc-wrappers.py
)

add_custom_target(generate_dserver_rpc_wrappers
	ALL
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/include/darlingserver/rpc.h
		${CMAKE_CURRENT_BINARY_DIR}/internal-include/darlingserver/rpc.internal.h
		${CMAKE_CURRENT_BINARY_DIR}/src/rpc.c
)

add_executable(darlingserver
	src/darlingserver.cpp
	src/server.cpp
	src/message.cpp
	src/call.cpp
	src/registry.cpp
	src/logging.cpp
	src/process.cpp
	src/thread.cpp
	src/utility.cpp
	src/kqchan.cpp
)

add_dependencies(darlingserver
	generate_dserver_rpc_wrappers
)

target_link_libraries(darlingserver
	darlingserver_duct_tape
	cap
)

target_compile_options(darlingserver PRIVATE -pthread -std=c++17)
target_link_options(darlingserver PRIVATE -pthread -Wl,--gc-sections)

install(TARGETS darlingserver DESTINATION bin)

#file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/${DARLING_SDK_RELATIVE_PATH}/usr/include/darlingserver")
#create_symlink(
#	"${DARLING_ROOT_RELATIVE_TO_SDK}/../../../src/darlingserver/include/darlingserver/rpc.h"
#	"${CMAKE_BINARY_DIR}/${DARLING_SDK_RELATIVE_PATH}/usr/include/darlingserver/rpc.h"
#)

include(setcap)

# necessary because mldr has these capabilities, so in order to access it for ptracing, we need the same set or a superset
setcap(bin/darlingserver cap_sys_rawio,cap_sys_resource+ep)

if (NOT "${DARLINGSERVER_INIT_PROCESS}" STREQUAL "")
	target_compile_definitions(darlingserver PRIVATE
		DARLINGSERVER_INIT_PROCESS="${DARLINGSERVER_INIT_PROCESS}"
	)
endif()
