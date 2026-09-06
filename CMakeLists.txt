project(darlingserver)

cmake_minimum_required(VERSION 3.13)

option(DSERVER_TOOLS "Build darlingserver tools (for debugging)" OFF)
option(DSERVER_ASAN "Build darlingserver with ASAN" OFF)
option(DSERVER_UBSAN "Build darlingserver with UBSAN" OFF)

if (DSERVER_TOOLS)
	add_subdirectory(tools)
endif()

if (DSERVER_ASAN)
	add_compile_definitions(
		DSERVER_ASAN=1
	)
else()
	add_compile_definitions(
		DSERVER_ASAN=0
	)
endif()

if (DSERVER_UBSAN)
	add_compile_definitions(
		DSERVER_UBSAN=1
	)
else()
	add_compile_definitions(
		DSERVER_UBSAN=0
	)
endif()

set(dserver_sanitizers "")
if (DSERVER_ASAN)
	if (NOT (dserver_sanitizers STREQUAL ""))
		set(dserver_sanitizers "${dserver_sanitizers},")
	endif()
	set(dserver_sanitizers "${dserver_sanitizers}address")
endif()
if (DSERVER_UBSAN)
	if (NOT (dserver_sanitizers STREQUAL ""))
		set(dserver_sanitizers "${dserver_sanitizers},")
	endif()
	set(dserver_sanitizers "${dserver_sanitizers}undefined")
endif()

option(DSERVER_EXTENDED_DEBUG "Build darlingserver with extended debugging support" OFF)

if (DSERVER_EXTENDED_DEBUG)
	add_compile_definitions(
		DSERVER_EXTENDED_DEBUG=1
	)
else()
	add_compile_definitions(
		DSERVER_EXTENDED_DEBUG=0
	)
endif()

option(DSERVER_SINGLE_THREADED "Only use a single thread per workqueue in darlingserver" ON)

if (DSERVER_SINGLE_THREADED)
	add_compile_definitions(
		DSERVER_SINGLE_THREADED=1
	)
else()
	add_compile_definitions(
		DSERVER_SINGLE_THREADED=0
	)
endif()

add_subdirectory(duct-tape)

set(DARLINGSERVER_INIT_PROCESS "/sbin/launchd" CACHE STRING "The init process darlingserver should execute (default is \"/sbin/launchd\")")

include_directories(
	include
	internal-include
	${CMAKE_CURRENT_BINARY_DIR}/include
	${CMAKE_CURRENT_BINARY_DIR}/internal-include
	${CMAKE_BINARY_DIR}/src/startup # for `rtsig.h`
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
	src/async-writer.cpp
	src/stack-pool.cpp
	src/system-config.cpp
	src/platform-identity.cpp
	src/code-signing.cpp
	src/trust-store.cpp
	src/prefix-setup.cpp
)

add_dependencies(darlingserver
	generate_dserver_rpc_wrappers
	rtsig_h
)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

# Link the library file rather than OpenSSL::Crypto: the imported target adds
# its include directory (usually /usr/include) as a system include, which
# moves it ahead of the C++ standard library's headers and breaks their
# #include_next. The headers are on the default search path anyway.
if (NOT OPENSSL_INCLUDE_DIR STREQUAL "/usr/include")
	target_include_directories(darlingserver PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

target_link_libraries(darlingserver PRIVATE
	darlingserver_duct_tape
	darlingserver_dc_codesign
	${OPENSSL_CRYPTO_LIBRARY}
)

find_package(LibXml2 REQUIRED)

# The code signature parser (include/darlingserver/dc_codesign.h and dc_entitlements.h).
# Host code, shared with mldr, so it is built position-independent.
add_library(darlingserver_dc_codesign STATIC
	src/codesign/dc_codesign.c
	src/codesign/dc_entitlements.c
)
set_target_properties(darlingserver_dc_codesign PROPERTIES POSITION_INDEPENDENT_CODE ON)
# <kern/cs_blobs.h> is copied into an include directory of its own, so that host code using it
# does not also see the rest of the imported XNU headers (which clash with the host's)
configure_file(duct-tape/xnu/osfmk/kern/cs_blobs.h ${CMAKE_CURRENT_BINARY_DIR}/codesign-include/kern/cs_blobs.h COPYONLY)
target_include_directories(darlingserver_dc_codesign PUBLIC
	include
	${CMAKE_CURRENT_BINARY_DIR}/codesign-include
)
if (NOT OPENSSL_INCLUDE_DIR STREQUAL "/usr/include")
	target_include_directories(darlingserver_dc_codesign PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
# Like OpenSSL above: LibXml2::LibXml2 can carry /usr/include (from pkg-config) as a
# system include directory, which breaks libstdc++'s #include_next <stdlib.h>.
target_include_directories(darlingserver_dc_codesign PUBLIC ${LIBXML2_INCLUDE_DIR})
target_link_libraries(darlingserver_dc_codesign PUBLIC
	${OPENSSL_CRYPTO_LIBRARY}
	${LIBXML2_LIBRARY}
)

find_library(LIBUCONTEXT ucontext)
if (LIBUCONTEXT)
	target_link_libraries(darlingserver PRIVATE ${LIBUCONTEXT})
	find_path(LIBUCONTEXT_INCLUDE_DIR NAMES libucontext/libucontext.h PATHS "${CMAKE_FIND_ROOT_PATH}/include" "${CMAKE_INSTALL_PREFIX}/include")
	if (LIBUCONTEXT_INCLUDE_DIR)
		target_include_directories(darlingserver PRIVATE ${LIBUCONTEXT_INCLUDE_DIR})
	elseif (DEFINED CMAKE_FIND_ROOT_PATH)
		target_include_directories(darlingserver PRIVATE ${CMAKE_FIND_ROOT_PATH}/include)
	endif()
endif()

find_library(LIBSEMAPHORE android-posix-semaphore)
if (LIBSEMAPHORE)
	target_link_libraries(darlingserver PRIVATE ${LIBSEMAPHORE})
endif()

target_compile_options(darlingserver PRIVATE
	-pthread
	-std=c++17
)
target_link_options(darlingserver PRIVATE
	-pthread
	-Wl,--gc-sections
)

if (DSERVER_ASAN OR DSERVER_UBSAN)
	target_compile_options(darlingserver PRIVATE
		-fsanitize=${dserver_sanitizers}
		-fsanitize-recover=all
		-fno-omit-frame-pointer
		-g
		-Og
	)
	target_link_options(darlingserver PRIVATE
		-fsanitize=${dserver_sanitizers}
		-fsanitize-recover=all
	)
endif()

if (DSERVER_EXTENDED_DEBUG)
	target_compile_options(darlingserver PRIVATE
		-fno-omit-frame-pointer
	)
endif()

install(TARGETS darlingserver DESTINATION bin)

#file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/${DARLING_SDK_RELATIVE_PATH}/usr/include/darlingserver")
#create_symlink(
#	"${DARLING_ROOT_RELATIVE_TO_SDK}/../../../src/darlingserver/include/darlingserver/rpc.h"
#	"${CMAKE_BINARY_DIR}/${DARLING_SDK_RELATIVE_PATH}/usr/include/darlingserver/rpc.h"
#)

if (NOT "${DARLINGSERVER_INIT_PROCESS}" STREQUAL "")
	target_compile_definitions(darlingserver PRIVATE
		DARLINGSERVER_INIT_PROCESS="${DARLINGSERVER_INIT_PROCESS}"
	)
endif()

add_subdirectory(tests)
