# Host unit tests (tests/host), built with darlingserver and run by `ctest`. Nothing here is
# installed. tests/run-host.sh and tests/run-*.sh build the same programs by hand, with sanitizers,
# and can run them against another source tree.

set(host ${CMAKE_CURRENT_SOURCE_DIR}/host)
set(root ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(gen ${CMAKE_CURRENT_BINARY_DIR}/generated)

# dserver_host_test(<topic> [TEMP_DIR] SOURCES <file>...)
# builds dserver_<topic>_test and registers it as darlingserver_<topic>;
# TEMP_DIR passes a new private directory as the program's argument
function(dserver_host_test topic)
	cmake_parse_arguments(TEST "TEMP_DIR" "" "SOURCES" ${ARGN})
	add_executable(dserver_${topic}_test ${TEST_SOURCES})
	target_compile_options(dserver_${topic}_test PRIVATE -pthread $<$<COMPILE_LANGUAGE:CXX>:-std=c++17>)
	target_link_options(dserver_${topic}_test PRIVATE -pthread)
	if (TEST_TEMP_DIR)
		add_test(NAME darlingserver_${topic} COMMAND ${host}/with-temp-dir.sh $<TARGET_FILE:dserver_${topic}_test>)
	else()
		add_test(NAME darlingserver_${topic} COMMAND dserver_${topic}_test)
	endif()
endfunction()

# tests that compile the real source files unchanged

foreach(topic message_recv message_recv_reuse message_send message_direct_send message_credentials)
	dserver_host_test(${topic} TEMP_DIR SOURCES ${host}/${topic}_test.cpp ${root}/src/message.cpp ${host}/log_stub.cpp)
endforeach()

dserver_host_test(workqueue_inline SOURCES ${host}/workqueue_inline_test.cpp)

dserver_host_test(logging TEMP_DIR SOURCES ${host}/logging_test.cpp ${root}/src/logging.cpp)
# stand-in server, process and thread headers, ahead of the real ones
target_include_directories(dserver_logging_test BEFORE PRIVATE ${host}/logging-stubs)

dserver_host_test(system_config SOURCES ${host}/system_config_test.cpp ${root}/src/system-config.cpp ${root}/duct-tape/src/csr.c)
target_include_directories(dserver_system_config_test PRIVATE ${root}/duct-tape/include)
# only the headers the host lacks (sys/csr.h, sys/appleapiopts.h) come from XNU
target_compile_options(dserver_system_config_test PRIVATE -idirafter ${root}/duct-tape/xnu/bsd)

dserver_host_test(platform_identity TEMP_DIR SOURCES ${host}/platform_identity_test.cpp ${root}/src/platform-identity.cpp)
if (NOT OPENSSL_INCLUDE_DIR STREQUAL "/usr/include")
	target_include_directories(dserver_platform_identity_test PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
target_link_libraries(dserver_platform_identity_test PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

# root-mode prefix setup helpers; run as an ordinary user in a private directory
dserver_host_test(prefix_setup TEMP_DIR SOURCES ${host}/prefix_setup_test.cpp ${root}/src/prefix-setup.cpp)

# tests that compile real functions cut out of a source file

add_custom_command(
	OUTPUT ${gen}/call.inc
	COMMAND ${CMAKE_COMMAND} -E make_directory ${gen}
	COMMAND python3 ${host}/extract-function.py ${root}/src/call.cpp ${gen}/call.inc
	DEPENDS ${host}/extract-function.py ${root}/src/call.cpp
	VERBATIM
)
add_custom_command(
	OUTPUT ${gen}/arg_parse.inc
	COMMAND ${CMAKE_COMMAND} -E make_directory ${gen}
	COMMAND sh -c "\"$@\" > \"$0\"" ${gen}/arg_parse.inc
		${host}/extract-static.sh ${root}/src/darlingserver.cpp parseNumericArgument parseIdArgument dropIdsMatch dropTookEffect
	DEPENDS ${host}/extract-static.sh ${root}/src/darlingserver.cpp
	VERBATIM
)
add_custom_command(
	OUTPUT ${gen}/process_state.inc
	COMMAND ${CMAKE_COMMAND} -E make_directory ${gen}
	COMMAND sh -c "\"$@\" > \"$0\"" ${gen}/process_state.inc
		${host}/extract-static.sh ${root}/src/darlingserver.cpp closeInheritedFds sanitizeProcessState
	DEPENDS ${host}/extract-static.sh ${root}/src/darlingserver.cpp
	VERBATIM
)
add_custom_command(
	OUTPUT ${gen}/launchd_handshake.inc
	COMMAND ${CMAKE_COMMAND} -E make_directory ${gen}
	COMMAND sh -c "\"$@\" > \"$0\"" ${gen}/launchd_handshake.inc
		${host}/extract-static.sh ${root}/src/darlingserver.cpp sendReadyByte readReadyByte
	DEPENDS ${host}/extract-static.sh ${root}/src/darlingserver.cpp
	VERBATIM
)
add_custom_command(
	OUTPUT ${gen}/process_maps.inc
	COMMAND ${CMAKE_COMMAND} -E make_directory ${gen}
	COMMAND sh -c "\"$@\" > \"$0\"" ${gen}/process_maps.inc
		${host}/extract-static.sh ${root}/src/process.cpp parseMapsLine procmapQuery procmapProtection
	DEPENDS ${host}/extract-static.sh ${root}/src/process.cpp
	VERBATIM
)
add_custom_command(
	OUTPUT ${gen}/pthread_cancel_defs.inc ${gen}/pthread_cancel_fns.inc
	COMMAND ${CMAKE_COMMAND} -E make_directory ${gen}
	COMMAND ${host}/pthread-cancel-inc.sh ${root} ${gen}/pthread_cancel_defs.inc ${gen}/pthread_cancel_fns.inc
	DEPENDS ${host}/pthread-cancel-inc.sh ${root}/duct-tape/src/psynch.c ${root}/duct-tape/src/thread.c
	VERBATIM
)
# the generated client code, built against socket-backed hooks (tests/host/rpc_hooks.h)
add_custom_command(
	OUTPUT
		${gen}/rpc/include/darlingserver/rpc.h
		${gen}/rpc/internal-include/darlingserver/rpc.internal.h
		${gen}/rpc/src/rpc.c
	COMMAND
		${root}/scripts/generate-rpc-wrappers.py
		${gen}/rpc/include/darlingserver/rpc.h
		${gen}/rpc/internal-include/darlingserver/rpc.internal.h
		${gen}/rpc/src/rpc.c
		\"rpc_hooks.h\"
	DEPENDS ${root}/scripts/generate-rpc-wrappers.py
	VERBATIM
)
# one target per generated file, so that the tests sharing it do not generate it concurrently
add_custom_target(dserver_test_call_inc DEPENDS ${gen}/call.inc)

foreach(topic call_peer_uid call_pid_order call_push_reply_pipe call_thread_owner)
	dserver_host_test(${topic} SOURCES ${host}/${topic}_test.cpp)
	target_include_directories(dserver_${topic}_test PRIVATE ${host})
	target_compile_definitions(dserver_${topic}_test PRIVATE CALL_FROM_MESSAGE_INC="${gen}/call.inc")
	add_dependencies(dserver_${topic}_test dserver_test_call_inc)
endforeach()

dserver_host_test(arg_parse SOURCES ${host}/arg_parse_test.cpp ${gen}/arg_parse.inc)
target_compile_definitions(dserver_arg_parse_test PRIVATE ARG_PARSE_INC="${gen}/arg_parse.inc")

dserver_host_test(process_state TEMP_DIR SOURCES ${host}/process_state_test.cpp ${gen}/process_state.inc)
target_compile_definitions(dserver_process_state_test PRIVATE PROCESS_STATE_INC="${gen}/process_state.inc")

dserver_host_test(launchd_handshake SOURCES ${host}/launchd_handshake_test.cpp ${gen}/launchd_handshake.inc)
target_compile_definitions(dserver_launchd_handshake_test PRIVATE LAUNCHD_HANDSHAKE_INC="${gen}/launchd_handshake.inc")

dserver_host_test(process_maps SOURCES ${host}/process_maps_test.cpp ${gen}/process_maps.inc)
target_include_directories(dserver_process_maps_test PRIVATE ${root}/src)
target_compile_definitions(dserver_process_maps_test PRIVATE PROCESS_MAPS_INC="${gen}/process_maps.inc")

dserver_host_test(pthread_cancel SOURCES ${host}/pthread_cancel_test.c ${gen}/pthread_cancel_defs.inc ${gen}/pthread_cancel_fns.inc)
target_compile_options(dserver_pthread_cancel_test PRIVATE -std=gnu11)
target_compile_definitions(dserver_pthread_cancel_test PRIVATE
	PTHREAD_CANCEL_DEFS_INC="${gen}/pthread_cancel_defs.inc"
	PTHREAD_CANCEL_FNS_INC="${gen}/pthread_cancel_fns.inc"
)

dserver_host_test(rpc_reply_fd SOURCES ${host}/rpc_reply_fd_test.c ${gen}/rpc/src/rpc.c)
# rpc.c is included by the test rather than compiled on its own
set_source_files_properties(${gen}/rpc/src/rpc.c PROPERTIES HEADER_FILE_ONLY TRUE)
target_include_directories(dserver_rpc_reply_fd_test BEFORE PRIVATE ${gen}/rpc/include ${gen}/rpc/internal-include ${host})
target_compile_options(dserver_rpc_reply_fd_test PRIVATE -std=gnu11 -w)
target_compile_definitions(dserver_rpc_reply_fd_test PRIVATE RPC_GENERATED_SOURCE="${gen}/rpc/src/rpc.c")
