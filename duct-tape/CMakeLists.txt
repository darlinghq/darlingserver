project(darlingserver-duct-tape)

include_directories(
	defines
	xnu/osfmk
	xnu/bsd
	xnu/libkern
	xnu/osfmk/libsa
	xnu/pexpert
	xnu/iokit
	xnu/EXTERNAL_HEADERS
	xnu

	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk
	${CMAKE_CURRENT_BINARY_DIR}/../include
	${CMAKE_BINARY_DIR}/src/startup
)

add_compile_definitions(
	__DARLING__
	DARLING_DEBUG
	PAGE_SIZE_FIXED
	CONFIG_SCHED_TRADITIONAL
	CONFIG_SCHED_TIMESHARE_CORE
	APPLE
	KERNEL
	KERNEL_PRIVATE
	XNU_KERNEL_PRIVATE
	PRIVATE
	__MACHO__=1
	volatile=__volatile
	NEXT
	__LITTLE_ENDIAN__=1
	__private_extern__=extern
	_NLINK_T
	VM32_SUPPORT=1
	MACH_KERNEL_PRIVATE
	ARCH_PRIVATE
	DRIVER_PRIVATE
	_KERNEL_BUILD
	KERNEL_BUILD
	MACH_KERNEL
	BSD_BUILD
	BSD_KERNEL_PRIVATE
	LP64KERN=1
	LP64_DEBUG=0
	TIMEZONE=0
	PST=0
	QUOTA
	ABSOLUTETIME_SCALAR_TYPE
	CONFIG_LCTX
	MACH
	CONFIG_ZLEAKS
	NO_DIRECT_RPC
	IPFIREWALL_FORWARD
	IPFIREWALL_DEFAULT_TO_ACCEPT
	TRAFFIC_MGT
	RANDOM_IP_ID
	TCP_DROP_SYNFIN
	ICMP_BANDLIM
	IFNET_INPUT_SANITY_CHK
	PSYNCH
	SECURE_KERNEL
	OLD_SEMWAIT_SIGNAL
	CONFIG_MBUF_JUMBO
	CONFIG_WORKQUEUE
	CONFIG_HFS_STD
	CONFIG_HFS_TRIM
	CONFIG_TASK_MAX=512
	CONFIG_IPC_TABLE_ENTRIES_STEPS=256
	NAMEDSTREAMS
	CONFIG_VOLFS
	CONFIG_IMGSRC_ACCESS
	CONFIG_TRIGGERS
	CONFIG_VFS_FUNNEL
	CONFIG_EXT_RESOLVER
	CONFIG_SEARCHFS
	IPSEC
	IPSEC_ESP
	IPV6FIREWALL_DEFAULT_TO_ACCEPT
	crypto
	randomipid
	CONFIG_KN_HASHSIZE=64
	CONFIG_VNODES=750
	CONFIG_VNODE_FREE_MIN=75
	CONFIG_NC_HASH=1024
	CONFIG_VFS_NAMES=2048
	CONFIG_MAX_CLUSTERS=4
	KAUTH_CRED_PRIMES_COUNT=3
	#"KAUTH_CRED_PRIMES={5, 17, 97}"
	CONFIG_MIN_NBUF=64
	CONFIG_MIN_NIOBUF=32
	#"CONFIG_NMBCLUSTERS=((1024 * 256) / MCLBYTES)"
	CONFIG_TCBHASHSIZE=128
	CONFIG_ICMP_BANDLIM=50
	CONFIG_AIO_MAX=10
	CONFIG_AIO_PROCESS_MAX=4
	CONFIG_AIO_THREAD_COUNT=2
	CONFIG_THREAD_MAX=1024
	CONFIG_MAXVIFS=2
	CONFIG_MFCTBLSIZ=16
	CONFIG_MSG_BSIZE=4096
	CONFIG_ENFORCE_SIGNED_CODE
	CONFIG_MEMORYSTATUS
	CONFIG_JETSAM
	CONFIG_FREEZE
	CONFIG_ZLEAK_ALLOCATION_MAP_NUM=8192
	CONFIG_ZLEAK_TRACE_MAP_NUM=4096
	VM_PRESSURE_EVENTS
	CONFIG_KERNEL_0DAY_SYSCALL_HANDLER
	EVENTMETER
	CONFIG_APP_PROFILE=0
	CC_USING_FENTRY=1
	IMPORTANCE_INHERITANCE=1
	#MACH_BSD=1
	CONFIG_REQUIRES_U32_MUNGING=1
	KERNEL_SERVER=1
	KERNEL_USER=1
	MACH_NOTIFY_SEND_POSSIBLE_EXPECTED
	XNU_TARGET_OS_OSX=1

	_CLOCK_T=1
	NO_KDEBUG=1
	CONFIG_IPC_KERNEL_MAP_SIZE=64

	__DARWIN_LITTLE_ENDIAN=1234
	__DARWIN_BYTE_ORDER=__DARWIN_LITTLE_ENDIAN
)

add_compile_options(
	-fblocks
	-ffunction-sections
	-fdata-sections
	-Wno-incompatible-library-redeclaration
	-Wno-error=int-conversion
)

if (DSERVER_ASAN OR DSERVER_UBSAN)
	add_compile_options(
		-fsanitize=${dserver_sanitizers}
		-fsanitize-recover=all
		-fno-omit-frame-pointer
		-g
		-Og
	)
	add_link_options(
		-fsanitize=${dserver_sanitizers}
		-fsanitize-recover=all
	)
endif()

if (DSERVER_EXTENDED_DEBUG)
	add_compile_options(
		-fno-omit-frame-pointer
	)
endif()

set(MIG_USER_SOURCE_SUFFIX "User.c")
set(MIG_SERVER_SOURCE_SUFFIX "Server.c")
set(MIG_SERVER_HEADER_SUFFIX "Server.h")
set(MIG_NO_XTRACE 1)

mig(xnu/osfmk/UserNotification/UNDReply.defs)

set(MIG_USER_SOURCE_SUFFIX "_user.c")
set(MIG_SERVER_SOURCE_SUFFIX "_server.c")
set(MIG_SERVER_HEADER_SUFFIX "_server.h")

mig(xnu/osfmk/device/device.defs)
mig(xnu/osfmk/default_pager/default_pager_alerts.defs)
mig(xnu/osfmk/default_pager/default_pager_object.defs)
mig(xnu/osfmk/kextd/kextd_mach.defs)
mig(xnu/osfmk/mach/audit_triggers.defs)
mig(xnu/osfmk/mach/clock.defs)
mig(xnu/osfmk/mach/clock_priv.defs)
mig(xnu/osfmk/mach/clock_reply.defs)
mig(xnu/osfmk/mach/exc.defs)
mig(xnu/osfmk/mach/host_notify_reply.defs)
mig(xnu/osfmk/mach/host_priv.defs)
mig(xnu/osfmk/mach/host_security.defs)
mig(xnu/osfmk/mach/lock_set.defs)
mig(xnu/osfmk/mach/mach_exc.defs)
mig(xnu/osfmk/mach/mach_host.defs)
mig(xnu/osfmk/mach/mach_notify.defs)
mig(xnu/osfmk/mach/mach_port.defs)
mig(xnu/osfmk/mach/mach_vm.defs)
mig(xnu/osfmk/mach/mach_voucher.defs)
mig(xnu/osfmk/mach/mach_voucher_attr_control.defs)
mig(xnu/osfmk/mach/memory_entry.defs)
mig(xnu/osfmk/mach/memory_object_control.defs)
mig(xnu/osfmk/mach/memory_object_default.defs)
mig(xnu/osfmk/mach/memory_object.defs)
mig(xnu/osfmk/mach/processor.defs)
mig(xnu/osfmk/mach/processor_set.defs)
mig(xnu/osfmk/mach/resource_notify.defs)
mig(xnu/osfmk/mach/restartable.defs)
mig(xnu/osfmk/mach/task_access.defs)
mig(xnu/osfmk/mach/task.defs)
mig(xnu/osfmk/mach/thread_act.defs)
mig(xnu/osfmk/mach/upl.defs)
mig(xnu/osfmk/mach/vm_map.defs)
mig(xnu/osfmk/mach/vm32_map.defs)
mig(xnu/osfmk/mach/exc.defs)
mig(xnu/osfmk/mach/mach_exc.defs)
mig(xnu/osfmk/mach/notify.defs)
mig(xnu/osfmk/mach/vm_map.defs)
mig(xnu/osfmk/mach/memory_object_default.defs)
mig(xnu/osfmk/mach/memory_object_control.defs)
mig(xnu/osfmk/mach/memory_object.defs)
mig(xnu/osfmk/mach/upl.defs)
mig(xnu/osfmk/mach/mach_notify.defs)
mig(xnu/osfmk/mach/vm32_map.defs)
mig(xnu/osfmk/mach/host_notify_reply.defs)
mig(xnu/osfmk/mach/mach_voucher_attr_control.defs)
mig(xnu/osfmk/mach/mach_voucher.defs)
mig(xnu/osfmk/mach/mach_eventlink.defs)

add_custom_target(kernel_mig_generate
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/upl.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/host_notify_reply.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/vm32_map_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/vm32_map_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_notify.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_voucher_attr_control.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/memory_entry_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/memory_object_control.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/memory_object_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/memory_object_default_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_voucher_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/vm_map.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/resource_notify.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/restartable_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/exc_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_exc_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/notify_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/task_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/clock_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/clock_priv_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/processor_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/host_priv_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/host_security_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/lock_set_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_port_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_vm_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_host_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/processor_set_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/thread_act_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/clock_reply_user.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_eventlink_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_eventlink_server.h
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/device/device_server.c
		${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/UserNotification/UNDReplyServer.c
)

add_library(darlingserver_duct_tape
	src/misc.c
	src/stubs.c
	src/locks.c
	src/memory.c
	src/task.c
	src/thread.c
	src/timer.c
	src/traps.c
	src/host.c
	src/processor.c
	src/kqchan.c
	src/semaphore.c
	src/psynch.c
	src/condvar.c

	xnu/libkern/os/refcnt.c
	xnu/libkern/gen/OSAtomicOperations.c
	xnu/libkern/c++/priority_queue.cpp

	xnu/osfmk/kern/ipc_clock.c
	xnu/osfmk/kern/ipc_host.c
	xnu/osfmk/kern/ipc_kobject.c
	xnu/osfmk/kern/ipc_mig.c
	xnu/osfmk/kern/ipc_misc.c
	xnu/osfmk/kern/ipc_sync.c
	xnu/osfmk/kern/ipc_tt.c
	xnu/osfmk/kern/turnstile.c
	xnu/osfmk/kern/waitq.c
	xnu/osfmk/kern/clock.c
	xnu/osfmk/kern/ltable.c
	xnu/osfmk/kern/mpsc_queue.c
	xnu/osfmk/kern/thread_call.c
	xnu/osfmk/kern/mk_timer.c
	xnu/osfmk/kern/host.c
	xnu/osfmk/kern/host_notify.c
	xnu/osfmk/kern/timer_call.c
	xnu/osfmk/kern/clock_oldops.c
	xnu/osfmk/kern/sync_sema.c
	xnu/osfmk/kern/sync_lock.c
	xnu/osfmk/kern/syscall_emulation.c
	xnu/osfmk/kern/ux_handler.c
	xnu/osfmk/kern/exception.c

	xnu/osfmk/ipc/ipc_entry.c
	xnu/osfmk/ipc/ipc_hash.c
	xnu/osfmk/ipc/ipc_importance.c
	xnu/osfmk/ipc/ipc_init.c
	xnu/osfmk/ipc/ipc_kmsg.c
	xnu/osfmk/ipc/ipc_mqueue.c
	xnu/osfmk/ipc/ipc_notify.c
	xnu/osfmk/ipc/ipc_object.c
	xnu/osfmk/ipc/ipc_port.c
	xnu/osfmk/ipc/ipc_pset.c
	xnu/osfmk/ipc/ipc_right.c
	xnu/osfmk/ipc/ipc_space.c
	xnu/osfmk/ipc/ipc_table.c
	xnu/osfmk/ipc/ipc_voucher.c
	xnu/osfmk/ipc/mach_debug.c
	xnu/osfmk/ipc/mach_kernelrpc.c
	xnu/osfmk/ipc/mach_msg.c
	xnu/osfmk/ipc/mach_port.c
	xnu/osfmk/ipc/mig_log.c
	xnu/osfmk/ipc/ipc_eventlink.c

	xnu/osfmk/i386/rtclock.c

	xnu/osfmk/prng/prng_random.c

	xnu/osfmk/vm/vm32_user.c

	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/clock_priv_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/clock_reply_user.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/clock_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/exc_user.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/exc_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/host_priv_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/host_security_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/lock_set_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_exc_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_exc_user.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_host_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_port_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_vm_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_voucher_attr_control_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_voucher_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/memory_entry_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/notify_user.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/processor_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/processor_set_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/restartable_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/task_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/thread_act_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/mach_eventlink_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/mach/vm32_map_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/device/device_server.c
	${CMAKE_CURRENT_BINARY_DIR}/xnu/osfmk/UserNotification/UNDReplyServer.c

	pthread/kern_synch.c
)

set_source_files_properties(pthread/kern_synch.c PROPERTIES
	COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}/pthread"
)

target_include_directories(darlingserver_duct_tape PRIVATE
	internal-include
	${CMAKE_CURRENT_BINARY_DIR}/../internal-include
	../include
)

target_include_directories(darlingserver_duct_tape PUBLIC
	include
)

add_dependencies(darlingserver_duct_tape
	kernel_mig_generate
	generate_dserver_rpc_wrappers
	rtsig_h
)

target_link_libraries(darlingserver_duct_tape PUBLIC
	libsimple_darlingserver
)
