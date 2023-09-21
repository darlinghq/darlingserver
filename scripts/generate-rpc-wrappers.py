#!/usr/bin/env python3

import os
import sys
from collections import OrderedDict
import textwrap
from datetime import datetime

XNU_TRAP_CALL          = 1 << 0
XNU_TRAP_NOPREFIX      = 1 << 1
XNU_TRAP_NOSUFFIX      = 1 << 2
XNU_TRAP_NOSUFFIX_ARGS = 1 << 3
XNU_TRAP_BSD           = 1 << 4
XNU_TRAP_NO_DTAPE_DEF  = 1 << 5
XNU_BSD_TRAP_CALL      = XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | XNU_TRAP_NOSUFFIX | XNU_TRAP_NOSUFFIX_ARGS | XNU_TRAP_BSD
UNMANAGED_CALL         = 1 << 6
ALLOW_INTERRUPTIONS    = 1 << 7
PUSH_UNKNOWN_REPLIES   = 1 << 8

# NOTE: in Python 3.7+, we can rely on dictionaries having their items in insertion order.
#       unfortunately, we can't expect everyone building Darling to have Python 3.7+ installed.
calls = [
	#
	# FORMAT:
	# tuple with either 3 or 4 members:
	#   1. call name: the name of the remote procedure
	#   2. call parameters: the set of parameters callers are expected to provide arguments for.
	#   3. return parameters: the set of parameters the procedure is expected to return values for.
	#   4. flags: an optional set of flags that modify how this call is processed and wrapped.
	# if the set of flags (4) is omitted, it defaults to 0.
	#
	# PARAMETERS:
	# each parameter (both for calls and returns) is a tuple with either 2 or 3 members:
	#   1. parameter name: the name of the parameter (duh)
	#   2. public type: the type used in the public RPC wrappers
	#   3. (optional) private type: the type used internally for serialization and for the server implementation.
	# if the private type (3) is omitted, it is the same as the public type.
	#
	# TYPES:
	# the types that can be used are normal C types. however, to be more architecture-agnostic,
	# it is recommended to use `stdint.h` types whenever possible (e.g. `int32_t` instead of `int`,
	# `uint64_t` instead of `unsigned long`, etc.).
	#
	# it is VERY IMPORTANT that pointer types ALWAYS have a distinct, fixed-size integral private type
	# that is wide enough to accommodate pointers for all architectures. a good choice is `uint64_t`;
	# NOT `uintptr_t`, as its size varies according to the architecture.
	#
	# SPECIAL TYPES:
	# one special type that is supported is `@fd`. this type indicates that the parameter specifies a file descriptor.
	# it will be treated as an `int` type-wise, but the RPC wrappers will perform some additional work on it
	# to serialize it across the connection. this works bi-directionally (i.e. both the client and server can send and receive FDs).
	# the resulting descriptor received on the other end (in either client or server) will behave like a `dup()`ed descriptor.
	#
	# FLAGS:
	#   XNU_TRAP_CALL
	#     this indicates that the given call is actually an XNU trap. this enables more advanced wrappers to be generated for that call
	#     and avoid unnecessary boilerplate code on the server side.
	#   XNU_TRAP_NOPREFIX
	#     this indicates that the XNU trap does not use the `_kernelrpc_` prefix on the server side.
	#     this affects both the function and argument structure names.
	#   XNU_TRAP_NOSUFFIX
	#     this indicates that the XNU trap does not use the `_trap` suffix on the server side.
	#     this affects both the function and argument structure names.
	#   XNU_TRAP_NOSUFFIX_ARGS
	#     this indicates the arguments structure for this call on the server side does not use the `_trap` suffix.
	#     this does not affect the name of the function on the server side.
	#   XNU_TRAP_BSD
	#     this indicates the XNU trap is for a BSD syscall. BSD syscalls have 2 return codes: one for failure and one for success.
	#     this flag informs the RPC wrapper generator about this so it can handle it appropriately.
	#   XNU_TRAP_NO_DTAPE_DEF
	#     by default, the RPC wrapper generator code will generate duct-tape wrappers for XNU traps that automatically call the
	#     XNU handler function for the trap. this flag tells it not to do that; this means you must define the duct-tape handler yourself.
	#   UNMANAGED_CALL
	#     this indicates that the given call may be called from an unmanaged process; that is, a process that the server does not manage or
	#     have direct access to (e.g. it cannot access its memory). this is mainly useful for calls that inspect the state of the container.
	#   ALLOW_INTERRUPTIONS
	#     by default, calls are performed atomically with signals disabled on the calling thread; this way, the call is either fully performed
	#     or fully unperformed. this flag indicates that the call should be allowed to be interrupted by signals. most calls should be performed
	#     without interruptions, but calls that may wait (usually for long periods of time) should be performed with interruptions allowed.
	#
	#     do note that this means callers may see the value of `dserver_rpc_hooks_get_interrupt_status()` on return and must handle it appropriately.
	#     this status is only returned when the RPC send operation is interrupted; when the RPC receive operation is interrupted, it is simply retried.
	#     thus, even when interruptions are allowed, callers should still see a consistent RPC state.
	#   PUSH_UNKNOWN_REPLIES
	#     the vast majority of calls should fail (spectacularly) when they receive an unexpected/unknown reply from the server.
	#     99% of the time, this is indicative of a critical RPC error. some calls (currently only one: interrupt_enter), however, need to gracefully handle
	#     mixed up replies because of race conditions.
	#
	#     for example, when a signal is received, interrupt_enter is called. sometimes, signals arrive while we're waiting for a reply from the server
	#     for another call. when the server receives interrupt_enter, it interrupts the current call and any reply it generates is deferred to be delivered
	#     once the server receives interrupt_exit. however, there is still a race condition here: if the server already had the reply to the interrupted
	#     call queued for delivery when the signal was received, the client will send interrupt_enter and immediately receive the reply to the interrupted
	#     call. without handling this gracefully (by saving the reply for later), RPC communication becomes desynchronized and the program crashes.
	#
	#     note that this flag should only be used in very special circumstances (interrupt_enter currently being the only such one).
	#     not only can it mask legitimate RPC communication errors, but it also requires significantly more stack space to handle such calls,
	#     as the wrapper must create a buffer large enough to store any possible reply (including any potential descriptors).
	#
	#     the way this works is that calls with this flag allocate enough space in the reply buffer to hold all possible replies;
	#     if they receive an unexpected reply, they push it back to the server. the server then holds on to the reply
	#     and re-sends it when appropriate (e.g. for interrupt_enter, that's after interrupt_exit is called).
	#
	# TODO: we should probably add a class for these calls (so it's more readable).
	#       we could even create a DSL (à-la-MIG), but that's probably overkill since
	#       we only use our RPC for darlingserver calls.
	#

	('checkin', [
		('is_fork', 'bool'),
		('stack_hint', 'void*', 'uint64_t'),
		('lifetime_listener_pipe', '@fd')
	], []),

	('checkout', [
		('exec_listener_pipe', '@fd'),
		('executing_macho', 'bool'),
	], []),

	('vchroot_path', [
		('buffer', 'char*', 'uint64_t'),
		('buffer_size', 'uint64_t'),
	], [
		('length', 'uint64_t'),
	]),

	('kprintf', [
		('string', 'const char*', 'uint64_t'),
		('string_length', 'uint64_t'),
	], []),

	('started_suspended', [], [
		('suspended', 'bool'),
	]),

	('get_tracer', [], [
		('tracer', 'int32_t'),
	]),

	('uidgid', [
		('new_uid', 'int32_t'),
		('new_gid', 'int32_t'),
	], [
		('old_uid', 'int32_t'),
		('old_gid', 'int32_t'),
	]),

	('set_thread_handles', [
		('pthread_handle', 'uint64_t'),
		('dispatch_qaddr', 'uint64_t'),
	], []),

	('vchroot', [
		('directory_fd', '@fd'),
	], []),

	('mldr_path', [
		('buffer', 'char*', 'uint64_t'),
		('buffer_size', 'uint64_t'),
	], [
		('length', 'uint64_t'),
	]),

	('fork_wait_for_child', [], [], ALLOW_INTERRUPTIONS),

	('sigprocess', [
		('bsd_signal_number', 'int32_t'),
		('linux_signal_number', 'int32_t'),
		('sender_pid', 'int32_t'),
		('code', 'int32_t'),
		('signal_address', 'uint64_t'),

		# these are in/out pointers
		('thread_state', 'uint64_t'),
		('float_state', 'uint64_t'),
	], [
		('new_bsd_signal_number', 'int32_t'),
	]),

	('task_is_64_bit', [
		('id', 'int32_t'),
	], [
		('is_64_bit', 'bool'),
	]),

	('interrupt_enter', [], [], PUSH_UNKNOWN_REPLIES),

	('interrupt_exit', [], []),

	('console_open', [], [
		('console', '@fd'),
	]),

	('set_dyld_info', [
		('address', 'uint64_t'),
		('length', 'uint64_t'),
	], []),

	('stop_after_exec', [], []),

	('set_tracer', [
		('target', 'int32_t'),
		('tracer', 'int32_t'),
	], []),

	('tid_for_thread', [
		('thread', 'uint32_t'),
	], [
		('tid', 'int32_t'),
	]),

	('ptrace_sigexc', [
		('target', 'int32_t'),
		('enabled', 'bool'),
	], []),

	('ptrace_thupdate', [
		('target', 'int32_t'),
		('signum', 'int32_t'),
	], []),

	('thread_suspended', [
		# these are in/out pointers
		('thread_state', 'uint64_t'),
		('float_state', 'uint64_t'),
	], []),

	('s2c_perform', [], []),

	('set_executable_path', [
		('buffer', 'const char*', 'uint64_t'),
		('buffer_size', 'uint64_t')
	], []),

	('get_executable_path', [
		('pid', 'int32_t'),
		('buffer', 'char*', 'uint64_t'),
		('buffer_size', 'uint64_t')
	], [
		('length', 'uint64_t'),
	]),

	('groups', [
		('new_groups', 'const uint32_t*', 'uint64_t'),
		('new_group_count', 'uint64_t'),
		('old_groups', 'uint32_t*', 'uint64_t'),
		('old_group_space', 'uint64_t'),
	], [
		('old_group_count', 'uint64_t'),
	]),

	#
	# kqueue channels
	#

	('kqchan_mach_port_open', [
		('port_name', 'uint32_t'),
		('receive_buffer', 'void*', 'uint64_t'),
		('receive_buffer_size', 'uint64_t'),
		('saved_filter_flags', 'uint64_t'),
	], [
		('socket', '@fd'),
	]),

	('kqchan_proc_open', [
		('pid', 'int32_t'),
		('flags', 'uint32_t'),
	], [
		('socket', '@fd'),
	]),

	#
	# pthread cancelation
	#

	('pthread_kill', [
		('thread_port', 'uint32_t'),
		('signal', 'int32_t'),
	], []),

	('pthread_canceled', [
		('action', 'int32_t'),
	], []),

	('pthread_markcancel', [
		('thread_port', 'uint32_t'),
	], []),

	#
	# Mach IPC traps
	#

	('task_self_trap', [], [
		('port_name', 'uint32_t'),
	]),

	('host_self_trap', [], [
		('port_name', 'uint32_t'),
	]),

	('thread_self_trap', [], [
		('port_name', 'uint32_t'),
	]),

	('mach_reply_port', [], [
		('port_name', 'uint32_t'),
	]),

	('thread_get_special_reply_port', [], [
		('port_name', 'uint32_t'),
	]),

	('mach_msg_overwrite', [
		('msg', 'void*', 'uint64_t'),
		('option', 'int32_t'),
		('send_size', 'uint32_t'),
		('rcv_size', 'uint32_t'),
		('rcv_name', 'uint32_t'),
		('timeout', 'uint32_t'),
		('priority', 'uint32_t'),
		('rcv_msg', 'void*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | ALLOW_INTERRUPTIONS),

	('mach_port_deallocate', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_allocate', [
		('target', 'uint32_t'),
		('right', 'int32_t'),

		# this would be better as a return parameter,
		# but due to the way darlingserver handles Mach IPC calls,
		# we need a pointer into the calling process's memory
		('name', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_mod_refs', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('right', 'int32_t'),
		('delta', 'int32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_move_member', [
		('target', 'uint32_t'),
		('member', 'uint32_t'),
		('after', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_insert_right', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('poly', 'uint32_t'),
		('polyPoly', 'int32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_insert_member', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('pset', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_extract_member', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('pset', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_construct', [
		('target', 'uint32_t'),
		('options', 'void*', 'uint64_t'),
		('context', 'uint64_t'),
		('name', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_destruct', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('srdelta', 'int32_t'),
		('guard', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_guard', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('guard', 'uint64_t'),
		('strict', 'bool'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_unguard', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('guard', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_request_notification', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('msgid', 'int32_t'),
		('sync', 'uint32_t'),
		('notify', 'uint32_t'),
		('notifyPoly', 'uint32_t'),
		('previous', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_get_attributes', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('flavor', 'int32_t'),
		('info', 'void*', 'uint64_t'),
		('count', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('mach_port_type', [
		('target', 'uint32_t'),
		('name', 'uint32_t'),
		('ptype', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	('task_for_pid', [
		('target_tport', 'uint32_t'),
		('pid', 'int32_t'),
		('t', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | XNU_TRAP_NOSUFFIX),

	('task_name_for_pid', [
		('target_tport', 'uint32_t'),
		('pid', 'int32_t'),
		('t', 'uint32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | XNU_TRAP_NOSUFFIX),

	('pid_for_task', [
		('t', 'uint32_t'),
		('pid', 'int32_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | XNU_TRAP_NOSUFFIX),

	#
	# Mach VM traps
	#

	('mach_vm_allocate', [
		('target', 'uint32_t'),
		('addr', 'uint64_t*', 'uint64_t'),
		('size', 'uint64_t'),
		('flags', 'int32_t'),
	], [], XNU_TRAP_CALL),

	('mach_vm_deallocate', [
		('target', 'uint32_t'),
		('address', 'uint64_t'),
		('size', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOSUFFIX_ARGS),

	#
	# Mach semaphore traps
	#

	('semaphore_signal', [
		('signal_name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('semaphore_signal_all', [
		('signal_name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('semaphore_wait', [
		('wait_name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | ALLOW_INTERRUPTIONS),

	('semaphore_wait_signal', [
		('wait_name', 'uint32_t'),
		('signal_name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | ALLOW_INTERRUPTIONS),

	('semaphore_timedwait', [
		('wait_name', 'uint32_t'),
		('sec', 'uint32_t'),
		('nsec', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | ALLOW_INTERRUPTIONS),

	('semaphore_timedwait_signal', [
		('wait_name', 'uint32_t'),
		('signal_name', 'uint32_t'),
		('sec', 'uint32_t'),
		('nsec', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX | ALLOW_INTERRUPTIONS),

	#
	# mk_timer traps
	#

	('mk_timer_create', [], [
		('port_name', 'uint32_t'),
	]),

	('mk_timer_destroy', [
		('name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('mk_timer_arm', [
		('name', 'uint32_t'),
		('expire_time', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('mk_timer_cancel', [
		('name', 'uint32_t'),
		('result_time', 'uint64_t*', 'uint64_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	#
	# psynch calls
	#

	('psynch_cvbroad', [
		('cv', 'uint64_t'),
		('cvlsgen', 'uint64_t'),
		('cvudgen', 'uint64_t'),
		('flags', 'uint32_t'),
		('mutex', 'uint64_t'),
		('mugen', 'uint64_t'),
		('tid', 'uint64_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF),

	('psynch_cvclrprepost', [
		('cv', 'uint64_t'),
		('cvgen', 'uint32_t'),
		('cvugen', 'uint32_t'),
		('cvsgen', 'uint32_t'),
		('prepocnt', 'uint32_t'),
		('preposeq', 'uint32_t'),
		('flags', 'uint32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF),

	('psynch_cvsignal', [
		('cv', 'uint64_t'),
		('cvlsgen', 'uint64_t'),
		('cvugen', 'uint32_t'),
		('threadport', 'int32_t'),
		('mutex', 'uint64_t'),
		('mugen', 'uint64_t'),
		('tid', 'uint64_t'),
		('flags', 'uint32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF),

	('psynch_cvwait', [
		('cv', 'uint64_t'),
		('cvlsgen', 'uint64_t'),
		('cvugen', 'uint32_t'),
		('mutex', 'uint64_t'),
		('mugen', 'uint64_t'),
		('flags', 'uint32_t'),
		('sec', 'int64_t'),
		('nsec', 'uint32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF | ALLOW_INTERRUPTIONS),

	('psynch_mutexdrop', [
		('mutex', 'uint64_t'),
		('mgen', 'uint32_t'),
		('ugen', 'uint32_t'),
		('tid', 'uint64_t'),
		('flags', 'uint32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF),

	('psynch_mutexwait', [
		('mutex', 'uint64_t'),
		('mgen', 'uint32_t'),
		('ugen', 'uint32_t'),
		('tid', 'uint64_t'),
		('flags', 'uint32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF | ALLOW_INTERRUPTIONS),

	('psynch_rw_rdlock', [
		('rwlock', 'uint64_t'),
		('lgenval', 'uint32_t'),
		('ugenval', 'uint32_t'),
		('rw_wc', 'uint32_t'),
		('flags', 'int32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF | ALLOW_INTERRUPTIONS),

	('psynch_rw_unlock', [
		('rwlock', 'uint64_t'),
		('lgenval', 'uint32_t'),
		('ugenval', 'uint32_t'),
		('rw_wc', 'uint32_t'),
		('flags', 'int32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF),

	('psynch_rw_wrlock', [
		('rwlock', 'uint64_t'),
		('lgenval', 'uint32_t'),
		('ugenval', 'uint32_t'),
		('rw_wc', 'uint32_t'),
		('flags', 'int32_t'),
	], [
		('retval', 'uint32_t'),
	], XNU_BSD_TRAP_CALL | XNU_TRAP_NO_DTAPE_DEF | ALLOW_INTERRUPTIONS),
]

ALLOWED_PRIVATE_TYPES = [
	'bool',
	'int8_t',
	'uint8_t',
	'int16_t',
	'uint16_t',
	'int32_t',
	'uint32_t',
	'int64_t',
	'uint64_t',
]

def parse_type(param_tuple, is_public):
	type_str = param_tuple[1].strip()

	if type_str == '@fd':
		type_str = 'int' if is_public else 'int32_t'
	else:
		if not is_public and len(param_tuple) > 2:
			type_str = param_tuple[2].strip()

	if not is_public and type_str not in ALLOWED_PRIVATE_TYPES:
		raise ValueError('Invalid private type: ' + type_str)

	return type_str

# we have to specify alignment for structures members greater than 4 bytes wide because on 32-bit architectures,
# these are 4-byte aligned, but on 64-bit architectures, these are 8-byte aligned. however, we want the same structure
# definitions across architectures, so we specify 8-byte alignment for 8-byte types.

def alignment_for_type(type):
	if type == 'int64_t' or type == 'uint64_t':
		return 8
	else:
		return 0

def alignment_str_for_type(type):
	alignment = alignment_for_type(type)
	if alignment > 0:
		return ' __attribute__((aligned(' + str(alignment) + ')))'
	else:
		return ''

def is_fd(param_tuple):
	return param_tuple[1] == '@fd'

if len(sys.argv) < 5:
	sys.exit("Usage: " + sys.argv[0] + " <public-header-path> <internal-header-path> <library-source-path> <library-import>")

os.makedirs(os.path.dirname(sys.argv[1]), exist_ok=True)
os.makedirs(os.path.dirname(sys.argv[2]), exist_ok=True)
os.makedirs(os.path.dirname(sys.argv[3]), exist_ok=True)

def to_camel_case(snake_str):
	components = snake_str.split('_')
	return ''.join(x.title() for x in components)

public_header = open(sys.argv[1], "w")
internal_header = open(sys.argv[2], "w")
library_source = open(sys.argv[3], "w")
library_import = sys.argv[4]

license_header = """\
// This file has been auto-generated by generate-rpc-wrappers.py for use with darlingserver

/**
 * This file is part of Darling.
 *
 * Copyright (C) {} Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

""".format(datetime.now().year)

public_header.write(license_header)
library_source.write(license_header)
internal_header.write(license_header)

public_header.write("""\
#ifndef _DARLINGSERVER_API_H_
#define _DARLINGSERVER_API_H_

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

""")

public_header.write("#define DSERVER_CALL_UNMANAGED_FLAG 0x80000000U\n\n")
public_header.write("enum dserver_callnum {\n")
# "52ccall" -> "s2c call"
public_header.write("\tdserver_callnum_s2c = 0x52cca11,\n")
public_header.write("\tdserver_callnum_push_reply = 0xbadca11,\n")
public_header.write("\tdserver_callnum_invalid = 0,\n")
idx = 1
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	flags = call[3] if len(call) >= 4 else 0

	debug_flag = ""

	if (flags & UNMANAGED_CALL) != 0:
		debug_flag = "DSERVER_CALL_UNMANAGED_FLAG | "

	public_header.write("\tdserver_callnum_" + call_name + " = " + debug_flag + str(idx) + "U,\n")

	idx += 1
public_header.write("};\n")

public_header.write("""\

typedef enum dserver_callnum dserver_callnum_t;

#ifndef DSERVER_RPC_HOOKS_ARCHITECTURE
#define DSERVER_RPC_HOOKS_ARCHITECTURE 1
enum dserver_rpc_architecture {
	dserver_rpc_architecture_invalid,
	dserver_rpc_architecture_i386,
	dserver_rpc_architecture_x86_64,
	dserver_rpc_architecture_arm32,
	dserver_rpc_architecture_arm64,
};

typedef enum dserver_rpc_architecture dserver_rpc_architecture_t;
#endif

typedef struct dserver_rpc_callhdr {
	dserver_callnum_t number;
	pid_t pid;
	pid_t tid;
	dserver_rpc_architecture_t architecture;
} dserver_rpc_callhdr_t;

typedef struct dserver_rpc_replyhdr {
	dserver_callnum_t number;
	int code;
} dserver_rpc_replyhdr_t;

typedef struct dserver_rpc_call_push_reply {
	dserver_rpc_callhdr_t header;
	uint64_t reply;
	uint64_t reply_size;
} dserver_rpc_call_push_reply_t;

""")

library_source.write("""\
#include {}
#include <darlingserver/rpc-supplement.h>

#if !defined(dserver_rpc_hooks_msghdr_t) || !defined(dserver_rpc_hooks_iovec_t) || !defined(dserver_rpc_hooks_cmsghdr_t) || !defined(DSERVER_RPC_HOOKS_CMSG_SPACE) || !defined(DSERVER_RPC_HOOKS_CMSG_FIRSTHDR) || !defined(DSERVER_RPC_HOOKS_SOL_SOCKET) || !defined(DSERVER_RPC_HOOKS_SCM_RIGHTS) || !defined(DSERVER_RPC_HOOKS_CMSG_LEN) || !defined(DSERVER_RPC_HOOKS_CMSG_DATA) || !defined(DSERVER_RPC_HOOKS_ATTRIBUTE) || !defined(dserver_rpc_hooks_atomic_save_t)
	#error Missing definitions
#endif

#ifndef dserver_rpc_hooks_get_pid
DSERVER_RPC_HOOKS_ATTRIBUTE pid_t dserver_rpc_hooks_get_pid(void);
#endif

#ifndef dserver_rpc_hooks_get_tid
DSERVER_RPC_HOOKS_ATTRIBUTE pid_t dserver_rpc_hooks_get_tid(void);
#endif

#ifndef dserver_rpc_hooks_get_architecture
DSERVER_RPC_HOOKS_ATTRIBUTE dserver_rpc_architecture_t dserver_rpc_hooks_get_architecture(void);
#endif

#ifndef dserver_rpc_hooks_get_server_address
DSERVER_RPC_HOOKS_ATTRIBUTE void* dserver_rpc_hooks_get_server_address(void);
#endif

#ifndef dserver_rpc_hooks_get_server_address_length
DSERVER_RPC_HOOKS_ATTRIBUTE size_t dserver_rpc_hooks_get_server_address_length(void);
#endif

#ifndef dserver_rpc_hooks_memcpy
DSERVER_RPC_HOOKS_ATTRIBUTE void* dserver_rpc_hooks_memcpy(void* destination, const void* source, size_t length);
#endif

#ifndef dserver_rpc_hooks_send_message
DSERVER_RPC_HOOKS_ATTRIBUTE long int dserver_rpc_hooks_send_message(int socket, const dserver_rpc_hooks_msghdr_t* message);
#endif

#ifndef dserver_rpc_hooks_receive_message
DSERVER_RPC_HOOKS_ATTRIBUTE long int dserver_rpc_hooks_receive_message(int socket, dserver_rpc_hooks_msghdr_t* out_message);
#endif

#ifndef dserver_rpc_hooks_get_bad_message_status
DSERVER_RPC_HOOKS_ATTRIBUTE int dserver_rpc_hooks_get_bad_message_status(void);
#endif

#ifndef dserver_rpc_hooks_get_communication_error_status
DSERVER_RPC_HOOKS_ATTRIBUTE int dserver_rpc_hooks_get_communication_error_status(void);
#endif

#ifndef dserver_rpc_hooks_get_broken_pipe_status
DSERVER_RPC_HOOKS_ATTRIBUTE int dserver_rpc_hooks_get_broken_pipe_status(void);
#endif

#ifndef dserver_rpc_hooks_close_fd
DSERVER_RPC_HOOKS_ATTRIBUTE void dserver_rpc_hooks_close_fd(int fd);
#endif

#ifndef dserver_rpc_hooks_get_socket
DSERVER_RPC_HOOKS_ATTRIBUTE int dserver_rpc_hooks_get_socket(void);
#endif

#ifndef dserver_rpc_hooks_printf
DSERVER_RPC_HOOKS_ATTRIBUTE void dserver_rpc_hooks_printf(const char* format, ...);
#endif

#ifndef dserver_rpc_hooks_atomic_begin
DSERVER_RPC_HOOKS_ATTRIBUTE void dserver_rpc_hooks_atomic_begin(dserver_rpc_hooks_atomic_save_t* atomic_save);
#endif

#ifndef dserver_rpc_hooks_atomic_end
DSERVER_RPC_HOOKS_ATTRIBUTE void dserver_rpc_hooks_atomic_end(dserver_rpc_hooks_atomic_save_t* atomic_save);
#endif

#ifndef dserver_rpc_hooks_get_interrupt_status
DSERVER_RPC_HOOKS_ATTRIBUTE int dserver_rpc_hooks_get_interrupt_status(void);
#endif

#ifndef dserver_rpc_hooks_push_reply
DSERVER_RPC_HOOKS_ATTRIBUTE void dserver_rpc_hooks_push_reply(int socket, const dserver_rpc_hooks_msghdr_t* message, size_t size);
#endif

""".format(library_import))

internal_header.write("#define DSERVER_VALID_CALLNUM_CASES \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]

	internal_header.write("\tcase dserver_callnum_" + call_name + ": \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_CONSTRUCT_CASES \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	camel_name = to_camel_case(call_name)

	internal_header.write("\tCALL_CASE(" + call_name + ", " + camel_name + "); \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_ENUM_VALUES \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	camel_name = to_camel_case(call_name)

	internal_header.write("\t" + camel_name + " = dserver_callnum_" + call_name + ", \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_CLASS_DECLS \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	camel_name = to_camel_case(call_name)

	internal_header.write("\tclass " + camel_name + "; \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_CLASS_DEFS \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	flags = call[3] if len(call) >= 4 else 0
	camel_name = to_camel_case(call_name)
	fd_count_in_reply = 0

	internal_header.write(textwrap.indent(textwrap.dedent("""\
		class Call::{1}: public Call, public std::enable_shared_from_this<Call::{1}> {{ \\
			friend class Call; \\
		private: \\
			{2}
		public: \\
			{1}(std::shared_ptr<Thread> thread, dserver_rpc_call_{0}_t* data, Message&& requestMessage): \\
				Call(thread, requestMessage.address(), reinterpret_cast<dserver_rpc_callhdr_t*>(data)){3} \\
				{4}
			{{ \\
		"""), '\t').format(
			call_name,
			camel_name,
			("dserver_call_" + call_name + "_t _body; \\") if len(call_parameters) > 0 else "\\",
			"," if len(call_parameters) > 0 else "",
			"_body(data->body) \\" if len(call_parameters) > 0 else "\\"
		)
	)

	for param in call_parameters:
		param_name = param[0]

		if not is_fd(param):
			continue

		internal_header.write("\t\t\t_body." + param_name + " = requestMessage.extractDescriptorAtIndex(_body." + param_name + "); \\\n")
	internal_header.write("\t\t}; \\\n")

	internal_header.write("\t\t~" + camel_name + "() { \\\n")
	for param in call_parameters:
		param_name = param[0]

		if not is_fd(param):
			continue

		internal_header.write("\t\t\tif (_body." + param_name + " != -1) { \\\n")
		internal_header.write("\t\t\t\tclose(_body." + param_name + "); \\\n")
		internal_header.write("\t\t} \\\n")

	internal_header.write(textwrap.indent(textwrap.dedent("""\
			}}; \\
			virtual Call::Number number() const override {{ \\
				return Call::Number::{0}; \\
			}}; \\
			virtual void processCall() override; \\
		private: \\
		"""), '\t').format(camel_name))

	internal_header.write("\t\tvoid _sendReply(int resultCode")
	for param in reply_parameters:
		param_name = param[0]

		if is_fd(param):
			fd_count_in_reply += 1

		internal_header.write(", " + parse_type(param, False) + " " + param_name)
	internal_header.write(") { \\\n")

	internal_header.write("\t\t\trpcReplyLog.debug() << \"Replying to call #\" << dserver_callnum_" + call_name + " << \" (dserver_callnum_" + call_name + ") from PID \" << _header.pid << \", TID \" << _header.tid << \" with result code \" << resultCode ")

	for param in reply_parameters:
		param_name = param[0]

		internal_header.write("<< \", " + param_name + "=\" << " + param_name + " ")

	internal_header.write("<< rpcReplyLog.endLog; \\\n")

	internal_header.write(textwrap.indent(textwrap.dedent("""\
		Message reply(sizeof(dserver_rpc_reply_{0}_t), 0); \\
		int fdIndex = 0; \\
		reply.setAddress(_replyAddress); \\
		auto replyStruct = reinterpret_cast<dserver_rpc_reply_{0}_t*>(reply.data().data()); \\
		replyStruct->header.number = dserver_callnum_{0}; \\
		replyStruct->header.code = resultCode; \\
		"""), '\t\t\t').format(call_name))

	fd_index = 0
	for param in reply_parameters:
		param_name = param[0]
		val = param_name

		if is_fd(param):
			val = "((" + param_name + " >= 0) ? (fdIndex++) : (-1))"
			internal_header.write("\t\t\tif (" + param_name + " >= 0) { \\\n")
			internal_header.write("\t\t\t\treply.pushDescriptor(" + param_name + "); \\\n")
			internal_header.write("\t\t\t} \\\n")

		internal_header.write("\t\t\treplyStruct->body." + param_name + " = " + val + "; \\\n")
	internal_header.write("\t\t\tif (auto thread = _thread.lock()) { \\\n")
	internal_header.write("\t\t\t\tthread->pushCallReply(shared_from_this(), std::move(reply)); \\\n")
	internal_header.write("\t\t\t} else { \\\n")
	internal_header.write("\t\t\t\tCall::sendReply(std::move(reply)); \\\n")
	internal_header.write("\t\t\t} \\\n")
	internal_header.write("\t\t}; \\\n")

	if len(reply_parameters) == 0:
		internal_header.write("\tpublic: \\\n")
		internal_header.write("\t\tvoid sendBasicReply(int resultCode) override { \\\n")
		internal_header.write("\t\t\t_sendReply(resultCode); \\\n")
		internal_header.write("\t\t}; \\\n")

	if (flags & XNU_TRAP_CALL) != 0:
		internal_header.write("\t\tbool isXNUTrap() const override { \\\n")
		internal_header.write("\t\t\treturn true; \\\n")
		internal_header.write("\t\t}; \\\n")

	if (flags & XNU_TRAP_BSD) != 0:
		internal_header.write("\t\tbool isBSDTrap() const override { \\\n")
		internal_header.write("\t\t\treturn true; \\\n")
		internal_header.write("\t\t}; \\\n")
		internal_header.write("\t\tvoid sendBSDReply(int resultCode, uint32_t returnValue) override { \\\n")
		internal_header.write("\t\t\t_sendReply(resultCode, returnValue); \\\n")
		internal_header.write("\t\t}; \\\n")

	internal_header.write("\t}; \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_CLASS_SOURCE_DEFS \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	flags = call[3] if len(call) >= 4 else 0
	camel_name = to_camel_case(call_name)

	if (flags & XNU_TRAP_CALL) == 0:
		continue

	# XNU traps return values by writing directly to the calling process's memory at the addresses given as regular call parameters
	if (flags & XNU_TRAP_BSD) != 0:
		if len(reply_parameters) != 1:
			raise RuntimeError("Call marked as a BSD trap does not have exactly 1 reply parameter")
	elif len(reply_parameters) > 0:
		raise RuntimeError("Call marked as an XNU trap has reply parameters")

	internal_header.write("\tvoid DarlingServer::Call::{0}::processCall() {{ \\\n".format(camel_name))

	if (flags & XNU_TRAP_BSD) != 0:
		internal_header.write("\t\tuint32_t* retvalPointer = nullptr; \\\n")
		internal_header.write("\t\t{ \\\n")
		internal_header.write("\t\t\tif (auto thread = _thread.lock()) { \\\n")
		internal_header.write("\t\t\t\tretvalPointer = thread->bsdReturnValuePointer(); \\\n")
		internal_header.write("\t\t\t} \\\n")
		internal_header.write("\t\t}; \\\n")

	internal_header.write("\t\tThread::syscallReturn(dtape_{0}(".format(call_name))

	is_first = True
	for param in call_parameters:
		param_name = param[0]

		if is_first:
			is_first = False
		else:
			internal_header.write(", ")

		internal_header.write("_body.{0}".format(param_name))

	if (flags & XNU_TRAP_BSD) != 0:
		if not is_first:
			internal_header.write(", ")
		internal_header.write("retvalPointer")

	internal_header.write(")); \\\n")
	internal_header.write("\t}; \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_DTAPE_DECLS \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	flags = call[3] if len(call) >= 4 else 0
	camel_name = to_camel_case(call_name)

	if (flags & XNU_TRAP_CALL) == 0:
		continue

	internal_header.write("\tint dtape_{0}(".format(call_name))

	is_first = True
	for param in call_parameters:
		param_name = param[0]

		if is_first:
			is_first = False
		else:
			internal_header.write(", ")

		internal_header.write("{0} {1}".format(parse_type(param, False), param_name))

	if (flags & XNU_TRAP_BSD) != 0:
		if not is_first:
			internal_header.write(", ")
		internal_header.write("uint32_t* retval")

	internal_header.write("); \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_DTAPE_DEFS \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	flags = call[3] if len(call) >= 4 else 0
	camel_name = to_camel_case(call_name)

	if (flags & XNU_TRAP_CALL) == 0 or (flags & XNU_TRAP_NO_DTAPE_DEF) != 0:
		continue

	trap_name = call_name
	if (flags & XNU_TRAP_NOPREFIX) == 0:
		trap_name = "_kernelrpc_" + trap_name
	if (flags & XNU_TRAP_NOSUFFIX) == 0:
		trap_name = trap_name + "_trap"

	trap_args_name = call_name
	if (flags & XNU_TRAP_NOPREFIX) == 0:
		trap_args_name = "_kernelrpc_" + trap_args_name
	if (flags & (XNU_TRAP_NOSUFFIX | XNU_TRAP_NOSUFFIX_ARGS)) == 0:
		trap_args_name = trap_args_name + "_trap"

	internal_header.write("\tint dtape_{0}(".format(call_name))

	is_first = True
	for param in call_parameters:
		param_name = param[0]

		if is_first:
			is_first = False
		else:
			internal_header.write(", ")

		internal_header.write("{0} {1}".format(parse_type(param, False), param_name))

	internal_header.write(") { \\\n")
	internal_header.write("\t\tstruct {0}_args args = {{ \\\n".format(trap_args_name))

	for param in call_parameters:
		param_name = param[0]
		internal_header.write("\t\t\t.{0} = {0}, \\\n".format(param_name))

	internal_header.write("\t\t}; \\\n")
	internal_header.write("\t\treturn {0}(&args); \\\n".format(trap_name))
	internal_header.write("\t}; \\\n")
internal_header.write("\n")

public_header.write("__attribute__((always_inline)) static const char* dserver_callnum_to_string(dserver_callnum_t callnum) {\n")
public_header.write("\tswitch (callnum) {\n")
public_header.write("\t\tcase dserver_callnum_s2c: return \"dserver_callnum_s2c\";\n")
public_header.write("\t\tcase dserver_callnum_push_reply: return \"dserver_callnum_push_reply\";\n")
for call in calls:
	call_name = call[0]
	public_header.write("\t\tcase dserver_callnum_" + call_name + ": return \"dserver_callnum_" + call_name + "\";\n")
public_header.write("\t\tdefault: return (const char*)0;\n")
public_header.write("\t}\n")
public_header.write("};\n\n")

max_call_fd_count = 0
max_reply_fd_count = 0
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	fd_count_in_call = 0
	fd_count_in_reply = 0
	flags = call[3] if len(call) >= 4 else 0
	for param in call_parameters:
		if is_fd(param):
			fd_count_in_call += 1
	for param in reply_parameters:
		if is_fd(param):
			fd_count_in_reply += 1
	if fd_count_in_call > max_call_fd_count:
		max_call_fd_count = fd_count_in_call
	if fd_count_in_reply > max_reply_fd_count:
		max_reply_fd_count = fd_count_in_reply

for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	fd_count_in_call = 0
	fd_count_in_reply = 0
	flags = call[3] if len(call) >= 4 else 0

	# define the RPC call body structure
	if len(call_parameters) > 0:
		public_header.write("typedef struct dserver_call_" + call_name + " dserver_call_" + call_name + "_t;\n")
		public_header.write("struct dserver_call_" + call_name + " {\n")
		for param in call_parameters:
			param_name = param[0]

			if is_fd(param):
				fd_count_in_call += 1

			parsed_type = parse_type(param, False)
			public_header.write("\t" + parsed_type + " " + param_name + alignment_str_for_type(parsed_type) + ";\n")
		public_header.write("};\n")

	# define the RPC call structure
	public_header.write(textwrap.dedent("""\
		typedef struct dserver_rpc_call_{0} dserver_rpc_call_{0}_t;
		struct dserver_rpc_call_{0} {{
			dserver_rpc_callhdr_t header;
		""").format(call_name))
	if len(call_parameters) > 0:
		public_header.write("\tdserver_call_" + call_name + "_t body;\n")
	public_header.write("};\n")

	# define the RPC reply body structure
	if len(reply_parameters) > 0:
		public_header.write("typedef struct dserver_reply_" + call_name + " dserver_reply_" + call_name + "_t;\n")
		public_header.write("struct dserver_reply_" + call_name + " {\n")
		for param in reply_parameters:
			param_name = param[0]

			if is_fd(param):
				fd_count_in_reply += 1

			parsed_type = parse_type(param, False)
			public_header.write("\t" + parsed_type + " " + param_name + alignment_str_for_type(parsed_type) + ";\n")
		public_header.write("};\n")

	# define the RPC reply structure
	public_header.write(textwrap.dedent("""\
		typedef struct dserver_rpc_reply_{0} dserver_rpc_reply_{0}_t;
		struct dserver_rpc_reply_{0} {{
			dserver_rpc_replyhdr_t header;
		""").format(call_name))
	if len(reply_parameters) > 0:
		public_header.write("\tdserver_reply_" + call_name + "_t body;\n")
	public_header.write("};\n")

	tmp = "int dserver_rpc_explicit_" + call_name + "(int server_socket"
	public_header.write(tmp)
	library_source.write(tmp)
	for param in call_parameters:
		param_name = param[0]

		tmp = ", "
		tmp += parse_type(param, True) + " " + param_name
		public_header.write(tmp)
		library_source.write(tmp)

	for param in reply_parameters:
		param_name = param[0]

		tmp = ", "
		tmp += parse_type(param, True) + "* out_" + param_name
		public_header.write(tmp)
		library_source.write(tmp)
	public_header.write(");\n\n")
	library_source.write(") {\n")

	# define the RPC call wrapper function
	library_source.write(textwrap.indent(textwrap.dedent("""\
		dserver_rpc_call_{0}_t call = {{
			.header = {{
				.architecture = dserver_rpc_hooks_get_architecture(),
				.pid = dserver_rpc_hooks_get_pid(),
				.tid = dserver_rpc_hooks_get_tid(),
				.number = dserver_callnum_{0},
			}},
		"""), '\t').format(call_name))

	if len(call_parameters) > 0:
		library_source.write("\t\t.body = {\n")
		fd_index = 0
		for param in call_parameters:
			param_name = param[0]
			val = param_name

			if is_fd(param):
				val = "(" + param_name + " < 0) ? -1 : " + str(fd_index)
				fd_index += 1

			# On recent versions of clang, the compiler will throw out an error if there is
			# a mismatch with certain integer types. 
			if len(param) > 2: 
				val = "(" + param[2] + ")" + val

			library_source.write("\t\t\t." + param_name + " = " + val + ",\n")
		library_source.write("\t\t},\n")

	library_source.write("\t};\n")
	library_source.write("\tunion {\n")
	library_source.write("\t\tdserver_rpc_reply_" + call_name + "_t reply;\n")
	library_source.write("\t\tdserver_s2c_call_t s2c;\n")

	# make room for any potetial replies if we need to handle unexpected replies
	if (flags & PUSH_UNKNOWN_REPLIES) != 0:
		for other_call in calls:
			other_call_name = other_call[0]
			other_call_parameters = other_call[1]
			other_reply_parameters = other_call[2]
			other_fd_count_in_reply = 0
			other_flags = other_call[3] if len(other_call) >= 4 else 0
			library_source.write("\t\tdserver_rpc_reply_" + other_call_name + "_t potential_reply_" + other_call_name + ";\n")

	library_source.write("\t} reply_msg;\n")

	# we always allocate space for at least one FD, since S2C calls might send a descriptor
	library_source.write("\tint fds[" + str(max(1, fd_count_in_call, fd_count_in_reply, max_reply_fd_count if (flags & PUSH_UNKNOWN_REPLIES) != 0 else 0)) + "];\n")
	library_source.write("\tint valid_fd_count;\n")
	library_source.write("\tchar controlbuf[DSERVER_RPC_HOOKS_CMSG_SPACE(sizeof(fds))];\n")

	if fd_count_in_call > 0:
		library_source.write("\tvalid_fd_count = 0;\n")
		for param in call_parameters:
			param_name = param[0]

			if not is_fd(param):
				continue

			library_source.write("\tif (" + param_name + " >= 0) {\n")
			library_source.write("\t\tfds[valid_fd_count++] = " + param_name + ";\n")
			library_source.write("\t}\n")

	library_source.write(textwrap.indent(textwrap.dedent("""\
		dserver_rpc_hooks_iovec_t call_data = {
			.iov_base = &call,
			.iov_len = sizeof(call),
		};
		dserver_rpc_hooks_msghdr_t callmsg = {
			.msg_name = dserver_rpc_hooks_get_server_address(),
			.msg_namelen = dserver_rpc_hooks_get_server_address_length(),
			.msg_iov = &call_data,
			.msg_iovlen = 1,
		"""), '\t'))

	if fd_count_in_call == 0:
		library_source.write("\t\t.msg_control = NULL,\n")
		library_source.write("\t\t.msg_controllen = 0,\n")
	else:
		library_source.write("\t\t.msg_control = (valid_fd_count > 0) ? controlbuf : NULL,\n")
		library_source.write("\t\t.msg_controllen = (valid_fd_count > 0) ? sizeof(controlbuf) : 0,\n")

	library_source.write("\t};\n")

	if fd_count_in_call > 0:
		library_source.write(textwrap.indent(textwrap.dedent("""\
			if (valid_fd_count > 0) {
				dserver_rpc_hooks_cmsghdr_t* call_cmsg = DSERVER_RPC_HOOKS_CMSG_FIRSTHDR(&callmsg);
				call_cmsg->cmsg_level = DSERVER_RPC_HOOKS_SOL_SOCKET;
				call_cmsg->cmsg_type = DSERVER_RPC_HOOKS_SCM_RIGHTS;
				call_cmsg->cmsg_len = DSERVER_RPC_HOOKS_CMSG_LEN(sizeof(int) * valid_fd_count);
				dserver_rpc_hooks_memcpy(DSERVER_RPC_HOOKS_CMSG_DATA(call_cmsg), fds, sizeof(int) * valid_fd_count);
			}
			"""), '\t'))

	library_source.write(textwrap.indent(textwrap.dedent("""\
		dserver_rpc_hooks_iovec_t reply_data = {
			.iov_base = &reply_msg,
			.iov_len = sizeof(reply_msg),
		};
		dserver_rpc_hooks_msghdr_t replymsg = {
			.msg_name = NULL,
			.msg_namelen = 0,
			.msg_iov = &reply_data,
			.msg_iovlen = 1,
			.msg_control = controlbuf,
			.msg_controllen = sizeof(controlbuf),
		"""), '\t'))

	library_source.write("\t};\n\n")

	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\tdserver_rpc_hooks_atomic_save_t atomic_save;\n")
		library_source.write("\tdserver_rpc_hooks_atomic_begin(&atomic_save);\n\n")

	library_source.write("\tlong int long_status;\n\n")

	library_source.write("retry_send:\n")
	library_source.write("\tlong_status = dserver_rpc_hooks_send_message(server_socket, &callmsg);\n\n")

	library_source.write("\tif (long_status == dserver_rpc_hooks_get_interrupt_status()) {\n")
	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\t\tgoto retry_send;\n")
	else:
		library_source.write("\t\treturn (int)long_status;\n")
	library_source.write("\t}\n\n")

	library_source.write("\tif (long_status < 0) {\n")
	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\t\tdserver_rpc_hooks_atomic_end(&atomic_save);\n")
	library_source.write("\t\tdserver_rpc_hooks_printf(\"*** %d:%d: %s: BAD SEND STATUS: %ld ***\\n\", dserver_rpc_hooks_get_pid(), dserver_rpc_hooks_get_tid(), __func__, long_status);\n")
	library_source.write("\t\treturn (int)long_status;\n")
	library_source.write("\t}\n\n")

	library_source.write("\tif (long_status != sizeof(call)) {\n")
	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\t\tdserver_rpc_hooks_atomic_end(&atomic_save);\n")
	library_source.write("\t\tdserver_rpc_hooks_printf(\"*** %d:%d: %s: BAD SEND LENGTH: %ld (expected %zu) ***\\n\", dserver_rpc_hooks_get_pid(), dserver_rpc_hooks_get_tid(), __func__, long_status, sizeof(call));\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_communication_error_status();\n")
	library_source.write("\t}\n\n")

	library_source.write("retry_receive:\n")
	library_source.write("\tlong_status = dserver_rpc_hooks_receive_message(server_socket, &replymsg);\n\n")

	library_source.write("\tif (long_status == dserver_rpc_hooks_get_interrupt_status()) {\n")
	library_source.write("\t\tgoto retry_receive;\n")
	library_source.write("\t}\n\n")
	
	library_source.write("\tif (long_status < 0) {\n")
	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\t\tdserver_rpc_hooks_atomic_end(&atomic_save);\n")
	library_source.write("\t\tdserver_rpc_hooks_printf(\"*** %d:%d: %s: BAD RECEIVE STATUS: %ld ***\\n\", dserver_rpc_hooks_get_pid(), dserver_rpc_hooks_get_tid(), __func__, long_status);\n")
	library_source.write("\t\treturn (int)long_status;\n")
	library_source.write("\t}\n\n")

	library_source.write("\tif (long_status < sizeof(dserver_rpc_replyhdr_t)) {\n")
	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\t\tdserver_rpc_hooks_atomic_end(&atomic_save);\n")
	library_source.write("\t\tdserver_rpc_hooks_printf(\"*** %d:%d: %s: BAD RECEIVE MESSAGE: length=%ld (expected %zu) ***\\n\", dserver_rpc_hooks_get_pid(), dserver_rpc_hooks_get_tid(), __func__, long_status, sizeof(reply_msg.reply));\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_communication_error_status();\n")
	library_source.write("\t}\n\n")

	library_source.write("\tif (reply_msg.reply.header.number != dserver_callnum_" + call_name + ") {\n")
	if (flags & PUSH_UNKNOWN_REPLIES) != 0:
		library_source.write("\t\tdserver_rpc_hooks_push_reply(server_socket, &replymsg, long_status);\n")
		library_source.write("\t\tgoto retry_receive;\n")
	else:
		if (flags & ALLOW_INTERRUPTIONS) == 0:
			library_source.write("\t\tdserver_rpc_hooks_atomic_end(&atomic_save);\n")
		library_source.write("\t\tdserver_rpc_hooks_printf(\"*** %d:%d: %s: BAD RECEIVE MESSAGE: number=%d (expected %d), code=%d, length=%ld (expected %zu) ***\\n\", dserver_rpc_hooks_get_pid(), dserver_rpc_hooks_get_tid(), __func__, reply_msg.reply.header.number, dserver_callnum_" + call_name + ", reply_msg.reply.header.code, long_status, sizeof(reply_msg.reply));\n")
		library_source.write("\t\treturn dserver_rpc_hooks_get_communication_error_status();\n")
	library_source.write("\t}\n\n")

	library_source.write("\tif (long_status != sizeof(reply_msg.reply)) {\n")
	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\t\tdserver_rpc_hooks_atomic_end(&atomic_save);\n")
	library_source.write("\t\tdserver_rpc_hooks_printf(\"*** %d:%d: %s: BAD RECEIVE MESSAGE: number=%d (expected %d), code=%d, length=%ld (expected %zu) ***\\n\", dserver_rpc_hooks_get_pid(), dserver_rpc_hooks_get_tid(), __func__, reply_msg.reply.header.number, dserver_callnum_" + call_name + ", reply_msg.reply.header.code, long_status, sizeof(reply_msg.reply));\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_communication_error_status();\n")
	library_source.write("\t}\n\n")

	if (flags & ALLOW_INTERRUPTIONS) == 0:
		library_source.write("\tdserver_rpc_hooks_atomic_end(&atomic_save);\n\n")

	if fd_count_in_reply != 0:
		library_source.write("\tvalid_fd_count = 0;\n")
		for param in reply_parameters:
			param_name = param[0]

			if not is_fd(param):
				continue

			library_source.write("\tif (reply_msg.reply.body." + param_name + " >= 0) {\n")
			library_source.write("\t\t++valid_fd_count;\n")
			library_source.write("\t}\n")

		library_source.write(textwrap.indent(textwrap.dedent("""\
			if (valid_fd_count > 0) {
				dserver_rpc_hooks_cmsghdr_t* reply_cmsg = DSERVER_RPC_HOOKS_CMSG_FIRSTHDR(&replymsg);
				if (!reply_cmsg || reply_cmsg->cmsg_level != DSERVER_RPC_HOOKS_SOL_SOCKET || reply_cmsg->cmsg_type != DSERVER_RPC_HOOKS_SCM_RIGHTS || reply_cmsg->cmsg_len != DSERVER_RPC_HOOKS_CMSG_LEN(sizeof(int) * valid_fd_count)) {
					return dserver_rpc_hooks_get_bad_message_status();
				}
				dserver_rpc_hooks_memcpy(fds, DSERVER_RPC_HOOKS_CMSG_DATA(reply_cmsg), sizeof(int) * valid_fd_count);
			}
			"""), '\t'))

	for param in reply_parameters:
		param_name = param[0]

		if is_fd(param):
			library_source.write("\tif (out_" + param_name + ") {\n")
			library_source.write("\t\t*out_" + param_name + " = (reply_msg.reply.body." + param_name + " >= 0) ? fds[reply_msg.reply.body." + param_name + "] : -1;\n")
			library_source.write("\t} else if (reply_msg.reply.body." + param_name + " >= 0) {\n")
			library_source.write("\t\tdserver_rpc_hooks_close_fd(fds[reply_msg.reply.body." + param_name + "]);\n")
			library_source.write("\t}\n")
		else:
			library_source.write("\tif (out_" + param_name + ") {\n")
			library_source.write("\t\t*out_" + param_name + " = reply_msg.reply.body." + param_name + ";\n")
			library_source.write("\t}\n")

	library_source.write("\treturn reply_msg.reply.header.code;\n")

	library_source.write("};\n\n")

	# declare the RPC call wrapper function
	# (and output the prototype part of the function definition)
	tmp = "int dserver_rpc_" + call_name + "("
	public_header.write(tmp)
	library_source.write(tmp)
	is_first = True
	for param in call_parameters:
		param_name = param[0]

		if is_first:
			is_first = False
			tmp = ""
		else:
			tmp = ", "
		tmp += parse_type(param, True) + " " + param_name
		public_header.write(tmp)
		library_source.write(tmp)

	for param in reply_parameters:
		param_name = param[0]

		if is_first:
			is_first = False
			tmp = ""
		else:
			tmp = ", "
		tmp += parse_type(param, True) + "* out_" + param_name
		public_header.write(tmp)
		library_source.write(tmp)
	public_header.write(");\n\n")
	library_source.write(") {\n")

	library_source.write("\tint server_socket = dserver_rpc_hooks_get_socket();\n")
	library_source.write("\tif (server_socket < 0) {\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_broken_pipe_status();\n")
	library_source.write("\t}\n\n")

	library_source.write("\treturn dserver_rpc_explicit_" + call_name + "(server_socket")

	for param in call_parameters:
		param_name = param[0]

		tmp = ", "
		tmp += param_name
		library_source.write(tmp)

	for param in reply_parameters:
		param_name = param[0]

		tmp = ", "
		tmp += "out_" + param_name
		library_source.write(tmp)

	library_source.write(");\n")

	library_source.write("};\n\n")

public_header.write("// we don't care about multiple evaluation here\n")
public_header.write("#define dserver_rpc_helper_max(a, b) (((b) > (a)) ? (b) : (a))\n\n")

curr_call_len_str = "0"
curr_reply_len_str = "0"
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	flags = call[3] if len(call) >= 4 else 0
	curr_call_len_str = "(dserver_rpc_helper_max(sizeof(dserver_rpc_call_" + call_name + "_t), " + curr_call_len_str + "))"
	curr_reply_len_str = "(dserver_rpc_helper_max(sizeof(dserver_rpc_reply_" + call_name + "_t), " + curr_reply_len_str + "))"

public_header.write("#define DSERVER_RPC_CALL_MAX_LENGTH " + curr_call_len_str + "\n")
public_header.write("#define DSERVER_RPC_REPLY_MAX_LENGTH " + curr_reply_len_str + "\n")
public_header.write("#define DSERVER_RPC_CALL_MAX_FD_COUNT " + str(max_call_fd_count) + "\n")
public_header.write("#define DSERVER_RPC_REPLY_MAX_FD_COUNT " + str(max_reply_fd_count) + "\n\n")

public_header.write("""\
#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_API_H_
""")

public_header.close()
internal_header.close()
library_source.close()
