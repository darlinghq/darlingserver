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
	# currently, the only flag that can be passed is XNU_TRAP_CALL. this indicates that the given call is actually an XNU trap.
	# this enables more advanced wrappers to be generated for that call and avoid unnecessary boilerplate code on the server side.
	#
	# TODO: we should probably add a class for these calls (so it's more readable).
	#       we could even create a DSL (à-la-MIG), but that's probably overkill since
	#       we only use our RPC for darlingserver calls.
	#

	('checkin', [
		('is_fork', 'bool'),
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
		('tracer', 'uint32_t'),
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

	('fork_wait_for_child', [], []),

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
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

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
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('semaphore_wait_signal', [
		('wait_name', 'uint32_t'),
		('signal_name', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('semaphore_timedwait', [
		('wait_name', 'uint32_t'),
		('sec', 'uint32_t'),
		('nsec', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

	('semaphore_timedwait_signal', [
		('wait_name', 'uint32_t'),
		('signal_name', 'uint32_t'),
		('sec', 'uint32_t'),
		('nsec', 'uint32_t'),
	], [], XNU_TRAP_CALL | XNU_TRAP_NOPREFIX),

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
]

def parse_type(param_tuple, is_public):
	type_str = param_tuple[1].strip()
	if type_str == '@fd':
		return 'int'
	else:
		if not is_public and len(param_tuple) > 2:
			return param_tuple[2].strip()
		else:
			return type_str

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

public_header.write("enum dserver_callnum {\n")
# "52ccall" -> "s2c call"
public_header.write("\tdserver_callnum_s2c = 0x52cca11,\n")
public_header.write("\tdserver_callnum_invalid = 0,\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]

	public_header.write("\tdserver_callnum_" + call_name + ",\n")
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

""")

library_source.write("""\
#include {}
#include <darlingserver/rpc-supplement.h>

#if !defined(dserver_rpc_hooks_msghdr_t) || !defined(dserver_rpc_hooks_iovec_t) || !defined(dserver_rpc_hooks_cmsghdr_t) || !defined(DSERVER_RPC_HOOKS_CMSG_SPACE) || !defined(DSERVER_RPC_HOOKS_CMSG_FIRSTHDR) || !defined(DSERVER_RPC_HOOKS_SOL_SOCKET) || !defined(DSERVER_RPC_HOOKS_SCM_RIGHTS) || !defined(DSERVER_RPC_HOOKS_CMSG_LEN) || !defined(DSERVER_RPC_HOOKS_CMSG_DATA) || !defined(DSERVER_RPC_HOOKS_ATTRIBUTE)
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
	camel_name = to_camel_case(call_name)
	fd_count_in_reply = 0

	internal_header.write(textwrap.indent(textwrap.dedent("""\
		class Call::{1}: public Call {{ \\
			friend class Call; \\
		private: \\
			{2}
		public: \\
			{1}(MessageQueue& replyQueue, std::shared_ptr<Thread> thread, dserver_rpc_call_{0}_t* data, Message&& requestMessage): \\
				Call(replyQueue, thread, requestMessage.address(), reinterpret_cast<dserver_rpc_callhdr_t*>(data)){3} \\
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
			virtual Call::Number number() const {{ \\
				return Call::Number::{0}; \\
			}}; \\
			virtual void processCall(); \\
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
	internal_header.write("\t\t\t\tthread->setWaitingForReply(false); \\\n")
	internal_header.write("\t\t\t} \\\n")
	internal_header.write("\t\t\t_replyQueue.push(std::move(reply)); \\\n")
	internal_header.write("\t\t}; \\\n")

	if len(reply_parameters) == 0:
		internal_header.write("\tpublic: \\\n")
		internal_header.write("\t\tvoid sendBasicReply(int resultCode) { \\\n")
		internal_header.write("\t\t\t_sendReply(resultCode); \\\n")
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
	if len(reply_parameters) > 0:
		raise RuntimeError("Call marked as an XNU trap has reply parameters")

	internal_header.write("\tvoid DarlingServer::Call::{0}::processCall() {{ \\\n".format(camel_name))
	internal_header.write("\t\t{ \\\n")
	internal_header.write("\t\t\tauto thread = _thread.lock(); \\\n")
	internal_header.write("\t\t\tif (thread) { \\\n")
	internal_header.write("\t\t\t\tthread->setActiveSyscall(shared_from_this()); \\\n")
	internal_header.write("\t\t\t} \\\n")
	internal_header.write("\t\t}; \\\n")
	internal_header.write("\t\t_sendReply(dtape_{0}(".format(call_name))

	is_first = True
	for param in call_parameters:
		param_name = param[0]

		if is_first:
			is_first = False
		else:
			internal_header.write(", ")

		internal_header.write("_body.{0}".format(param_name))

	internal_header.write(")); \\\n")
	internal_header.write("\t\t{ \\\n")
	internal_header.write("\t\t\tauto thread = _thread.lock(); \\\n")
	internal_header.write("\t\t\tif (thread) { \\\n")
	internal_header.write("\t\t\t\tthread->setActiveSyscall(nullptr); \\\n")
	internal_header.write("\t\t\t} \\\n")
	internal_header.write("\t\t}; \\\n")
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

	internal_header.write("); \\\n")
internal_header.write("\n")

internal_header.write("#define DSERVER_DTAPE_DEFS \\\n")
for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	flags = call[3] if len(call) >= 4 else 0
	camel_name = to_camel_case(call_name)

	if (flags & XNU_TRAP_CALL) == 0:
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
for call in calls:
	call_name = call[0]
	public_header.write("\t\tcase dserver_callnum_" + call_name + ": return \"dserver_callnum_" + call_name + "\";\n")
public_header.write("\t\tdefault: return (const char*)0;\n")
public_header.write("\t}\n")
public_header.write("};\n\n")

for call in calls:
	call_name = call[0]
	call_parameters = call[1]
	reply_parameters = call[2]
	fd_count_in_call = 0
	fd_count_in_reply = 0

	# define the RPC call body structure
	if len(call_parameters) > 0:
		public_header.write("typedef struct dserver_call_" + call_name + " dserver_call_" + call_name + "_t;\n")
		public_header.write("struct dserver_call_" + call_name + " {\n")
		for param in call_parameters:
			param_name = param[0]

			if is_fd(param):
				fd_count_in_call += 1

			public_header.write("\t" + parse_type(param, False) + " " + param_name + ";\n")
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

			public_header.write("\t" + parse_type(param, False) + " " + param_name + ";\n")
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

			library_source.write("\t\t\t." + param_name + " = " + val + ",\n")
		library_source.write("\t\t},\n")

	library_source.write("\t};\n")
	library_source.write("\tunion {\n")
	library_source.write("\t\tdserver_rpc_reply_" + call_name + "_t reply;\n")
	library_source.write("\t\tdserver_s2c_call_t s2c;\n")
	library_source.write("\t} reply_msg;\n")

	if fd_count_in_call > 0 or fd_count_in_reply > 0:
		library_source.write("\tint fds[" + str(max(fd_count_in_call, fd_count_in_reply)) + "];\n")
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
		library_source.write("\t\t.msg_control = controlbuf,\n")
		library_source.write("\t\t.msg_controllen = sizeof(controlbuf),\n")

	library_source.write("\t};\n")

	if fd_count_in_call > 0:
		library_source.write(textwrap.indent(textwrap.dedent("""\
			dserver_rpc_hooks_cmsghdr_t* call_cmsg = DSERVER_RPC_HOOKS_CMSG_FIRSTHDR(&callmsg);
			call_cmsg->cmsg_level = DSERVER_RPC_HOOKS_SOL_SOCKET;
			call_cmsg->cmsg_type = DSERVER_RPC_HOOKS_SCM_RIGHTS;
			call_cmsg->cmsg_len = DSERVER_RPC_HOOKS_CMSG_LEN(sizeof(int) * valid_fd_count);
			dserver_rpc_hooks_memcpy(DSERVER_RPC_HOOKS_CMSG_DATA(call_cmsg), fds, sizeof(int) * valid_fd_count);
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
		"""), '\t'))

	if fd_count_in_reply == 0:
		library_source.write("\t\t.msg_control = NULL,\n")
		library_source.write("\t\t.msg_controllen = 0,\n")
	else:
		library_source.write("\t\t.msg_control = controlbuf,\n")
		library_source.write("\t\t.msg_controllen = sizeof(controlbuf),\n")

	library_source.write("\t};\n\n")

	library_source.write("\tint socket = dserver_rpc_hooks_get_socket();\n")
	library_source.write("\tif (socket < 0) {\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_broken_pipe_status();\n")
	library_source.write("\t}\n\n")

	library_source.write("\tlong int long_status = dserver_rpc_hooks_send_message(socket, &callmsg);\n")
	library_source.write("\tif (long_status < 0) {\n")
	library_source.write("\t\treturn (int)long_status;\n")
	library_source.write("\t}\n\n")
	library_source.write("\tif (long_status != sizeof(call)) {\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_communication_error_status();\n")
	library_source.write("\t}\n\n")

	library_source.write("\tlong_status = dserver_rpc_hooks_receive_message(socket, &replymsg);\n")
	library_source.write("\tif (long_status < 0) {\n")
	library_source.write("\t\treturn (int)long_status;\n")
	library_source.write("\t}\n\n")
	library_source.write("\tif (long_status != sizeof(reply_msg.reply)) {\n")
	library_source.write("\t\treturn dserver_rpc_hooks_get_communication_error_status();\n")
	library_source.write("\t}\n\n")

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

public_header.write("""\
#ifdef __cplusplus
};
#endif

#endif // _DARLINGSERVER_API_H_
""")

public_header.close()
internal_header.close()
library_source.close()
