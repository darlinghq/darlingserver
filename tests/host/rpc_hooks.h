// Hooks for the generated client code (rpc.c), backed by plain Linux sockets, for the host test.
// The names and macros are the ones the generator requires (scripts/generate-rpc-wrappers.py).
#ifndef RPC_HOOKS_H
#define RPC_HOOKS_H

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc.internal.h>

#define DSERVER_RPC_HOOKS_ATTRIBUTE static
#define dserver_rpc_hooks_msghdr_t struct msghdr
#define dserver_rpc_hooks_iovec_t struct iovec
#define dserver_rpc_hooks_cmsghdr_t struct cmsghdr
#define DSERVER_RPC_HOOKS_CMSG_SPACE CMSG_SPACE
#define DSERVER_RPC_HOOKS_CMSG_FIRSTHDR CMSG_FIRSTHDR
#define DSERVER_RPC_HOOKS_CMSG_LEN CMSG_LEN
#define DSERVER_RPC_HOOKS_CMSG_DATA CMSG_DATA
#define DSERVER_RPC_HOOKS_SOL_SOCKET SOL_SOCKET
#define DSERVER_RPC_HOOKS_SCM_RIGHTS SCM_RIGHTS
#define dserver_rpc_hooks_atomic_save_t int

#define HOOK_BAD_MESSAGE (-4242)
#define HOOK_COMM_ERROR (-4243)

extern int hook_socket;

static pid_t dserver_rpc_hooks_get_pid(void) { return getpid(); }
static pid_t dserver_rpc_hooks_get_tid(void) { return getpid(); }
static dserver_rpc_architecture_t dserver_rpc_hooks_get_architecture(void) { return dserver_rpc_architecture_invalid; }
static void* dserver_rpc_hooks_get_server_address(void) { return NULL; }
static size_t dserver_rpc_hooks_get_server_address_length(void) { return 0; }
static void* dserver_rpc_hooks_memcpy(void* d, const void* s, size_t n) { return memcpy(d, s, n); }
static long int dserver_rpc_hooks_send_message(int socket, const struct msghdr* m) { return sendmsg(socket, m, 0); }
static long int dserver_rpc_hooks_receive_message(int socket, struct msghdr* m) { return recvmsg(socket, m, 0); }
static int dserver_rpc_hooks_get_bad_message_status(void) { return HOOK_BAD_MESSAGE; }
static int dserver_rpc_hooks_get_communication_error_status(void) { return HOOK_COMM_ERROR; }
static int dserver_rpc_hooks_get_broken_pipe_status(void) { return -32; }
static void dserver_rpc_hooks_close_fd(int fd) { close(fd); }
static int dserver_rpc_hooks_get_socket(void) { return hook_socket; }
static void dserver_rpc_hooks_printf(const char* f, ...) { (void)f; }
static void dserver_rpc_hooks_atomic_begin(int* s) { (void)s; }
static void dserver_rpc_hooks_atomic_end(int* s) { (void)s; }
static int dserver_rpc_hooks_get_interrupt_status(void) { return -4; }
static void dserver_rpc_hooks_push_reply(int socket, const struct msghdr* m, size_t size) { (void)socket; (void)m; (void)size; }

#endif
