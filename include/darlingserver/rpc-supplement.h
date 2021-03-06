#ifndef _DARLINGSERVER_RPC_SUPPLEMENT_H_
#define _DARLINGSERVER_RPC_SUPPLEMENT_H_

#include <stdint.h>
#include <stdbool.h>

#if __cplusplus
extern "C" {
#endif

//
// kqueue channels
//

/**
 * kqchan is short for "kqueue channel".
 *
 * kqueue channels are used to allow libkqueue to monitor events
 * that occur on the server side (in darlingserver). This is necessary
 * for filters like EVFILT_MACHPORT and EVFILT_PROC.
 *
 * The general process works like this:
 *   1. libkqueue is told to add a knote for one of the special filters that requires a kqchan.
 *   2. libkqueue hands that off to our filter handler code for that filter.
 *   3. our filter handler opens a kqchan using a darlingserver RPC call.
 *   4. darlingserver sets up the kqchan on the server side and sends back a socket
 *      that the client can monitor and send channel messages to.
 *   5. when the client needs to modify some of the server state for the channel,
 *      it sends a special message (specialized depending on the channel type).
 *   6. when the server receives an event of interest, it notifies the client
 *      by sending a generic notification message (to which the client should NOT reply).
 *   7. when the client receives a notification, libkqueue will attempt to read the message
 *      by calling the copyout method on the filter. for kqchan-based filters, this means
 *      sending a special message (specialized depending on the channel type) to which the
 *      server replies with the necessary event information.
 */

enum dserver_kqchan_msgnum {
	dserver_kqchan_msgnum_invalid = 0,

	/**
	 * Indicates that something has occurred on the server side that the client should know about.
	 *
	 * This is the only type of server-initiated message.
	 *
	 * This is common to all types of kqueue channels.
	 *
	 * This message does NOT require a reply.
	 */
	dserver_kqchan_msgnum_notification,

	/**
	 * A request to modify the server context for this mach port kqueue channel.
	 */
	dserver_kqchan_msgnum_mach_port_modify,

	/**
	 * A request to read the data for the most recent notification on this mach port kqueue channel.
	 */
	dserver_kqchan_msgnum_mach_port_read,

	/**
	 * A request to modify the server context for this proc kqueue channel.
	 */
	dserver_kqchan_msgnum_proc_modify,

	/**
	 * A request to read the data for the most recent notification on this proc kqueue channel.
	 */
	dserver_kqchan_msgnum_proc_read,
};

typedef enum dserver_kqchan_msgnum dserver_kqchan_msgnum_t;

typedef struct dserver_kqchan_callhdr {
	dserver_kqchan_msgnum_t number;
	int pid;
	int tid;
} dserver_kqchan_callhdr_t;

typedef struct dserver_kqchan_replyhdr {
	dserver_kqchan_msgnum_t number;
	int code;
} dserver_kqchan_replyhdr_t;

typedef struct dserver_kqchan_call_notification {
	dserver_kqchan_callhdr_t header;
} dserver_kqchan_call_notification_t;

typedef struct dserver_kqchan_call_mach_port_modify {
	dserver_kqchan_callhdr_t header;
	uint64_t receive_buffer;
	uint64_t receive_buffer_size;
	uint64_t saved_filter_flags;
} dserver_kqchan_call_mach_port_modify_t;

typedef struct dserver_kqchan_reply_mach_port_modify {
	dserver_kqchan_replyhdr_t header;
} dserver_kqchan_reply_mach_port_modify_t;

typedef struct dserver_kqchan_call_mach_port_read {
	dserver_kqchan_callhdr_t header;
	uint64_t default_buffer;
	uint64_t default_buffer_size;
} dserver_kqchan_call_mach_port_read_t;

typedef struct dserver_kqchan_reply_mach_port_read {
	dserver_kqchan_replyhdr_t header;
	struct {
		uint64_t ident;
		int16_t filter;
		uint16_t flags;
		int32_t qos;
		uint64_t udata;
		uint32_t fflags;
		uint32_t xflags;
		int64_t data;
		uint64_t ext[4];
	} kev;
} dserver_kqchan_reply_mach_port_read_t;

typedef struct dserver_kqchan_call_proc_modify {
	dserver_kqchan_callhdr_t header;
	uint32_t flags;
} dserver_kqchan_call_proc_modify_t;

typedef struct dserver_kqchan_reply_proc_modify {
	dserver_kqchan_replyhdr_t header;
} dserver_kqchan_reply_proc_modify_t;

typedef struct dserver_kqchan_call_proc_read {
	dserver_kqchan_callhdr_t header;
} dserver_kqchan_call_proc_read_t;

typedef struct dserver_kqchan_reply_proc_read {
	dserver_kqchan_replyhdr_t header;
	uint32_t fflags;
	int64_t data;
} dserver_kqchan_reply_proc_read_t;

//
// S2C
//
// server-to-client RPC calls
//

enum dserver_s2c_msgnum {
	dserver_s2c_msgnum_invalid = 0,
	dserver_s2c_msgnum_mmap,
	dserver_s2c_msgnum_munmap,
	dserver_s2c_msgnum_mprotect,
	dserver_s2c_msgnum_msync,
};

typedef enum dserver_s2c_msgnum dserver_s2c_msgnum_t;

typedef struct dserver_s2c_callhdr {
	int call_number;
	dserver_s2c_msgnum_t s2c_number;
} dserver_s2c_callhdr_t;

typedef struct dserver_s2c_replyhdr {
	int call_number;
	int pid;
	int tid;
	int architecture;
	dserver_s2c_msgnum_t s2c_number;
} dserver_s2c_replyhdr_t;

typedef struct dserver_s2c_call_mmap {
	dserver_s2c_callhdr_t header;
	uint64_t address;
	uint64_t length;
	int32_t protection;
	int32_t flags;
	int32_t fd;
	int64_t offset;
} dserver_s2c_call_mmap_t;

typedef struct dserver_s2c_reply_mmap {
	dserver_s2c_replyhdr_t header;
	uint64_t address;
	int errno_result;
} dserver_s2c_reply_mmap_t;

typedef struct dserver_s2c_call_munmap {
	dserver_s2c_callhdr_t header;
	uint64_t address;
	uint64_t length;
} dserver_s2c_call_munmap_t;

typedef struct dserver_s2c_reply_munmap {
	dserver_s2c_replyhdr_t header;
	int return_value;
	int errno_result;
} dserver_s2c_reply_munmap_t;

typedef struct dserver_s2c_call_mprotect {
	dserver_s2c_callhdr_t header;
	uint64_t address;
	uint64_t length;
	int protection;
} dserver_s2c_call_mprotect_t;

typedef struct dserver_s2c_reply_mprotect {
	dserver_s2c_replyhdr_t header;
	int return_value;
	int errno_result;
} dserver_s2c_reply_mprotect_t;

typedef struct dserver_s2c_call_msync {
	dserver_s2c_callhdr_t header;
	uint64_t address;
	uint64_t size;
	int sync_flags;
} dserver_s2c_call_msync_t;

typedef struct dserver_s2c_reply_msync {
	dserver_s2c_replyhdr_t header;
	int return_value;
	int errno_result;
} dserver_s2c_reply_msync_t;

typedef union dserver_s2c_call {
	dserver_s2c_call_mmap_t mmap;
	dserver_s2c_call_munmap_t munmap;
	dserver_s2c_call_mprotect_t mprotect;
        dserver_s2c_call_msync_t msync;
} dserver_s2c_call_t;

#if __cplusplus
};
#endif

#endif // _DARLINGSERVER_RPC_SUPPLEMENT_H_
