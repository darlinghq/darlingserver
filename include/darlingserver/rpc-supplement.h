#ifndef _DARLINGSERVER_RPC_SUPPLEMENT_H_
#define _DARLINGSERVER_RPC_SUPPLEMENT_H_

#include <stdint.h>
#include <stdbool.h>

#if __cplusplus
extern "C" {
#endif

// These structures are shared by 32-bit and 64-bit clients and the 64-bit server, but 32-bit x86
// aligns 64-bit members to 4 bytes only. Align them to 8 bytes everywhere, as the generated RPC
// structures do, so that every architecture uses the same layout.
#define DSERVER_RPC_ALIGN64 __attribute__((aligned(8)))

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
	uint64_t receive_buffer DSERVER_RPC_ALIGN64;
	uint64_t receive_buffer_size DSERVER_RPC_ALIGN64;
	uint64_t saved_filter_flags DSERVER_RPC_ALIGN64;
} dserver_kqchan_call_mach_port_modify_t;

typedef struct dserver_kqchan_reply_mach_port_modify {
	dserver_kqchan_replyhdr_t header;
} dserver_kqchan_reply_mach_port_modify_t;

typedef struct dserver_kqchan_call_mach_port_read {
	dserver_kqchan_callhdr_t header;
	uint64_t default_buffer DSERVER_RPC_ALIGN64;
	uint64_t default_buffer_size DSERVER_RPC_ALIGN64;
} dserver_kqchan_call_mach_port_read_t;

typedef struct dserver_kqchan_reply_mach_port_read {
	dserver_kqchan_replyhdr_t header;
	struct {
		uint64_t ident DSERVER_RPC_ALIGN64;
		int16_t filter;
		uint16_t flags;
		int32_t qos;
		uint64_t udata DSERVER_RPC_ALIGN64;
		uint32_t fflags;
		uint32_t xflags;
		int64_t data DSERVER_RPC_ALIGN64;
		uint64_t ext[4] DSERVER_RPC_ALIGN64;
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
	int64_t data DSERVER_RPC_ALIGN64;
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
	uint64_t address DSERVER_RPC_ALIGN64;
	uint64_t length DSERVER_RPC_ALIGN64;
	int32_t protection;
	int32_t flags;
	int32_t fd;
	int64_t offset DSERVER_RPC_ALIGN64;
} dserver_s2c_call_mmap_t;

typedef struct dserver_s2c_reply_mmap {
	dserver_s2c_replyhdr_t header;
	uint64_t address DSERVER_RPC_ALIGN64;
	int errno_result;
} dserver_s2c_reply_mmap_t;

typedef struct dserver_s2c_call_munmap {
	dserver_s2c_callhdr_t header;
	uint64_t address DSERVER_RPC_ALIGN64;
	uint64_t length DSERVER_RPC_ALIGN64;
} dserver_s2c_call_munmap_t;

typedef struct dserver_s2c_reply_munmap {
	dserver_s2c_replyhdr_t header;
	int return_value;
	int errno_result;
} dserver_s2c_reply_munmap_t;

typedef struct dserver_s2c_call_mprotect {
	dserver_s2c_callhdr_t header;
	uint64_t address DSERVER_RPC_ALIGN64;
	uint64_t length DSERVER_RPC_ALIGN64;
	int protection;
} dserver_s2c_call_mprotect_t;

typedef struct dserver_s2c_reply_mprotect {
	dserver_s2c_replyhdr_t header;
	int return_value;
	int errno_result;
} dserver_s2c_reply_mprotect_t;

typedef struct dserver_s2c_call_msync {
	dserver_s2c_callhdr_t header;
	uint64_t address DSERVER_RPC_ALIGN64;
	uint64_t size DSERVER_RPC_ALIGN64;
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

//
// system configuration
//

/**
 * The system configuration holds the values of the `org.darlinghq.security`
 * preferences domain that darlingserver is the authority for. A guest daemon
 * reads the domain through CFPreferences and pushes it with
 * `set_system_config`; darlingserver itself parses no plists.
 *
 * Until the first push, darlingserver uses built-in defaults (no enforcement).
 * `wait_system_config` returns once the first push has been accepted.
 *
 * Only a caller whose user ID (as darlingserver tracks it for the process) is 0
 * may push. A push is validated completely before anything is applied, so a
 * rejected push changes nothing. Anyone may read the configuration back with
 * `get_system_config`.
 */

#define DSERVER_SYSTEM_CONFIG_VERSION 1

// size of `trust_store_path`, including the terminating NUL (MAXPATHLEN on Darwin)
#define DSERVER_SYSTEM_CONFIG_PATH_MAX 1024

// bits in `present`: which keys the pushed domain contained
#define DSERVER_SYSTEM_CONFIG_HAS_CODE_SIGNING_POLICY (1u << 0)
#define DSERVER_SYSTEM_CONFIG_HAS_CSR_ACTIVE_CONFIG   (1u << 1)
#define DSERVER_SYSTEM_CONFIG_HAS_SEAL_IMAGES         (1u << 2)
#define DSERVER_SYSTEM_CONFIG_HAS_TRUST_STORE_PATH    (1u << 3)

#define DSERVER_SYSTEM_CONFIG_HAS_ALL ( \
		DSERVER_SYSTEM_CONFIG_HAS_CODE_SIGNING_POLICY | \
		DSERVER_SYSTEM_CONFIG_HAS_CSR_ACTIVE_CONFIG | \
		DSERVER_SYSTEM_CONFIG_HAS_SEAL_IMAGES | \
		DSERVER_SYSTEM_CONFIG_HAS_TRUST_STORE_PATH \
	)

// values of `CodeSigningPolicy` ("off", "warn" and "enforce" in the domain)
enum dserver_code_signing_policy {
	dserver_code_signing_policy_off = 0,
	dserver_code_signing_policy_warn = 1,
	dserver_code_signing_policy_enforce = 2,
};

typedef struct dserver_system_config {
	/**
	 * Must be `DSERVER_SYSTEM_CONFIG_VERSION`.
	 */
	uint32_t version;

	/**
	 * Must be `sizeof(dserver_system_config_t)`.
	 */
	uint32_t size;

	/**
	 * A combination of `DSERVER_SYSTEM_CONFIG_HAS_*` bits.
	 *
	 * In a push, every field whose bit is clear must be zero, and darlingserver uses its default for it.
	 * Read back, the bits say which values came from the last push; every field holds the value in effect.
	 */
	uint32_t present;

	/**
	 * One of `dserver_code_signing_policy`. Default: off.
	 */
	uint32_t code_signing_policy;

	/**
	 * Same meaning as the `csr-active-config` NVRAM variable: `CSR_ALLOW_*` flags from `<sys/csr.h>`.
	 * Only `CSR_VALID_FLAGS` may be set. Default: `CSR_DISABLE_FLAGS` (what `csrutil disable` sets).
	 *
	 * After the first push, a push may only clear flags (turn protections on), never set flags
	 * that are not in effect; relaxing the configuration takes a restart of the prefix.
	 */
	uint32_t csr_active_config;

	/**
	 * 0 or 1. Default: 0.
	 */
	uint32_t seal_images;

	/**
	 * Number of pushes accepted so far; 0 means the built-in defaults are in effect.
	 * Filled in by darlingserver when read back; must be zero in a push.
	 */
	uint64_t generation;

	/**
	 * An absolute, NUL-terminated path. Empty (all zero) when not present, which is also the default.
	 */
	char trust_store_path[DSERVER_SYSTEM_CONFIG_PATH_MAX];
} dserver_system_config_t;

#if __cplusplus
};
#endif

#endif // _DARLINGSERVER_RPC_SUPPLEMENT_H_
