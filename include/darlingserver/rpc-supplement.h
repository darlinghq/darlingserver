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

//
// platform identity
//

/**
 * The platform identity holds the values of the `org.darlinghq.platform`
 * preferences domain that the layers below CoreFoundation report: `hw.model`,
 * `machdep.cpu.brand_string`, `hw.memsize` (and `host_info()`), `gethostuuid()`,
 * and the IOPlatformExpertDevice properties that iokitd publishes. As with the
 * system configuration, a guest daemon reads the domain through CFPreferences
 * and pushes it with `set_platform_identity`. It pushes the identity before the
 * system configuration, so `wait_system_config` also covers the identity.
 *
 * Until the first push, and for every key a push leaves out, darlingserver uses
 * its defaults:
 *   - `model`: MacBookPro16,1 on x86_64 and i386, Mac14,2 on arm64;
 *   - `product_name`: the default model on x86_64 and i386, none on arm64;
 *   - `board_id`: Mac-E1008331FDC96864 on x86_64 and i386, none on arm64;
 *   - `platform_uuid`: derived from the host's machine ID (see below);
 *   - `serial_number`: "DARLING-" and 8 hex digits from the same derivation;
 *   - `cpu_brand_string`, `memory_size`: none, so the host's values are used;
 *   - `rom`, `mlb_serial_number`, `system_id`, `provisioning_udid`: none
 *     (these are never synthesized).
 *
 * The platform UUID is derived the way machine-id(5) recommends for
 * application-specific IDs: HMAC-SHA256 keyed with the 16-byte machine ID over
 * a fixed Darling application ID. The first 16 bytes of the result, with the
 * RFC 4122 version 4 and variant bits set, are the UUID; the next 4 bytes give
 * the serial number. The raw machine ID is never handed out. If the host has no
 * machine ID, the UUID is all zero and the serial number is empty.
 *
 * Only a caller whose user ID is 0 may push; anyone may read the identity back
 * with `get_platform_identity`. A push is validated completely before anything
 * is applied. A later push applies to processes that read the identity
 * afterwards; libsystem_kernel reads it once per process.
 */

#define DSERVER_PLATFORM_IDENTITY_VERSION 1

// size of each string field, including the terminating NUL
#define DSERVER_PLATFORM_IDENTITY_STRING_MAX 64

// bits in `present`: which keys the pushed domain contained
#define DSERVER_PLATFORM_IDENTITY_HAS_MODEL             (1u << 0)
#define DSERVER_PLATFORM_IDENTITY_HAS_PRODUCT_NAME      (1u << 1)
#define DSERVER_PLATFORM_IDENTITY_HAS_BOARD_ID          (1u << 2)
#define DSERVER_PLATFORM_IDENTITY_HAS_SERIAL_NUMBER     (1u << 3)
#define DSERVER_PLATFORM_IDENTITY_HAS_PLATFORM_UUID     (1u << 4)
#define DSERVER_PLATFORM_IDENTITY_HAS_CPU_BRAND_STRING  (1u << 5)
#define DSERVER_PLATFORM_IDENTITY_HAS_MEMORY_SIZE       (1u << 6)
#define DSERVER_PLATFORM_IDENTITY_HAS_ROM               (1u << 7)
#define DSERVER_PLATFORM_IDENTITY_HAS_MLB_SERIAL_NUMBER (1u << 8)
#define DSERVER_PLATFORM_IDENTITY_HAS_SYSTEM_ID         (1u << 9)
#define DSERVER_PLATFORM_IDENTITY_HAS_PROVISIONING_UDID (1u << 10)

#define DSERVER_PLATFORM_IDENTITY_HAS_ALL ((1u << 11) - 1)

typedef struct dserver_platform_identity {
	/**
	 * Must be `DSERVER_PLATFORM_IDENTITY_VERSION`.
	 */
	uint32_t version;

	/**
	 * Must be `sizeof(dserver_platform_identity_t)`.
	 */
	uint32_t size;

	/**
	 * A combination of `DSERVER_PLATFORM_IDENTITY_HAS_*` bits.
	 *
	 * In a push, every field whose bit is clear must be zero, and darlingserver uses its default for it.
	 * Read back, the bits say which values came from the last push. Every field holds the value in effect,
	 * or zero (an empty string) when there is none.
	 */
	uint32_t present;

	/**
	 * Must be zero.
	 */
	uint32_t reserved;

	/**
	 * Number of pushes accepted so far; 0 means the defaults are in effect.
	 * Filled in by darlingserver when read back; must be zero in a push.
	 */
	uint64_t generation DSERVER_RPC_ALIGN64;

	/**
	 * `MemorySize`: the memory size in bytes that `hw.memsize` and `host_info()` report. Nonzero when pushed.
	 */
	uint64_t memory_size DSERVER_RPC_ALIGN64;

	/**
	 * `PlatformUUID`: what `gethostuuid()` and `IOPlatformUUID` report. Not the nil UUID when pushed.
	 */
	uint8_t platform_uuid[16];

	/**
	 * `SystemID`: 16 bytes, not all zero when pushed.
	 */
	uint8_t system_id[16];

	/**
	 * `ProvisioningUDID`: when pushed, must equal the platform UUID in effect.
	 */
	uint8_t provisioning_udid[16];

	/**
	 * `ROM`: 6 bytes, not all zero when pushed.
	 */
	uint8_t rom[6];

	/**
	 * Must be zero.
	 */
	uint8_t rom_reserved[2];

	/**
	 * When pushed, each string is printable ASCII, not empty, and NUL-terminated inside its field.
	 */
	char model[DSERVER_PLATFORM_IDENTITY_STRING_MAX];             // `Model`
	char product_name[DSERVER_PLATFORM_IDENTITY_STRING_MAX];      // `ProductName`
	char board_id[DSERVER_PLATFORM_IDENTITY_STRING_MAX];          // `BoardID`
	char serial_number[DSERVER_PLATFORM_IDENTITY_STRING_MAX];     // `SerialNumber`
	char mlb_serial_number[DSERVER_PLATFORM_IDENTITY_STRING_MAX]; // `MLBSerialNumber`
	char cpu_brand_string[DSERVER_PLATFORM_IDENTITY_STRING_MAX];  // `CPUBrandString`
} dserver_platform_identity_t;

//
// code signing state
//

/**
 * What darlingserver records about the code signature of a process.
 *
 * mldr registers the image a process starts from with `cs_register_image`, once per exec.
 * darlingserver reads the signature itself, from the descriptor it is given; nothing the process
 * says about its own signature is taken on trust. When the process's code signing policy is not
 * `off`, every code page and the CMS signature (if any) are checked too. Only under `enforce`
 * does a problem with a signature (one that cannot be fully parsed, a changed page, a CMS
 * signature that does not verify) make the status invalid; otherwise signed code is reported as
 * validly signed, and under `warn` the problem is logged. A forked process
 * inherits the state of its parent. Under `enforce`, only a process that has just exec'd (or the
 * very first process) may register, once.
 *
 * Anyone may read the state of any process.
 *
 * The state also records the code signing policy and `csr-active-config` that were in effect
 * when the process started (see `dserver_system_config_t`). The policy of the *target* process
 * decides whether darlingserver mediates access to it (task ports, ptrace attach); with the
 * default policy (`off`) nothing is restricted.
 */

#define DSERVER_CS_STATE_VERSION 1

// sizes of the fixed fields, terminating NUL included where it applies
#define DSERVER_CS_CDHASH_LEN 20
#define DSERVER_CS_TEAM_ID_MAX 64
#define DSERVER_CS_IDENTIFIER_MAX 512

enum dserver_cs_status {
	// no image has been registered for the process (yet)
	dserver_cs_status_unregistered = 0,
	// the image has no code signature
	dserver_cs_status_unsigned = 1,
	// the image has a code signature that did not verify, or could not be read
	dserver_cs_status_invalid = 2,
	// the signature and every code page verified
	dserver_cs_status_valid = 3,
};

enum dserver_cs_signer {
	dserver_cs_signer_none = 0,
	// an ad-hoc signature (no CMS signature)
	dserver_cs_signer_adhoc = 1,
	// a CMS signature that signs the CodeDirectory; its certificate chain is not evaluated
	dserver_cs_signer_certificate = 2,
};

// bits in `darling_flags`
#define DSERVER_CS_DENY_ATTACH  (1u << 0) // the process called ptrace(PT_DENY_ATTACH)
#define DSERVER_CS_TRUST_STORE  (1u << 1) // the CDHash is in Darling's trust store (hence `CS_PLATFORM_BINARY`)
#define DSERVER_CS_SANDBOXED    (1u << 2) // the process (or an ancestor) applied a sandbox profile; nothing is enforced

typedef struct dserver_cs_state {
	/**
	 * `DSERVER_CS_STATE_VERSION` and `sizeof(dserver_cs_state_t)`.
	 */
	uint32_t version;
	uint32_t size;

	/**
	 * One of `dserver_cs_status` and `dserver_cs_signer`.
	 */
	uint32_t status;
	uint32_t signer;

	/**
	 * `CS_*` flags from `<kern/cs_blobs.h>`, as `csops(CS_OPS_STATUS)` reports them. Zero unless
	 * the status is valid; `CS_VALID` may have been cleared since.
	 */
	uint32_t flags;

	/**
	 * `DSERVER_CS_*` bits.
	 */
	uint32_t darling_flags;

	/**
	 * The `dserver_code_signing_policy` and `csr-active-config` in effect when the process
	 * started (its last exec, or its first ancestor's).
	 */
	uint32_t code_signing_policy;
	uint32_t csr_active_config;

	/**
	 * From the CodeDirectory that is used: `CS_HASHTYPE_*`, the platform field and the hardened
	 * runtime version (0 when absent).
	 */
	uint32_t hash_type;
	uint32_t platform;
	uint32_t runtime_version;

	/**
	 * Lengths of the entitlements and DER entitlements blobs, headers included (what
	 * `cs_copy_entitlements` returns); 0 when there are none.
	 */
	uint32_t entitlements_length;
	uint32_t der_entitlements_length;

	uint32_t reserved;

	/**
	 * darlingserver's ID for the process; a different value means a different process (or a
	 * different exec of it), even if the PID is the same.
	 */
	uint64_t generation DSERVER_RPC_ALIGN64;

	/**
	 * Where the image starts in its file (non-zero for a slice of a universal binary), and
	 * the signed range and executable segment that the CodeDirectory describes.
	 */
	uint64_t image_offset DSERVER_RPC_ALIGN64;
	uint64_t code_limit DSERVER_RPC_ALIGN64;
	uint64_t exec_seg_base DSERVER_RPC_ALIGN64;
	uint64_t exec_seg_limit DSERVER_RPC_ALIGN64;
	uint64_t exec_seg_flags DSERVER_RPC_ALIGN64;

	uint8_t cdhash[DSERVER_CS_CDHASH_LEN];
	uint8_t reserved2[4];

	/**
	 * NUL-terminated; empty when there is none.
	 */
	char team_id[DSERVER_CS_TEAM_ID_MAX];
	char identifier[DSERVER_CS_IDENTIFIER_MAX];
} dserver_cs_state_t;

#if __cplusplus
};
#endif

#endif // _DARLINGSERVER_RPC_SUPPLEMENT_H_
