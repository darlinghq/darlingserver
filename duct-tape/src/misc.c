#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/hooks.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/waitq.h>
#include <kern/clock.h>
#include <kern/turnstile.h>
#include <kern/thread_call.h>
#include <ipc/ipc_init.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_pset.h>
#include <kern/host.h>

#include <sys/types.h>

const dtape_hooks_t* dtape_hooks;

int vsnprintf(char* buffer, size_t buffer_size, const char* format, va_list args);
ssize_t getrandom(void* buf, size_t buflen, unsigned int flags);

void ipc_table_init(void);

void dtape_log(dtape_log_level_t level, const char* format, ...) {
	char message[4096];

	va_list args;
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	dtape_hooks->log(level, message);
};

void dtape_init(const dtape_hooks_t* hooks) {
	dtape_hooks = hooks;

	ipc_space_zone = zone_create("ipc spaces", sizeof(struct ipc_space), ZC_NOENCRYPT);

	ipc_table_init();

	ipc_object_zones[IOT_PORT] = zone_create("ipc ports", sizeof(struct ipc_port), ZC_NOENCRYPT | ZC_CACHING | ZC_ZFREE_CLEARMEM | ZC_NOSEQUESTER);
	ipc_object_zones[IOT_PORT_SET] = zone_create("ipc port sets", sizeof(struct ipc_pset), ZC_NOENCRYPT | ZC_ZFREE_CLEARMEM | ZC_NOSEQUESTER);

	lck_mtx_init(&realhost.lock, LCK_GRP_NULL, LCK_ATTR_NULL);

	dtape_log_debug("waitq_bootstrap");
	waitq_bootstrap();

	dtape_log_debug("clock_init");
	clock_init();

	dtape_log_debug("turnstiles_init");
	turnstiles_init();

	dtape_log_debug("thread_call_initialize");
	thread_call_initialize();

	dtape_log_debug("ipc_thread_call_init");
	ipc_thread_call_init();

	dtape_log_debug("clock_service_create");
	clock_service_create();
};

void dtape_deinit(void) {

};

void read_frandom(void* buffer, unsigned int numBytes) {
	getrandom(buffer, numBytes, 0);
};
