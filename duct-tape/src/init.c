#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/log.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/processor.h>
#include <darlingserver/duct-tape/psynch.h>
#include <darlingserver/duct-tape/task.h>

#include <ipc/ipc_importance.h>
#include <ipc/ipc_init.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>
#include <kern/host.h>
#include <kern/ipc_host.h>
#include <kern/sync_sema.h>
#include <kern/ux_handler.h>

const dtape_hooks_t* dtape_hooks;

extern zone_t ipc_importance_inherit_zone;
extern lck_spin_t ipc_importance_lock_data;
extern zone_t ipc_importance_task_zone;
extern zone_t semaphore_zone;

void ipc_table_init(void);
void ipc_init(void);
void mig_init(void);
void host_notify_init(void);
void user_data_attr_manager_init(void);
void ipc_voucher_init(void);

void dtape_timer_init(void);
void dtape_mk_timer_init(void);

void dtape_init(const dtape_hooks_t* hooks) {
	dtape_hooks = hooks;

	dtape_log_debug("dtape_processor_init");
	dtape_processor_init();

	dtape_log_debug("dtape_memory_init");
	dtape_memory_init();

	ipc_space_zone = zone_create("ipc spaces", sizeof(struct ipc_space), ZC_NOENCRYPT);
	ipc_kmsg_zone = zone_create("ipc kmsgs", IKM_SAVED_KMSG_SIZE, ZC_CACHING | ZC_ZFREE_CLEARMEM);
	semaphore_zone = zone_create("semaphores", sizeof(struct semaphore), ZC_NONE);

	ipc_object_zones[IOT_PORT] = zone_create("ipc ports", sizeof(struct ipc_port), ZC_NOENCRYPT | ZC_CACHING | ZC_ZFREE_CLEARMEM | ZC_NOSEQUESTER);
	ipc_object_zones[IOT_PORT_SET] = zone_create("ipc port sets", sizeof(struct ipc_pset), ZC_NOENCRYPT | ZC_ZFREE_CLEARMEM | ZC_NOSEQUESTER);

	ipc_importance_task_zone = zone_create("ipc task importance", sizeof(struct ipc_importance_task), ZC_NOENCRYPT);
	ipc_importance_inherit_zone = zone_create("ipc importance inherit", sizeof(struct ipc_importance_inherit), ZC_NOENCRYPT);

	lck_mtx_init(&realhost.lock, LCK_GRP_NULL, LCK_ATTR_NULL);
	lck_spin_init(&ipc_importance_lock_data, LCK_GRP_NULL, LCK_ATTR_NULL);

	dtape_log_debug("dtape_timer_init");
	dtape_timer_init();

	dtape_log_debug("dtape_mk_timer_init");
	dtape_mk_timer_init();

	dtape_log_debug("timer_call_init");
	timer_call_init();

	dtape_log_debug("ipc_table_init");
	ipc_table_init();

	dtape_log_debug("ipc_voucher_init");
	ipc_voucher_init();

	dtape_log_debug("dtape_task_init");
	dtape_task_init();

	dtape_log_debug("ipc_init");
	ipc_init();

	for (size_t i = 0; i < processor_count; ++i) {
		if (processor_array[i] == master_processor) {
			continue;
		}

		ipc_processor_init(processor_array[i]);
		ipc_processor_enable(processor_array[i]);
	}

	dtape_log_debug("mig_init");
	mig_init();

	dtape_log_debug("host_notify_init");
	host_notify_init();

	dtape_log_debug("user_data_attr_manager_init");
	user_data_attr_manager_init();

	dtape_log_debug("waitq_bootstrap");
	waitq_bootstrap();

	dtape_log_debug("clock_init");
	clock_init();

	dtape_log_debug("turnstiles_init");
	turnstiles_init();

	dtape_log_debug("host_statistics_init");
	host_statistics_init();
};

void dtape_init_in_thread(void) {
	dtape_log_debug("thread_call_initialize");
	thread_call_initialize();

	dtape_log_debug("ipc_thread_call_init");
	ipc_thread_call_init();

	dtape_log_debug("clock_service_create");
	clock_service_create();

	dtape_log_debug("thread_deallocate_daemon_init");
	thread_deallocate_daemon_init();

	ux_handler_setup();

	dtape_psynch_init();
};

void dtape_deinit(void) {

};
