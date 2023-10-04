#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>

uint64_t dtape_debug_task_port_count(dtape_task_t* task) {
	return task->xnu_task.itk_space->is_table_hashed;
};

uint64_t dtape_debug_task_list_ports(dtape_task_t* task, dtape_debug_task_list_ports_iterator_f iterator, void* context) {
	uint64_t port_count = 0;
	bool call_it = true;

	for (mach_port_index_t index = 0; index < task->xnu_task.itk_space->is_table_size; ++index) {
		ipc_entry_t entry = &task->xnu_task.itk_space->is_table[index];
		dtape_debug_port_t debug_port;
		ipc_port_t port = NULL;

		if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
			continue;
		}

		port = ip_object_to_port(entry->ie_object);

		debug_port.name = MACH_PORT_MAKE(index, IE_BITS_GEN(entry->ie_bits));
		debug_port.refs = IE_BITS_UREFS(entry->ie_bits);
		debug_port.rights = IE_BITS_TYPE(entry->ie_bits);
		debug_port.messages = port->ip_messages.imq_msgcount;

		if (call_it) {
			call_it = iterator(context, &debug_port);
		}

		++port_count;
	}

	return port_count;
};

uint64_t dtape_debug_portset_list_members(dtape_task_t* task, uint32_t portset, dtape_debug_portset_list_members_iterator_f iterator, void* context) {
	ipc_object_t object = NULL;
	ipc_mqueue_t mqueue = NULL;
	ipc_entry_num_t member_count = 0;
	mach_port_name_t* names = NULL;
	ipc_entry_num_t actual_count = 0;
	bool call_it = true;

	if (ipc_mqueue_copyin(task->xnu_task.itk_space, portset, &mqueue, &object) != KERN_SUCCESS) {
		return 0;
	}

	do {
		if (names) {
			kfree(names, sizeof(*names) * member_count);
		}

		names = kalloc(sizeof(*names) * actual_count);
		member_count = actual_count;

		ipc_mqueue_set_gather_member_names(task->xnu_task.itk_space, mqueue, member_count, names, &actual_count);
	} while (member_count != actual_count);

	for (ipc_entry_num_t i = 0; i < member_count; ++i) {
		mach_port_name_t* name = &names[i];
		dtape_debug_port_t debug_port;
		ipc_entry_t entry = NULL;
		ipc_port_t port = NULL;

		entry = ipc_entry_lookup(task->xnu_task.itk_space, *name);
		port = ip_object_to_port(entry->ie_object);

		debug_port.name = *name;
		debug_port.refs = IE_BITS_UREFS(entry->ie_bits);
		debug_port.rights = IE_BITS_TYPE(entry->ie_bits);
		debug_port.messages = port->ip_messages.imq_msgcount;

		if (call_it) {
			call_it = iterator(context, &debug_port);
		}
	}

	if (names) {
		kfree(names, sizeof(*names) * member_count);
	}

	io_release(object);

	return member_count;
};

uint64_t dtape_debug_port_list_messages(dtape_task_t* task, uint32_t port, dtape_debug_port_list_messages_iterator_f iterator, void* context) {
	ipc_object_t object = NULL;
	ipc_mqueue_t mqueue = NULL;
	uint64_t message_count = 0;
	bool call_it = true;

	if (ipc_mqueue_copyin(task->xnu_task.itk_space, port, &mqueue, &object) != KERN_SUCCESS) {
		return 0;
	}

	for (ipc_kmsg_t kmsg = ipc_kmsg_queue_first(&mqueue->imq_messages); kmsg != NULL; kmsg = ipc_kmsg_queue_next(&mqueue->imq_messages, kmsg)) {
		dtape_debug_message_t debug_message;

		debug_message.sender = 0;

		if (kmsg->ikm_header->msgh_remote_port && kmsg->ikm_header->msgh_remote_port->ip_receiver) {
			debug_message.sender = dtape_task_for_xnu_task(kmsg->ikm_header->msgh_remote_port->ip_receiver->is_task)->saved_pid;
		}

		debug_message.size = kmsg->ikm_size;

		if (call_it) {
			call_it = iterator(context, &debug_message);
		}

		++message_count;
	}

	io_release(object);

	return message_count;
};
