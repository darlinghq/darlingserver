/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Darling Developers
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

#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/task.h>

#include <ipc/ipc_port.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_misc.h>

#include <stdlib.h>

int close(int fd);
int dup(int fd);

/*
 * A fileport is a kernel-owned Mach port whose send rights stand for an open
 * file. XNU keeps a fileglob as the port's kobject; here the kobject holds a
 * host descriptor that the server owns. The send right moves between tasks
 * like any other right, and when the last one goes away, the no-senders
 * notification (fileport_notify) calls fileport_releasefg, which closes the
 * descriptor.
 */
struct dtape_fileport {
	int fd;
};

void fileport_releasefg(struct fileglob* fg) {
	struct dtape_fileport* fileport = (struct dtape_fileport*)fg;

	close(fileport->fd);
	free(fileport);
};

dtape_fileport_result_t dtape_fileport_makeport(dtape_task_t* task, int fd, uint32_t* out_port_name) {
	struct dtape_fileport* fileport;
	ipc_port_t port;
	mach_port_name_t name;

	fileport = malloc(sizeof(*fileport));
	if (!fileport) {
		close(fd);
		return dtape_fileport_result_no_resources;
	}
	fileport->fd = fd;

	port = fileport_alloc((struct fileglob*)fileport);
	if (!IP_VALID(port)) {
		fileport_releasefg((struct fileglob*)fileport);
		return dtape_fileport_result_no_resources;
	}

	// this consumes the send right; if it fails, the right is released,
	// which destroys the port and closes the descriptor
	name = ipc_port_copyout_send(port, task->xnu_task.itk_space);
	if (!MACH_PORT_VALID(name)) {
		return dtape_fileport_result_invalid_port;
	}

	*out_port_name = name;
	return dtape_fileport_result_ok;
};

static int dup_fileport(mach_port_name_t name, struct fileglob* fg, void* context) {
	return dup(((struct dtape_fileport*)fg)->fd);
};

dtape_fileport_result_t dtape_fileport_makefd(dtape_task_t* task, uint32_t port_name, int* out_fd) {
	int fd = -1;
	kern_return_t kr;

	// this holds a send right reference while dup_fileport runs, so the
	// descriptor cannot be closed under us
	kr = fileport_invoke(&task->xnu_task, port_name, dup_fileport, NULL, &fd);
	if (kr != KERN_SUCCESS) {
		return dtape_fileport_result_invalid_port;
	}

	if (fd < 0) {
		return dtape_fileport_result_no_resources;
	}

	*out_fd = fd;
	return dtape_fileport_result_ok;
};
