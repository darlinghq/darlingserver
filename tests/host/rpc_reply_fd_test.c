// Drives the generated dserver_rpc_console_open() (a reply with one descriptor) against a fake
// server on a socketpair. The reply body carries an index into the descriptors that came with it;
// an index the message does not back must be rejected, not used to index the local array.
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "rpc_hooks.h"
#include RPC_GENERATED_SOURCE

int hook_socket = -1;

static int failures = 0;
static int checks = 0;

static void check(bool ok, const char* what) {
	checks++;
	if (!ok) {
		failures++;
		printf("FAIL: %s\n", what);
	}
}

static int openFDCount() {
	int n = 0;
	DIR* d = opendir("/proc/self/fd");
	while (readdir(d))
		n++;
	closedir(d);
	return n;
}

// Queues one console_open reply on the client's end of the socketpair, as the server would:
// `index` in the body, `attached` descriptors (all the read end of a fresh pipe) in the message.
static void queueReply(int serverEnd, int32_t index, int attached) {
	dserver_rpc_reply_console_open_t reply;
	memset(&reply, 0, sizeof(reply));
	reply.header.number = dserver_callnum_console_open;
	reply.header.code = 0;
	reply.body.console = index;

	int pipefds[2];
	if (pipe(pipefds) != 0)
		abort();

	char control[CMSG_SPACE(sizeof(int) * 2)];
	memset(control, 0, sizeof(control));
	struct iovec iov = { &reply, sizeof(reply) };
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (attached > 0) {
		msg.msg_control = control;
		msg.msg_controllen = CMSG_SPACE(sizeof(int) * attached);
		struct cmsghdr* c = CMSG_FIRSTHDR(&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int) * attached);
		int fds[2] = { pipefds[0], pipefds[0] };
		memcpy(CMSG_DATA(c), fds, sizeof(int) * attached);
	}
	if (sendmsg(serverEnd, &msg, 0) != (ssize_t)sizeof(reply))
		abort();
	close(pipefds[0]);
	close(pipefds[1]);
}

static void drain(int serverEnd) {
	char buf[512];
	recv(serverEnd, buf, sizeof(buf), MSG_DONTWAIT);
}

typedef struct {
	int status;
	int out;
	int fdDelta;
} Result;

static Result run(int32_t index, int attached) {
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
		abort();
	hook_socket = sv[0];
	queueReply(sv[1], index, attached);
	int before = openFDCount();
	Result r;
	r.out = -77;
	r.status = dserver_rpc_console_open(&r.out);
	r.fdDelta = openFDCount() - before;
	if (r.out >= 0)
		close(r.out);
	drain(sv[1]);
	close(sv[0]);
	close(sv[1]);
	return r;
}

int main() {
	Result r;

	r = run(0, 1);
	check(r.status == 0, "index 0 of 1 descriptor: call succeeds");
	check(r.out >= 0, "index 0 of 1 descriptor: descriptor returned");

	r = run(-1, 0);
	check(r.status == 0 && r.out == -1, "index -1: no descriptor, out is -1");

	const int32_t bad[] = { 1, 2, 1000000, 2147483647 };
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		int32_t index = bad[i];
		char msg[96];
		r = run(index, 1);
		snprintf(msg, sizeof(msg), "index %d of 1 descriptor: rejected as a bad message", index);
		check(r.status == HOOK_BAD_MESSAGE, msg);
		snprintf(msg, sizeof(msg), "index %d of 1 descriptor: out parameter untouched", index);
		check(r.out == -77, msg);
		snprintf(msg, sizeof(msg), "index %d of 1 descriptor: the received descriptor is closed", index);
		check(r.fdDelta == 0, msg);
	}

	printf("%d of %d checks passed\n", checks - failures, checks);
	return failures ? 1 : 0;
}
