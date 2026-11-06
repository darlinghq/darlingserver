// Credentials attached to outgoing messages (src/message.cpp, compiled unchanged): the cached server
// credentials are the process's own, the kernel accepts them on an SO_PASSCRED socket, they can only be
// initialized once, and a forked child sends its own PID instead of the parent's.
#include <darlingserver/message.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// sends one Message from `sender` and returns the credentials the kernel delivered to `receiver`
static bool sendAndReceive(int sender, int receiver, struct ucred& received) {
	Message message(16, 0);
	std::memset(message.data().data(), 'm', message.data().size());
	// the socket pair is connected, so send without the message's (empty) address
	struct msghdr outgoing = message.rawHeader();
	outgoing.msg_name = nullptr;
	outgoing.msg_namelen = 0;
	if (sendmsg(sender, &outgoing, 0) < 0) {
		std::printf("  sendmsg: %s\n", std::strerror(errno));
		return false;
	}

	char data[16];
	alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(struct ucred))];
	struct iovec iov = { data, sizeof(data) };
	struct msghdr header = {};
	header.msg_iov = &iov;
	header.msg_iovlen = 1;
	header.msg_control = control;
	header.msg_controllen = sizeof(control);
	if (recvmsg(receiver, &header, 0) < 0) {
		return false;
	}
	for (auto cmsg = CMSG_FIRSTHDR(&header); cmsg; cmsg = CMSG_NXTHDR(&header, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
			std::memcpy(&received, CMSG_DATA(cmsg), sizeof(received));
			return true;
		}
	}
	return false;
}

static bool ownCredentials(const struct ucred& creds) {
	return creds.pid == getpid() && creds.uid == getuid() && creds.gid == getgid();
}

int main() {
	int pair[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) != 0) {
		std::perror("socketpair");
		return 2;
	}
	int one = 1;
	setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));

	struct ucred creds = {};
	CHECK(sendAndReceive(pair[0], pair[1], creds) && ownCredentials(creds), "without a cache, a message carries the process's credentials");

	Message::initializeServerCredentials();
	creds = {};
	CHECK(sendAndReceive(pair[0], pair[1], creds) && ownCredentials(creds), "with the cache, a message carries the process's credentials");

	bool threw = false;
	try {
		Message::initializeServerCredentials();
	} catch (const std::logic_error&) {
		threw = true;
	}
	CHECK(threw, "the cache cannot be initialized twice");

	pid_t child = fork();
	if (child == 0) {
		struct ucred childCreds = {};
		// a message carrying the parent's PID would be rejected by the kernel with EPERM
		_exit(sendAndReceive(pair[0], pair[1], childCreds) && childCreds.pid == getpid() ? 0 : 1);
	}
	int status = 0;
	waitpid(child, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "a forked child sends its own PID, not the cached one");

	creds = {};
	CHECK(sendAndReceive(pair[0], pair[1], creds) && ownCredentials(creds), "the parent still sends its own credentials after the fork");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
