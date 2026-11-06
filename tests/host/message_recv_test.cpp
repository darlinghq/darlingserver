// MessageQueue::receiveMany over real AF_UNIX sockets: a datagram that did not fit the receive buffer
// (MSG_TRUNC for the body, MSG_CTRUNC for the descriptors) must not be queued, and the descriptors it
// carried must not stay open. src/message.cpp is compiled unchanged.
#include <darlingserver/message.hpp>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static int openFds() {
	int n = 0;
	DIR* d = opendir("/proc/self/fd");
	while (readdir(d)) n++;
	closedir(d);
	return n;
}

// sends `len` bytes carrying `nfds` descriptors; returns the sendmsg result or -errno
static int sendWithFds(int s, const sockaddr_un* to, size_t len, int nfds) {
	char data[512];
	std::memset(data, 'x', sizeof(data));
	iovec iov{data, len};
	int fds[16];
	for (int i = 0; i < nfds; ++i) fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
	alignas(cmsghdr) char ctl[CMSG_SPACE(sizeof(fds))];
	msghdr mh{};
	mh.msg_name = (void*)to;
	mh.msg_namelen = to ? sizeof(*to) : 0;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	if (nfds) {
		mh.msg_control = ctl;
		mh.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
		cmsghdr* c = CMSG_FIRSTHDR(&mh);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
		std::memcpy(CMSG_DATA(c), fds, sizeof(int) * nfds);
	}
	ssize_t r = sendmsg(s, &mh, 0);
	int err = errno;
	for (int i = 0; i < nfds; ++i) close(fds[i]);
	return r < 0 ? -err : (int)r;
}

static size_t drain(MessageQueue& q, size_t* descriptorTotal) {
	size_t n = 0;
	*descriptorTotal = 0;
	while (auto m = q.pop()) {
		n++;
		*descriptorTotal += m->descriptors().size();
	}
	return n;
}

int main(int, char** argv) {
	std::string dir = argv[1]; // private directory made by run-host.sh
	sockaddr_un serverAddr{};
	serverAddr.sun_family = AF_UNIX;
	if (dir.size() + sizeof("/server.sock") > sizeof(serverAddr.sun_path)) {
		std::fprintf(stderr, "socket directory too long for sun_path: %s\n", dir.c_str());
		return 2;
	}
	std::snprintf(serverAddr.sun_path, sizeof(serverAddr.sun_path), "%s/server.sock", dir.c_str());

	// datagram listener as in Server::start, plus a raw sender
	int server = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	int one = 1;
	setsockopt(server, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
	if (bind(server, (sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) { std::perror("bind"); return 2; }
	int client = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	size_t descs = 0;

	{
		int baseline = openFds();
		MessageQueue q;
		CHECK(sendWithFds(client, &serverAddr, 300, 1) == 300, "sent a datagram longer than the 256-byte receive buffer, with 1 descriptor");
		CHECK(sendWithFds(client, &serverAddr, 64, 6) == 64, "sent a datagram with 6 descriptors (4 receive slots)");
		q.receiveMany(server);
		CHECK(q.empty(), "[datagram] neither the cut body nor the cut descriptor set is queued");
		CHECK(openFds() == baseline, "[datagram] no descriptor of the dropped datagrams stays open after the receive round");
	}
	{
		MessageQueue q;
		sendWithFds(client, &serverAddr, 300, 1);
		sendWithFds(client, &serverAddr, 64, 6);
		sendWithFds(client, &serverAddr, 64, 1);
		q.receiveMany(server);
		size_t n = drain(q, &descs);
		std::printf("  queued %zu message(s), %zu descriptor(s)\n", n, descs);
		CHECK(n == 1 && descs == 1, "[datagram] a well-formed datagram after two dropped ones is still queued with its descriptor");
	}
	{
		// the kqchan sockets are SOCK_SEQPACKET socketpairs without SO_PASSCRED
		int sp[2];
		socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sp);
		fcntl(sp[0], F_SETFL, O_NONBLOCK);
		int before = openFds();
		MessageQueue q;
		sendWithFds(sp[1], nullptr, 300, 2);
		sendWithFds(sp[1], nullptr, 6, 14); // without SO_PASSCRED the credentials slot is free, so 12 descriptors fit
		q.receiveMany(sp[0]);
		CHECK(q.empty(), "[seqpacket] neither the cut record nor the cut descriptor set is queued");
		CHECK(openFds() == before, "[seqpacket] no descriptor of the dropped records stays open");
		sendWithFds(sp[1], nullptr, 32, 0);
		q.receiveMany(sp[0]);
		size_t n = drain(q, &descs);
		CHECK(n == 1, "[seqpacket] the record after the dropped ones is queued");
		close(sp[0]);
		close(sp[1]);
	}
	close(client);
	close(server);
	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
