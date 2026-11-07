// MessageQueue::receiveMany keeps its receive buffers between rounds: a round that finds nothing
// allocates nothing, and a round that receives one message replaces only that message's buffer.
// Reused buffers still receive full-size messages with all their descriptors, and the descriptors
// of a message are closed when receiving fails half-way. A Message whose data buffer cannot be
// allocated does not leak its control buffer. src/message.cpp is compiled unchanged.
#include <darlingserver/message.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <new>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// counts operator new calls while `counting` is set, and makes the next one throw while `failNext` is set
static bool counting, failNext;
static unsigned allocations;

void* operator new(size_t size) {
	if (failNext) {
		failNext = false;
		throw std::bad_alloc();
	}
	if (counting) {
		allocations++;
	}
	if (void* p = std::malloc(size ? size : 1)) {
		return p;
	}
	throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }

static int openFds() {
	int n = 0;
	DIR* d = opendir("/proc/self/fd");
	while (readdir(d)) n++;
	closedir(d);
	return n;
}

// sends `len` bytes, each `tag + index`, with `nfds` pipe read ends; the byte in pipe k is `tag + k`
static bool sendTagged(int s, const sockaddr_un* to, unsigned char tag, size_t len, int nfds) {
	unsigned char data[512];
	for (size_t i = 0; i < len; ++i) data[i] = tag + i;
	iovec iov{data, len};
	int fds[8];
	for (int i = 0; i < nfds; ++i) {
		int p[2];
		if (pipe2(p, O_CLOEXEC) != 0) return false;
		unsigned char b = tag + i;
		if (write(p[1], &b, 1) != 1) return false;
		close(p[1]);
		fds[i] = p[0];
	}
	alignas(cmsghdr) char ctl[CMSG_SPACE(sizeof(fds))];
	msghdr mh{};
	mh.msg_name = (void*)to;
	mh.msg_namelen = sizeof(*to);
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
	for (int i = 0; i < nfds; ++i) close(fds[i]);
	return r == (ssize_t)len;
}

// pops one message and checks that it is the one sendTagged() sent
static bool popTagged(MessageQueue& q, unsigned char tag, size_t len, int nfds) {
	auto m = q.pop();
	if (!m || m->data().size() != len) return false;
	for (size_t i = 0; i < len; ++i) {
		if (m->data()[i] != (unsigned char)(tag + i)) return false;
	}
	if ((int)m->descriptors().size() != nfds || m->pid() != getpid()) return false;
	for (int i = 0; i < nfds; ++i) {
		int fd = m->extractDescriptorAtIndex(0);
		unsigned char b = 0;
		bool ok = fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) && read(fd, &b, 1) == 1 && b == (unsigned char)(tag + i);
		close(fd);
		if (!ok) return false;
	}
	return true;
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
	int baseline = openFds();

	{
		MessageQueue q;
		q.receiveMany(server); // the first round sets up the buffers

		allocations = 0;
		counting = true;
		bool more = q.receiveMany(server);
		counting = false;
		std::printf("  a round with nothing to receive: %u allocation(s)\n", allocations);
		CHECK(!more && q.empty() && allocations == 0, "[reuse] a round with nothing to receive allocates nothing");

		sendTagged(client, &serverAddr, 10, 100, 2);
		allocations = 0;
		counting = true;
		q.receiveMany(server);
		q.receiveMany(server);
		counting = false;
		std::printf("  a round with one message, then an empty one: %u allocation(s)\n", allocations);
		CHECK(allocations <= 2, "[reuse] receiving one message replaces only that message's buffer (at most a queue node besides)");
		CHECK(popTagged(q, 10, 100, 2), "[reuse] the message arrives with its payload, sender credentials and descriptors");

		// slot 0 was used, slots 1.. were not: both kinds must still take a full-size message with 4 descriptors
		for (int round = 0; round < 3; ++round) {
			for (int i = 0; i < 5; ++i) sendTagged(client, &serverAddr, 20 + i, i == round ? 256 : 1 + i, i == round ? 4 : i % 2);
			q.receiveMany(server);
			bool ok = true;
			for (int i = 0; i < 5; ++i) ok = popTagged(q, 20 + i, i == round ? 256 : 1 + i, i == round ? 4 : i % 2) && ok;
			CHECK(ok && q.empty(), "[reuse] reused buffers receive a 256-byte message with 4 descriptors after shorter ones");
		}

		// more than one batch, with the batches' slots used again in the same call
		for (int i = 0; i < 40; ++i) sendTagged(client, &serverAddr, i, (i * 7) % 257, i % 5);
		q.receiveMany(server);
		bool ok = true;
		for (int i = 0; i < 40; ++i) ok = popTagged(q, i, (i * 7) % 257, i % 5) && ok;
		CHECK(ok && q.empty(), "[reuse] 40 messages over three batches arrive intact and in order");

		// a message that did not fit, received into a reused buffer, is dropped with its descriptors
		sendTagged(client, &serverAddr, 30, 300, 1);
		sendTagged(client, &serverAddr, 31, 8, 6);
		sendTagged(client, &serverAddr, 32, 8, 1);
		q.receiveMany(server);
		CHECK(popTagged(q, 32, 8, 1) && q.empty(), "[reuse] cut messages are dropped, the next one is queued");
	}
	CHECK(openFds() == baseline, "[reuse] no descriptor stays open once the queue is gone");

	{
		// an allocation failure after recvmmsg (the queue growing) must not leak what was received
		MessageQueue q;
		q.receiveMany(server);
		for (int i = 0; i < 12; ++i) sendTagged(client, &serverAddr, 40 + i, 8, 1 + i % 4);
		failNext = true;
		bool threw = false;
		try {
			q.receiveMany(server);
		} catch (const std::bad_alloc&) {
			threw = true;
		}
		failNext = false;
		while (q.pop()) {}
		// drop whatever is still waiting in the socket
		while (q.receiveMany(server) || !q.empty()) {
			while (q.pop()) {}
		}
		CHECK(threw, "[failure] the injected allocation failure reached the caller");
		CHECK(openFds() == baseline, "[failure] every received descriptor is closed");
		sendTagged(client, &serverAddr, 60, 64, 3);
		q.receiveMany(server);
		CHECK(popTagged(q, 60, 64, 3), "[failure] the queue receives normally afterwards");
	}
	CHECK(openFds() == baseline, "[failure] no descriptor stays open once the queue is gone");

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
	{
		// the control buffer is allocated with malloc; a failing data buffer must not strand it
		// (under ASan, mallinfo2 does not see ASan's heap, and LeakSanitizer reports the leak instead)
		auto inUse = []() { return mallinfo2().uordblks; };
		for (int warm = 0; warm < 2; ++warm) {
			try { failNext = true; Message m(256, 4); } catch (const std::bad_alloc&) {}
		}
		size_t before = inUse();
		int thrown = 0;
		for (int i = 0; i < 100; ++i) {
			try {
				failNext = true;
				Message m(256, 4);
			} catch (const std::bad_alloc&) {
				thrown++;
			}
		}
		failNext = false;
		size_t after = inUse();
		std::printf("  heap in use before %zu, after 100 failed constructions %zu\n", before, after);
		CHECK(thrown == 100 && after <= before, "[constructor] a Message whose data buffer cannot be allocated frees its control buffer");
	}
#endif

	close(client);
	close(server);
	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
