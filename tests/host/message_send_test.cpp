// MessageQueue::sendMany over real AF_UNIX datagram sockets and the real sendmmsg: a reply that fails
// because of its destination is dropped and the rest of the queue is still sent; a reply that would be
// retried (EAGAIN) stays queued; a broken server socket is still fatal. src/message.cpp is compiled unchanged.
#include <darlingserver/message.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static std::string dir;

static sockaddr_un pathAddr(const std::string& name) {
	sockaddr_un a{};
	a.sun_family = AF_UNIX;
	if ((size_t)std::snprintf(a.sun_path, sizeof(a.sun_path), "%s/%s", dir.c_str(), name.c_str()) >= sizeof(a.sun_path)) {
		std::fprintf(stderr, "socket directory too long for sun_path: %s\n", dir.c_str());
		_exit(2);
	}
	return a;
}

static int boundDgram(const std::string& name) {
	int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
	sockaddr_un a = pathAddr(name);
	if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { std::perror("bind"); _exit(2); }
	return s;
}

static void queueTo(MessageQueue& q, const sockaddr_un* to, char tag) {
	Message m(64, 0);
	std::memset(m.data().data(), tag, m.data().size());
	if (to) m.setAddress(Address(*to, sizeof(*to)));
	q.push(std::move(m));
}

// returns 1 if sendMany threw, 0 if not; *more receives its result
static int sendThrows(MessageQueue& q, int sock, bool* more = nullptr) {
	try {
		bool m = q.sendMany(sock);
		if (more) *more = m;
		return 0;
	} catch (const std::exception& e) {
		std::printf("  sendMany threw: %s\n", e.what());
		return 1;
	}
}

static bool gotTag(int peer, char tag) {
	char buf[128];
	return recv(peer, buf, sizeof(buf), MSG_DONTWAIT) == 64 && buf[0] == tag;
}

// a reply to `bad` must be dropped and the following reply to `good` must still arrive
static void dropCase(int server, int good, const sockaddr_un* bad, const char* what) {
	MessageQueue q;
	queueTo(q, bad, 'x');
	sockaddr_un goodAddr = pathAddr("good.sock");
	queueTo(q, &goodAddr, 'g');
	std::string name = what;
	CHECK(!sendThrows(q, server), (name + ": sendMany does not throw").c_str());
	CHECK(q.empty(), (name + ": the failing reply is dropped and the queue drains").c_str());
	CHECK(gotTag(good, 'g'), (name + ": the next client still gets its reply").c_str());
}

int main(int, char** argv) {
	dir = argv[1]; // private directory made by run-host.sh
	int server = boundDgram("server.sock");
	int good = boundDgram("good.sock");

	{
		// peer socket connected to a different socket: the kernel refuses our datagram with EPERM
		int other = boundDgram("other.sock");
		int peer = boundDgram("peer.sock");
		sockaddr_un otherAddr = pathAddr("other.sock");
		if (connect(peer, (sockaddr*)&otherAddr, sizeof(otherAddr)) != 0) { std::perror("connect"); return 2; }
		sockaddr_un peerAddr = pathAddr("peer.sock");
		char probe = 0;
		errno = 0;
		sendto(server, &probe, 1, MSG_DONTWAIT, (sockaddr*)&peerAddr, sizeof(peerAddr));
		CHECK(errno == EPERM, "[setup] sending to a socket connected elsewhere fails with EPERM");
		dropCase(server, good, &peerAddr, "[EPERM] peer connected to another socket");
		close(peer);
		close(other);
	}
	{
		sockaddr_un gone = pathAddr("no-such.sock");
		dropCase(server, good, &gone, "[ENOENT] reply address no longer exists");
	}
	{
		int stale = boundDgram("stale.sock");
		close(stale); // the socket file stays, nobody listens: ECONNREFUSED
		sockaddr_un staleAddr = pathAddr("stale.sock");
		dropCase(server, good, &staleAddr, "[ECONNREFUSED] socket file without a listener");
	}
	{
		dropCase(server, good, nullptr, "[ENOTCONN] empty reply address on an unconnected socket");
	}
	{
		// full receive queue: EAGAIN keeps every message for a later round
		int slow = boundDgram("slow.sock");
		int small = 4096;
		setsockopt(slow, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
		sockaddr_un slowAddr = pathAddr("slow.sock");
		MessageQueue q;
		const int total = 400;
		for (int i = 0; i < total; ++i) queueTo(q, &slowAddr, (char)('A' + i % 26));
		bool more = true;
		CHECK(!sendThrows(q, server, &more), "[EAGAIN] sendMany does not throw on a full peer queue");
		CHECK(!more && !q.empty(), "[EAGAIN] it reports it cannot send more and keeps the unsent replies");
		int received = 0;
		bool inOrder = true;
		for (int rounds = 0; rounds < 1000 && received < total; ++rounds) {
			char buf[128];
			ssize_t n;
			while ((n = recv(slow, buf, sizeof(buf), MSG_DONTWAIT)) == 64) {
				if (buf[0] != (char)('A' + received % 26)) inOrder = false;
				received++;
			}
			sendThrows(q, server);
		}
		CHECK(received == total && inOrder && q.empty(), "[EAGAIN] after the peer reads, every reply arrives once, in order");
		close(slow);
	}
	{
		MessageQueue q;
		sockaddr_un goodAddr = pathAddr("good.sock");
		queueTo(q, &goodAddr, 'e');
		int closed = dup(server);
		close(closed);
		CHECK(sendThrows(q, closed) == 1, "[EBADF] a broken server socket is still fatal");
	}
	close(server);
	close(good);
	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
