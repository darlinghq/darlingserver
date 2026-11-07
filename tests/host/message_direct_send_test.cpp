// MessageQueue::pushAndSend over real AF_UNIX datagram sockets: the caller sends the message itself,
// the owner's notification callback fires only when messages are left over (socket full, or an error),
// a message never overtakes ones queued before it (also with several threads sending at once), the
// descriptors a message carries are closed on the sending side once it is sent, and a dead peer
// neither throws nor blocks the queue. src/message.cpp is compiled unchanged.
#include <darlingserver/message.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace DarlingServer;
static int fails;
static std::string dir;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static int openFds() {
	int n = 0;
	DIR* d = opendir("/proc/self/fd");
	while (readdir(d)) n++;
	closedir(d);
	return n;
}

static sockaddr_un addressOf(const std::string& path) {
	sockaddr_un a{};
	a.sun_family = AF_UNIX;
	std::snprintf(a.sun_path, sizeof(a.sun_path), "%s", path.c_str());
	return a;
}

// a client endpoint bound to its own address, like a guest thread's RPC socket
struct Peer {
	int fd;
	std::string path;
	explicit Peer(const char* name): path(dir + "/" + name) {
		fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
		sockaddr_un a = addressOf(path);
		if (bind(fd, (sockaddr*)&a, sizeof(a)) != 0) std::perror("bind");
	}
	~Peer() {
		if (fd >= 0) close(fd);
		unlink(path.c_str());
	}
};

// the server's listener; a small send buffer makes it run full quickly
static int serverSocket(int sendBuffer) {
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sendBuffer) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendBuffer, sizeof(sendBuffer));
	return fd;
}

static Message tagged(const std::string& to, uint64_t tag, size_t size = 64, size_t descriptorSpace = 0) {
	Message m(size, descriptorSpace);
	std::memcpy(m.data().data(), &tag, sizeof(tag));
	m.setAddress(Address(addressOf(to)));
	return m;
}

// reads one datagram; returns false if none is waiting
static bool receiveTag(int fd, uint64_t* tag, std::vector<int>* fds = nullptr) {
	unsigned char buf[512];
	alignas(cmsghdr) char ctl[CMSG_SPACE(sizeof(int) * 8)];
	iovec iov{buf, sizeof(buf)};
	msghdr mh{};
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = ctl;
	mh.msg_controllen = sizeof(ctl);
	ssize_t r = recvmsg(fd, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
	if (r < (ssize_t)sizeof(*tag)) return false;
	std::memcpy(tag, buf, sizeof(*tag));
	for (cmsghdr* c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
		if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
		size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		for (size_t i = 0; i < n; ++i) {
			int d;
			std::memcpy(&d, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
			if (fds) fds->push_back(d); else close(d);
		}
	}
	return true;
}

static void notifications() {
	int server = serverSocket(4096);
	Peer peer("notify.sock");
	MessageQueue q;
	unsigned callbacks = 0;
	bool emptyCallback = false;
	q.setMessageArrivalNotificationCallback([&]() {
		callbacks++;
		emptyCallback = emptyCallback || q.empty();
	});

	q.pushAndSend(tagged(peer.path, 1), server);
	uint64_t tag = 0;
	CHECK(callbacks == 0 && q.empty(), "[notify] a message the socket takes is sent without notifying the owner");
	CHECK(receiveTag(peer.fd, &tag) && tag == 1, "[notify] ... and arrives");

	// the peer does not read, so the socket runs full
	for (uint64_t i = 0; i < 64; ++i) q.pushAndSend(tagged(peer.path, 100 + i), server);
	CHECK(callbacks > 0 && !q.empty() && !emptyCallback, "[notify] once the socket is full, the owner is notified and the rest stays queued");

	// the owner's retry (the server's main loop) sends the rest; nothing is lost or reordered
	unsigned before = callbacks;
	std::vector<uint64_t> got;
	for (int spin = 0; got.size() < 64 && spin < 20000; ++spin) {
		q.sendMany(server);
		while (receiveTag(peer.fd, &tag)) got.push_back(tag);
		if (got.size() < 64) std::this_thread::sleep_for(std::chrono::microseconds(50));
	}
	bool inOrder = got.size() == 64;
	for (size_t i = 0; inOrder && i < 64; ++i) inOrder = got[i] == 100 + i;
	CHECK(inOrder && q.empty(), "[notify] the owner's retries deliver the rest in order");
	CHECK(callbacks == before, "[notify] sendMany itself never notifies");

	// a message sent while others are still queued goes out after them
	for (uint64_t i = 0; i < 64; ++i) q.pushAndSend(tagged(peer.path, 200 + i), server);
	while (receiveTag(peer.fd, &tag)) {}
	q.pushAndSend(tagged(peer.path, 999), server);
	got.clear();
	for (int spin = 0; (got.empty() || got.back() != 999) && spin < 20000; ++spin) {
		q.sendMany(server);
		while (receiveTag(peer.fd, &tag)) got.push_back(tag);
		if (got.empty() || got.back() != 999) std::this_thread::sleep_for(std::chrono::microseconds(50));
	}
	bool last = !got.empty() && got.back() == 999;
	for (size_t i = 0; last && i + 1 < got.size(); ++i) last = got[i] >= 200 && got[i] < 264 && (i == 0 || got[i] == got[i - 1] + 1);
	CHECK(last && q.empty(), "[notify] a direct send does not overtake messages queued before it");

	// an error on the socket itself is thrown, with the message still queued and the owner notified
	close(server);
	callbacks = 0;
	bool threw = false;
	try {
		q.pushAndSend(tagged(peer.path, 300), server);
	} catch (const std::system_error& e) {
		threw = e.code().value() == EBADF;
	}
	CHECK(threw && callbacks == 1 && !q.empty(), "[notify] a socket error is thrown after notifying, and the message stays queued");
}

static void concurrentSenders() {
	int server = serverSocket(4096); // small, so that direct sends and the owner's retries mix
	Peer peer("concurrent.sock");
	MessageQueue q;
	std::atomic<unsigned> callbacks{0};
	q.setMessageArrivalNotificationCallback([&]() { callbacks++; });

	constexpr unsigned senders = 4, perSender = 2000;
	std::vector<std::thread> threads;
	for (unsigned s = 0; s < senders; ++s) {
		threads.emplace_back([&, s]() {
			for (uint64_t i = 0; i < perSender; ++i) q.pushAndSend(tagged(peer.path, ((uint64_t)s << 32) | i), server);
		});
	}

	// the owner's part: retry whatever the senders had to leave queued, while the peer reads
	std::vector<uint64_t> next(senders, 0);
	unsigned received = 0;
	bool ordered = true;
	for (int spin = 0; received < senders * perSender && spin < 400000; ++spin) {
		q.sendMany(server);
		uint64_t tag;
		while (receiveTag(peer.fd, &tag)) {
			unsigned s = tag >> 32;
			if (s >= senders || (tag & 0xffffffff) != next[s]) ordered = false;
			else next[s]++;
			received++;
		}
		if (received < senders * perSender) std::this_thread::sleep_for(std::chrono::microseconds(50));
	}
	for (auto& t : threads) t.join();
	std::printf("  %u messages from %u threads, %u notification(s)\n", received, senders, callbacks.load());
	CHECK(received == senders * perSender && q.empty(), "[concurrent] every message from 4 sending threads arrives once");
	CHECK(ordered, "[concurrent] each thread's messages arrive in the order it sent them");
	close(server);
}

static void descriptors() {
	int server = serverSocket(65536);
	Peer peer("fds.sock");
	MessageQueue q;
	int baseline = openFds();
	bool closedAfterSend = true;
	for (uint64_t i = 0; i < 8; ++i) {
		Message m = tagged(peer.path, 400 + i, 64, 2);
		for (int d = 0; d < 2; ++d) {
			int p[2];
			pipe2(p, O_CLOEXEC);
			unsigned char b = i * 2 + d;
			write(p[1], &b, 1);
			close(p[1]);
			m.pushDescriptor(p[0]);
		}
		q.pushAndSend(std::move(m), server);
		closedAfterSend = closedAfterSend && openFds() == baseline;
	}
	CHECK(closedAfterSend && q.empty(), "[descriptors] the sender's copies are closed once each message is sent");
	bool ok = true;
	for (uint64_t i = 0; i < 8; ++i) {
		uint64_t tag = 0;
		std::vector<int> fds;
		ok = receiveTag(peer.fd, &tag, &fds) && tag == 400 + i && fds.size() == 2 && ok;
		for (size_t d = 0; d < fds.size(); ++d) {
			unsigned char b = 0;
			ok = read(fds[d], &b, 1) == 1 && b == (unsigned char)(i * 2 + d) && ok;
			close(fds[d]);
		}
	}
	CHECK(ok && openFds() == baseline, "[descriptors] the peer receives both descriptors of every message");
	close(server);
}

static void deadPeers() {
	int server = serverSocket(0);
	Peer live("live.sock");
	MessageQueue q;
	unsigned callbacks = 0;
	q.setMessageArrivalNotificationCallback([&]() { callbacks++; });
	bool threw = false;
	try {
		// the peer's address is gone (ENOENT)
		q.pushAndSend(tagged(dir + "/gone.sock", 500), server);
		// the address exists, but nobody listens on it any more (ECONNREFUSED)
		{
			Peer closed("closed.sock");
			close(closed.fd);
			closed.fd = -1;
			q.pushAndSend(tagged(closed.path, 501), server);
			q.pushAndSend(tagged(closed.path, 502), server);
		}
		q.pushAndSend(tagged(live.path, 503), server);
	} catch (const std::exception&) {
		threw = true;
	}
	uint64_t tag = 0;
	CHECK(!threw && q.empty() && callbacks == 0, "[dead peer] messages to dead peers are dropped without an error or a notification");
	CHECK(receiveTag(live.fd, &tag) && tag == 503, "[dead peer] the next message still reaches its live peer");
	close(server);
}

int main(int, char** argv) {
	dir = argv[1]; // private directory made by run-host.sh
	if (dir.size() + sizeof("/concurrent.sock") > sizeof(sockaddr_un::sun_path)) {
		std::fprintf(stderr, "socket directory too long for sun_path: %s\n", dir.c_str());
		return 2;
	}
	notifications();
	concurrentSenders();
	descriptors();
	deadPeers();
	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
