// A push_reply call carries the write end of the client's synchronization pipe. Whether the call is
// accepted or rejected, the server must not keep that descriptor open: the client thread blocks reading
// the other end and is released by one byte (accepted) or by EOF (rejected).
// Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are stand-ins.
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// process: kernel pid 500, namespace pid 100, thread 101
static void reset() {
	procs.m.clear(); threads.m.clear();
	auto p = std::make_shared<Process>(500, 100, Process::Architecture::x86_64, -1);
	procs.m[100] = p;
	threads.m[101] = std::make_shared<Thread>(p, 101, nullptr);
}

static Message pushReply(pid_t kernelPid, int writeEnd) {
	Message m;
	m.bytes.resize(sizeof(dserver_rpc_call_push_reply_t));
	auto c = reinterpret_cast<dserver_rpc_call_push_reply_t*>(m.bytes.data());
	c->header.number = dserver_callnum_push_reply;
	c->header.pid = 100;
	c->header.tid = 101;
	c->reply_size = 16;
	m.kernelPid = kernelPid;
	m.fds = {writeEnd};
	return m;
}

static bool threw(Message m) {
	try { Call::callFromMessage(std::move(m)); return false; } catch (const std::exception&) { return true; }
}

// what the client's read of the pipe sees: 1 = a byte, 0 = EOF, -1 = would block (a write end is still open)
static int clientRead(int readEnd) {
	char c;
	ssize_t n = read(readEnd, &c, 1);
	return n < 0 ? -1 : (int)n;
}

int main(int, char**) {
	int p[2];

	// rejected: no interrupt is in progress on the thread
	reset();
	if (pipe2(p, O_NONBLOCK | O_CLOEXEC) != 0) return 2;
	CHECK(threw(pushReply(500, p[1])), "push_reply outside an interrupt is rejected");
	CHECK(clientRead(p[0]) == 0, "the client sees EOF: the server closed its copy of the pipe");
	close(p[0]);

	// rejected: kernel pid mismatch
	reset();
	if (pipe2(p, O_NONBLOCK | O_CLOEXEC) != 0) return 2;
	CHECK(threw(pushReply(999, p[1])), "push_reply with a mismatched kernel pid is rejected");
	CHECK(clientRead(p[0]) == 0, "the client sees EOF after a pid mismatch");
	close(p[0]);

	// accepted: an interrupt is in progress, the byte is written and the pipe closed
	reset();
	threads.m[101]->_interrupts.push({});
	if (pipe2(p, O_NONBLOCK | O_CLOEXEC) != 0) return 2;
	CHECK(!threw(pushReply(500, p[1])), "push_reply during an interrupt is accepted");
	CHECK(threads.m[101]->_interrupts.top().savedReply.has_value(), "the reply is saved on the interrupt");
	CHECK(clientRead(p[0]) == 1, "the client receives its byte");
	CHECK(clientRead(p[0]) == 0, "and then EOF: the server closed the pipe");
	close(p[0]);

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
