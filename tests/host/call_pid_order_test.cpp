// A message whose kernel-reported pid does not match the recorded process must be rejected before it
// can register a thread or replace a registered thread's reply address.
// Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are stand-ins.
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// process: kernel pid 500, namespace pid 100, thread 101 registered with reply address "registered"
static void reset() {
	procs.m.clear(); threads.m.clear();
	auto p = std::make_shared<Process>(500, 100, Process::Architecture::x86_64, -1);
	procs.m[100] = p;
	auto t = std::make_shared<Thread>(p, 101, nullptr);
	t->address = "registered";
	threads.m[101] = t;
}

static Message msg(uint32_t number, pid_t kernelPid, pid_t nspid, pid_t tid, size_t size) {
	Message m;
	m.bytes.resize(size);
	if (size >= sizeof(dserver_rpc_callhdr_t)) {
		auto h = reinterpret_cast<dserver_rpc_callhdr_t*>(m.bytes.data());
		h->number = number; h->pid = nspid; h->tid = tid;
	}
	m.kernelPid = kernelPid; m.addr = "sender";
	return m;
}

static bool threw(Message m) {
	try { Call::callFromMessage(std::move(m)); return false; } catch (const std::exception&) { return true; }
}

int main(int, char**) {
	reset();
	CHECK(threw(msg(dserver_callnum_dummy, 999, 100, 101, 64)), "pid mismatch on a registered thread is rejected");
	CHECK(threads.m[101]->address == "registered", "the rejected message did not replace the thread's reply address");
	CHECK(threw(msg(dserver_callnum_dummy, 999, 100, 102, 64)), "pid mismatch with a new thread id is rejected");
	CHECK(!threads.m.count(102), "the rejected message did not register a thread");
	CHECK(threw(msg(dserver_callnum_dummy, 500, 100, 101, 4)), "a message shorter than the call header is rejected");
	CHECK(threw(msg(0x1234, 500, 100, 101, 64)), "an unknown call number is rejected");
	CHECK(!threw(msg(dserver_callnum_dummy, 500, 100, 101, 64)) && threads.m[101]->address == "sender",
		"a matching message is accepted and updates the reply address");
	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
