// A managed call names its thread by namespace tid in the header. The thread found in the registry must
// belong to the process the message was checked against; otherwise one process could run a call on another
// process's thread and replace its reply address.
// Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are stand-ins.
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

// process A: kernel pid 500, namespace pid 100, thread 101 (reply address "a-registered")
// process B: kernel pid 600, namespace pid 200, thread 201 (reply address "b-registered")
static void reset() {
	procs.m.clear(); threads.m.clear();
	auto a = std::make_shared<Process>(500, 100, Process::Architecture::x86_64, -1);
	procs.m[100] = a;
	auto ta = std::make_shared<Thread>(a, 101, nullptr);
	ta->address = "a-registered";
	threads.m[101] = ta;
	auto b = std::make_shared<Process>(600, 200, Process::Architecture::x86_64, -1);
	procs.m[200] = b;
	auto tb = std::make_shared<Thread>(b, 201, nullptr);
	tb->address = "b-registered";
	threads.m[201] = tb;
}

static Message msg(uint32_t number, pid_t kernelPid, pid_t nspid, pid_t tid) {
	Message m;
	m.bytes.resize(64);
	auto h = reinterpret_cast<dserver_rpc_callhdr_t*>(m.bytes.data());
	h->number = number; h->pid = nspid; h->tid = tid;
	m.kernelPid = kernelPid; m.addr = "sender";
	return m;
}

static bool threw(Message m) {
	try { Call::callFromMessage(std::move(m)); return false; } catch (const std::exception&) { return true; }
}

int main(int, char**) {
	reset();
	CHECK(threw(msg(dserver_callnum_dummy, 600, 200, 101)), "B naming A's thread is rejected");
	CHECK(threads.m[101]->address == "a-registered", "A's thread keeps its reply address");
	CHECK(threads.m[101]->_pendingCall == nullptr, "no call is queued on A's thread");

	// B's kernel pid is 600 but the header claims A's namespace pid 100 and A's thread 101
	reset();
	CHECK(threw(msg(dserver_callnum_dummy, 600, 100, 101)), "B claiming A's pid and thread is rejected");
	CHECK(threads.m[101]->address == "a-registered", "A's reply address survives a spoofed pid and tid");

	reset();
	CHECK(!threw(msg(dserver_callnum_dummy, 600, 200, 201)) && threads.m[201]->address == "sender", "B on its own registered thread is accepted");
	CHECK(!threw(msg(dserver_callnum_dummy, 600, 200, 202)) && threads.m.count(202) && threads.m[202]->process() == procs.m[200],
		"B on a new thread id is accepted and the thread is bound to B");

	reset();
	threads.m[101]->_process = nullptr; // a thread detached from its process, as at exec
	CHECK(threw(msg(dserver_callnum_dummy, 500, 100, 101)), "a registered thread detached from its process is rejected");

	reset();
	CHECK(!threw(msg(dserver_callnum_dbg, 600, 200, 101)), "an unmanaged call does not look up a thread, so it is not affected");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
