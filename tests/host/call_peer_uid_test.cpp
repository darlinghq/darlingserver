// A message whose kernel-reported (SCM_CREDENTIALS) uid differs from the server's uid is rejected before
// any process or thread is registered, for managed and unmanaged calls alike. The uids are derived from
// getuid(), so the result does not depend on who runs the test.
// Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are stand-ins.
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static Message msg(uint32_t number, uid_t uid) {
	Message m;
	m.bytes.resize(64);
	auto h = reinterpret_cast<dserver_rpc_callhdr_t*>(m.bytes.data());
	h->number = number; h->pid = 300; h->tid = 301;
	m.kernelPid = 700; m.kernelUid = uid; m.addr = "sender";
	return m;
}

static bool threw(Message m) {
	try { Call::callFromMessage(std::move(m)); return false; } catch (const std::exception&) { return true; }
}

int main(int, char**) {
	const uid_t self = getuid(), other = self + 1;

	procs.m.clear(); threads.m.clear();
	CHECK(threw(msg(dserver_callnum_dummy, other)), "a managed call from another uid is rejected");
	CHECK(!procs.m.count(300) && !threads.m.count(301), "it registers no process or thread");
	CHECK(threw(msg(dserver_callnum_dbg, other)), "an unmanaged call from another uid is rejected");
	CHECK(threw(msg(dserver_callnum_s2c, other)), "an S2C reply from another uid is rejected");
	CHECK(threw(msg(dserver_callnum_dummy, (uid_t)-1)), "a message without credentials (uid -1) is rejected");

	CHECK(!threw(msg(dserver_callnum_dummy, self)) && procs.m.count(300), "a managed call from the server's uid is accepted");
	CHECK(!threw(msg(dserver_callnum_dbg, self)), "an unmanaged call from the server's uid is accepted");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
