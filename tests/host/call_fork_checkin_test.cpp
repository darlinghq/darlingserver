// A process first seen through a fork child's check-in must be created as a fork child, so that its
// task keeps the parent's architecture whatever architecture the child reports in the call header.
// Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are stand-ins.
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static Message checkin(pid_t pid, bool isFork, pid_t parentPid = 0) {
	Message m;
	m.bytes.resize(sizeof(dserver_rpc_call_checkin_t));
	auto call = reinterpret_cast<dserver_rpc_call_checkin_t*>(m.bytes.data());
	call->header.number = dserver_callnum_checkin;
	call->header.pid = pid;
	call->header.tid = pid;
	call->body.lifetime_listener_pipe = -1;
	call->body.is_fork = isFork;
	call->body.parent_pid = parentPid;
	m.kernelPid = pid + 400; m.addr = "sender";
	return m;
}

static Message dummy(pid_t pid) {
	Message m;
	m.bytes.resize(64);
	auto h = reinterpret_cast<dserver_rpc_callhdr_t*>(m.bytes.data());
	h->number = dserver_callnum_dummy; h->pid = pid; h->tid = pid;
	m.kernelPid = pid + 400; m.addr = "sender";
	return m;
}

// the stand-in call table has no Checkin call, so building it throws after the process is registered
static void send(Message m) {
	try { Call::callFromMessage(std::move(m)); } catch (const std::exception&) {}
}

int main(int, char**) {
	procs.m.clear(); threads.m.clear();

	send(checkin(100, true));
	CHECK(procs.m.count(100) && procs.m[100]->_forkChild, "a fork child's check-in creates the process as a fork child");

	send(checkin(200, false));
	CHECK(procs.m.count(200) && !procs.m[200]->_forkChild, "a check-in after exec creates the process as no fork child");

	send(checkin(400, true, 100));
	CHECK(procs.m.count(400) && procs.m[400]->_forkParentNSID == 100, "a fork child's check-in hands the process the parent it names");

	send(dummy(300));
	CHECK(procs.m.count(300) && !procs.m[300]->_forkChild, "another first call creates the process as no fork child");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
