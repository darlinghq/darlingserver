// A sigprocess call from a libsystem_kernel that predates the exception state is shorter than the call
// struct. It must be taken as a call without exception state, not dropped (which leaves the thread waiting for
// the reply forever). Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are
// stand-ins.
#include <cstddef>
#include <cstring>
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static const size_t legacySize = offsetof(dserver_rpc_call_sigprocess_t, body.exception_fault_address);
// the size of the call before the exception state was added (16-byte header, 4 int32_t and 3 uint64_t)
static_assert(offsetof(dserver_rpc_call_sigprocess_t, body.exception_fault_address) == 56, "the legacy prefix must not change");

static Message sigprocess(pid_t pid, size_t size) {
	dserver_rpc_call_sigprocess_t call;
	std::memset(&call, 0, sizeof(call));
	call.header.number = dserver_callnum_sigprocess;
	call.header.pid = pid;
	call.header.tid = pid;
	call.body.linux_signal_number = 11;
	call.body.float_state = 0x1234;
	call.body.exception_fault_address = 0x5000;
	call.body.exception_trapno = 14;
	call.body.exception_err = 4;
	call.body.has_exception_state = true;

	Message m;
	m.bytes.resize(size);
	std::memcpy(m.bytes.data(), &call, std::min(size, sizeof(call)));
	m.kernelPid = pid + 400; m.addr = "sender";
	return m;
}

static std::shared_ptr<SigprocessCall> send(Message m) {
	try {
		Call::callFromMessage(std::move(m));
	} catch (const std::exception&) {
		return nullptr;
	}
	auto thread = threads.m.begin()->second;
	auto call = std::dynamic_pointer_cast<SigprocessCall>(thread->_pendingCall);
	thread->_pendingCall = nullptr;
	return call;
}

int main(int, char**) {
	procs.m.clear(); threads.m.clear();

	auto full = send(sigprocess(100, sizeof(dserver_rpc_call_sigprocess_t)));
	CHECK(full && full->call.body.has_exception_state && full->call.body.exception_trapno == 14 && full->call.body.exception_err == 4
		&& full->call.body.exception_fault_address == 0x5000, "a full call keeps its exception state");

	auto legacy = send(sigprocess(100, legacySize));
	CHECK(legacy && !legacy->call.body.has_exception_state && legacy->call.body.exception_trapno == 0
		&& legacy->call.body.exception_fault_address == 0, "a call without the exception state fields is one without exception state");
	CHECK(legacy && legacy->call.body.linux_signal_number == 11 && legacy->call.body.float_state == 0x1234,
		"... and keeps its other fields");

	CHECK(!send(sigprocess(100, legacySize - 8)), "a shorter call is still rejected");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
