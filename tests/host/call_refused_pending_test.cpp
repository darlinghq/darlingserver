// Copyright (C) 2026 Lubos Dolezel
//
// A managed call that the thread cannot take, because another call is already pending on it, is refused
// with -EAGAIN so that the guest can retry. The refusal must not unwind out of callFromMessage() into the
// server's top-level guard, which ends the server and every process of the container with it.
// Body of Call::callFromMessage is the real one (extracted from src/call.cpp); the types are stand-ins.
#include "call_stubs.hpp"
#include CALL_FROM_MESSAGE_INC

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static Message msg(uint32_t number, pid_t kernelPid, pid_t nspid, pid_t tid) {
	Message m;
	m.bytes.resize(64);
	auto h = reinterpret_cast<dserver_rpc_callhdr_t*>(m.bytes.data());
	h->number = number; h->pid = nspid; h->tid = tid;
	m.kernelPid = kernelPid; m.addr = "sender";
	return m;
}

int main(int, char**) {
	auto a = std::make_shared<Process>(500, 100, Process::Architecture::x86_64, -1);
	procs.m[100] = a;
	auto ta = std::make_shared<Thread>(a, 101, nullptr);
	threads.m[101] = ta;

	std::shared_ptr<Call> result;
	bool threw = false;

	try { result = Call::callFromMessage(msg(dserver_callnum_dummy, 500, 100, 101)); } catch (const std::exception&) { threw = true; }
	CHECK(!threw && result != nullptr && ta->_pendingCall == result, "a call the thread can take is queued on it");
	CHECK(!Call::armingRefused, "and is not marked as refused");

	ta->rejectPendingCall = true;
	ta->_pendingCall = nullptr;
	result = nullptr;
	try { result = Call::callFromMessage(msg(dserver_callnum_dummy, 500, 100, 101)); } catch (const std::exception&) { threw = true; }
	CHECK(!(threw), "a call the thread refuses does not throw out of callFromMessage");
	CHECK(result == nullptr, "and produces no call to run");
	CHECK(Call::armingRefused, "the call is marked as one that never entered a thread slot");
	CHECK(Call::basicReply == -EAGAIN, "and is answered with -EAGAIN");
	CHECK(ta->_pendingCall == nullptr, "the thread's own slots are untouched");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
