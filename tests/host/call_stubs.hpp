// Stand-in types for Call::callFromMessage (included by call_*_test.cpp before the extracted function).
// Only the function body under test is real; Message, Process, Thread and the registries are stubs that
// record what the function does to them.
#pragma once
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <shared_mutex>
#include <stack>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

#define DSERVER_CALL_UNMANAGED_FLAG 0x80000000U
enum : uint32_t { dserver_callnum_checkin = 1, dserver_callnum_dummy = 2, dserver_callnum_s2c = 0xdead, dserver_callnum_push_reply = 0xbadca11, dserver_callnum_dbg = 0x80000003U };
#define DSERVER_VALID_CALLNUM_CASES case dserver_callnum_checkin: case dserver_callnum_dummy: case dserver_callnum_dbg:
#define DSERVER_CONSTRUCT_CASES CALL_CASE(dummy, DummyCall) CALL_CASE(dbg, DbgCall)

typedef struct { uint32_t number; pid_t pid; pid_t tid; uint32_t architecture; } dserver_rpc_callhdr_t;
typedef struct { dserver_rpc_callhdr_t header; struct { int lifetime_listener_pipe; uint64_t stack_hint; } body; } dserver_rpc_call_checkin_t;
typedef struct { dserver_rpc_callhdr_t header; } dserver_rpc_call_dummy_t;
typedef struct { dserver_rpc_callhdr_t header; } dserver_rpc_call_dbg_t;
typedef struct { dserver_rpc_callhdr_t header; uint64_t reply; uint64_t reply_size; } dserver_rpc_call_push_reply_t;

static const char* dserver_callnum_to_string(uint32_t) { return "call"; }
static void dtape_semaphore_up(void*) {}

struct NullBuf : std::streambuf { int overflow(int c) override { return c; } };
static NullBuf nullBuf;
static std::ostream nullStream(&nullBuf);
struct LogStub {
	std::ostream& debug() const { return nullStream; }
	std::ostream& error() const { return nullStream; }
	static constexpr const char* endLog = "";
};
static LogStub callLog;

namespace DarlingServer {
	using Address = std::string;

	class FD {
		int _fd;
	public:
		FD(int fd): _fd(fd) {}
		~FD() { if (_fd != -1) close(_fd); }
		FD(const FD&) = delete;
		int fd() const { return _fd; }
		explicit operator bool() { return _fd != -1; }
	};

	struct Message {
		std::vector<char> bytes;
		std::vector<int> fds;
		pid_t kernelPid = -1;
		uid_t kernelUid = getuid();
		Address addr;
		Message() = default;
		Message(size_t size, size_t): bytes(size) {}
		Message(Message&& o): bytes(std::move(o.bytes)), fds(std::move(o.fds)), kernelPid(o.kernelPid), addr(o.addr), kernelUid(o.kernelUid) { o.fds.clear(); }
		Message& operator=(Message&& o) { cleanup(); bytes = std::move(o.bytes); fds = std::move(o.fds); o.fds.clear(); kernelPid = o.kernelPid; kernelUid = o.kernelUid; addr = o.addr; return *this; }
		~Message() { cleanup(); }
		void cleanup() { for (int fd : fds) if (fd != -1) close(fd); fds.clear(); }
		std::vector<char>& data() { return bytes; }
		pid_t pid() const { return kernelPid; }
		uid_t uid() const { return kernelUid; }
		Address address() const { return addr; }
		void setAddress(Address a) { addr = a; }
		std::vector<int> descriptors() const { std::vector<int> r; for (int fd : fds) if (fd != -1) r.push_back(fd); return r; }
		int extractDescriptorAtIndex(size_t index) {
			for (size_t i = 0, present = 0; i < fds.size(); ++i) {
				if (fds[i] == -1) continue;
				if (present++ != index) continue;
				int fd = fds[i]; fds[i] = -1; return fd;
			}
			return -1;
		}
		void replaceDescriptors(const std::vector<int>& n) { fds = n; }
	};

	struct Process {
		enum class Architecture { x86_64 };
		pid_t _id, _nsid;
		Process(pid_t id, pid_t nsid, Architecture, int): _id(id), _nsid(nsid) {}
		pid_t id() const { return _id; }
		pid_t nsid() const { return _nsid; }
		bool readMemory(uint64_t, void*, uint64_t) { return true; }
	};

	struct Call;
	struct Thread {
		struct Interrupt { std::optional<Message> savedReply; };
		std::shared_ptr<Process> _process; pid_t _nsid; Address address;
		std::shared_mutex _rwlock;
		std::optional<Message> _s2cReply, _pendingSavedReply;
		void* _s2cReplySempahore = nullptr;
		std::shared_ptr<Call> _pendingCall;
		std::stack<Interrupt> _interrupts;
		Thread(std::shared_ptr<Process> p, pid_t nsid, void*): _process(p), _nsid(nsid) {}
		std::shared_ptr<Process> process() const { return _process; }
		pid_t id() const { return _nsid; }
		pid_t nsid() const { return _nsid; }
		void setAddress(Address a) { address = a; }
		void registerWithProcess() {}
		void setPendingCall(std::shared_ptr<Call> c) { _pendingCall = c; }
		static void kernelAsync(std::function<void()>) {}
	};
	inline std::ostream& operator<<(std::ostream& o, const Thread&) { return o; }

	template<class T> struct Registry {
		std::map<pid_t, std::shared_ptr<T>> m;
		std::shared_ptr<T> registerIfAbsent(pid_t id, std::function<std::shared_ptr<T>()> make) {
			if (m.count(id)) return m[id];
			auto t = make();
			if (t) m[id] = t;
			return t;
		}
	};
	static Registry<Process> procs;
	static Registry<Thread> threads;
	static Registry<Process>& processRegistry() { return procs; }
	static Registry<Thread>& threadRegistry() { return threads; }

	struct Server {
		static Server& sharedInstance() { static Server s; return s; }
		void monitorProcess(std::shared_ptr<Process>) {}
	};

	struct Call {
		enum class Number { InterruptEnter, Other };
		virtual ~Call() = default;
		Number number() const { return Number::Other; }
		void processCall() {}
		static std::shared_ptr<Call> callFromMessage(Message&& requestMessage);
	};
	struct DbgCall : Call {
		DbgCall(std::shared_ptr<Thread>, dserver_rpc_call_dbg_t*, Message&&) {}
	};
	struct DummyCall : Call {
		DummyCall(std::shared_ptr<Thread>, dserver_rpc_call_dummy_t*, Message&&) {}
	};
}

