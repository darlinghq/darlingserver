// A fork child's task keeps its parent's architecture, whatever architecture the child reports, and starts with its
// parent's dyld image information.
// The Process constructor is the real one, cut out of src/process.cpp by tests/host/process-ctor-inc.sh
// into the file named by PROCESS_CTOR_INC; Process's other members, the registry and duct-tape are stand-ins.
// The parent is found the way the server finds it: through the PPid line of /proc/<pid>/status.
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <shared_mutex>
#include <string>
#include <system_error>
#include <vector>
#include <sys/syscall.h>
#include <unistd.h>

typedef int dserver_rpc_architecture_t;
typedef struct { uint32_t darling_flags; } dserver_cs_state_t;
struct dtape_task_t { dserver_rpc_architecture_t architecture; uint64_t dyld_info_addr = 0; uint64_t dyld_info_length = 0; };
struct dtape_semaphore_t {};

static std::vector<std::unique_ptr<dtape_task_t>> tasks;
static dtape_task_t* dtape_task_create(dtape_task_t*, int, void*, dserver_rpc_architecture_t architecture) {
	tasks.push_back(std::make_unique<dtape_task_t>(dtape_task_t{architecture}));
	return tasks.back().get();
}
static void dtape_task_inherit_dyld_info(dtape_task_t* task, dtape_task_t* parent_task) {
	task->dyld_info_addr = parent_task->dyld_info_addr;
	task->dyld_info_length = parent_task->dyld_info_length;
}
static dtape_semaphore_t* dtape_semaphore_create(dtape_task_t*, int) { return nullptr; }

struct NullBuf : std::streambuf { int overflow(int c) override { return c; } };
static NullBuf nullBuf;
static std::ostream nullStream(&nullBuf);
static struct { std::ostream& info() const { return nullStream; } } processLog;

namespace DarlingServer {
	class FD {
		int _fd;
	public:
		FD(int fd): _fd(fd) {}
		~FD() { if (_fd >= 0) close(_fd); }
	};

	namespace CodeSigning {
		struct Image {};
		static uint32_t darlingFlagsInheritedByFork(uint32_t flags) { return flags; }
	}

	struct Process {
		enum class Architecture { Invalid = 0, i386, x86_64, ARM32, ARM64 };
		using ID = pid_t;
		using NSID = ID;

		ID _pid;
		NSID _nspid;
		Architecture _architecture;
		std::shared_ptr<FD> _pidfd;
		mutable std::shared_mutex _rwlock;
		std::string _cachedVchrootPath;
		std::shared_ptr<FD> _vchrootDescriptor;
		dtape_task_t* _dtapeTask = nullptr;
		std::weak_ptr<Process> _parentProcess;
		dtape_semaphore_t* _dtapeForkWaitSemaphore = nullptr;
		std::vector<uint32_t> _groups;
		dserver_cs_state_t _csState {};
		std::shared_ptr<const CodeSigning::Image> _csImage;
		bool _csMayRegister = false;
		void _resetCodeSigningState() {}

		Process(ID id, NSID nsid, Architecture architecture, int pipe = -1, bool forkChild = false);
	};

	static struct {
		std::map<pid_t, std::shared_ptr<Process>> m;
		std::optional<std::shared_ptr<Process>> lookupEntryByID(pid_t id) {
			if (m.count(id)) return m[id];
			return std::nullopt;
		}
	} registry;
	static decltype(registry)& processRegistry() { return registry; }
}

#include PROCESS_CTOR_INC

using namespace DarlingServer;
using Arch = Process::Architecture;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static bool hasArchitecture(const Process& p, Arch a) {
	return p._architecture == a && p._dtapeTask && p._dtapeTask->architecture == static_cast<dserver_rpc_architecture_t>(a);
}

int main(int, char**) {
	// this process stands in for the child, its parent for the parent the server already knows
	{
		Process orphan(getpid(), 2, Arch::x86_64, -1, true);
		CHECK(hasArchitecture(orphan, Arch::x86_64), "a fork child without a known parent keeps the reported architecture");
	}

	registry.m[getppid()] = std::make_shared<Process>(getppid(), 1, Arch::ARM64, -1, false);
	registry.m[getppid()]->_dtapeTask->dyld_info_addr = 0x7ff800001000;
	registry.m[getppid()]->_dtapeTask->dyld_info_length = 0x170;

	Process child(getpid(), 2, Arch::x86_64, -1, true);
	CHECK(child._parentProcess.lock() == registry.m[getppid()], "the parent is found through PPid");
	CHECK(hasArchitecture(child, Arch::ARM64), "a fork child's task takes its parent's architecture, not the reported one");
	CHECK(child._dtapeTask->dyld_info_addr == 0x7ff800001000 && child._dtapeTask->dyld_info_length == 0x170,
		"a fork child's task starts with its parent's dyld image information");

	Process execd(getpid(), 2, Arch::x86_64, -1, false);
	CHECK(hasArchitecture(execd, Arch::x86_64), "a process that is no fork child keeps the reported architecture");
	CHECK(execd._dtapeTask->dyld_info_addr == 0 && execd._dtapeTask->dyld_info_length == 0,
		"a process that is no fork child waits for its own dyld image information");

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
