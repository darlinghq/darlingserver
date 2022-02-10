#ifndef _DARLINGSERVER_KQCHAN_HPP_
#define _DARLINGSERVER_KQCHAN_HPP_

#include <memory>
#include <optional>

#include <darlingserver/monitor.hpp>
#include <darlingserver/message.hpp>
#include <darlingserver/duct-tape.h>

namespace DarlingServer {
	class Process;
	class Thread;

	class Kqchan {
		friend class Process;

	protected:
		uint64_t _debugID;

		Kqchan();

		virtual uintptr_t _idForProcess() const = 0;

	public:
		virtual ~Kqchan() = 0;

		class MachPort;
	};


	class Kqchan::MachPort: public Kqchan, public std::enable_shared_from_this<MachPort> {
	private:
		std::weak_ptr<Process> _process;
		std::shared_ptr<FD> _socket;
		uint32_t _port;
		std::shared_ptr<Monitor> _monitor;
		uint64_t _receiveBuffer;
		uint64_t _receiveBufferSize;
		uint64_t _savedFilterFlags;
		MessageQueue _inbox;
		MessageQueue _outbox;
		bool _canSend = false;
		dtape_kqchan_mach_port_t* _dtapeKqchan = nullptr;
		std::mutex _notificationMutex;
		bool _canSendNotification = true;
		std::mutex _sendingMutex;

		void _modify(uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags, pid_t nstid);
		void _read(uint64_t defaultBuffer, uint64_t defaultBufferSize, pid_t nstid);

		void _notify();

	protected:
		virtual uintptr_t _idForProcess() const;

	public:
		MachPort(std::shared_ptr<Process> process, uint32_t port, uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags);
		~MachPort();

		MachPort(const MachPort&) = delete;
		MachPort& operator=(const MachPort&) = delete;

		MachPort(MachPort&&) = delete;
		MachPort& operator=(MachPort&&) = delete;

		int setup();
	};
};

#endif // _DARLINGSERVER_KQCHAN_HPP_
