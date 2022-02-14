/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DARLINGSERVER_CALL_HPP_
#define _DARLINGSERVER_CALL_HPP_

#include <darlingserver/rpc.h>
#include <darlingserver/rpc.internal.h>

#include <darlingserver/message.hpp>
#include <darlingserver/registry.hpp>
#include <darlingserver/logging.hpp>

#include <memory>

#include <unistd.h>

namespace DarlingServer {
	class CallWithReply;

	class Call: public std::enable_shared_from_this<Call> {
	public:
		enum class Number {
			Invalid = dserver_callnum_invalid,
			DSERVER_ENUM_VALUES
		};

	protected:
		std::weak_ptr<Thread> _thread;
		MessageQueue& _replyQueue;
		Address _replyAddress;
		dserver_rpc_callhdr_t _header;

		static DarlingServer::Log rpcReplyLog;

	public:
		Call(MessageQueue& replyQueue, std::shared_ptr<Thread> thread, Address replyAddress, dserver_rpc_callhdr_t* callHeader);
		virtual ~Call();

		static std::shared_ptr<Call> callFromMessage(Message&& requestMessage, MessageQueue& replyQueue);

		virtual Number number() const = 0;
		std::shared_ptr<Thread> thread() const;

		virtual void processCall() = 0;

		virtual void sendBasicReply(int resultCode);

		DSERVER_CLASS_DECLS;
	};

	DSERVER_CLASS_DEFS;
};

#endif // _DARLINGSERVER_CALL_HPP_
