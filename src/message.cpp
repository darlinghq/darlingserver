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

#include <darlingserver/message.hpp>
#include <unistd.h>
#include <cstdlib>
#include <stdexcept>
#include <new>
#include <mutex>
#include <system_error>

/* msg_ucred_t: the credential type used in socket control messages.
 * On FreeBSD we use bsdos_ucred (our Linux-compat {pid,uid,gid} struct) since
 * FreeBSD's struct ucred is the kernel-internal type with different fields. */
#ifdef DARLING_FREEBSD
typedef struct bsdos_ucred msg_ucred_t;
#else
typedef struct ucred msg_ucred_t;
#endif

DarlingServer::Address::Address() {
	_address.sun_family = AF_UNIX;
	memset(_address.sun_path, 0, sizeof(_address.sun_path));
	_size = sizeof(_address);
};

DarlingServer::Address::Address(const struct sockaddr_un& rawAddress, size_t addressLength) {
	_address = rawAddress;
	_size = addressLength;
};

struct sockaddr_un& DarlingServer::Address::raw() {
	return _address;
};

const struct sockaddr_un& DarlingServer::Address::raw() const {
	return _address;
};

size_t DarlingServer::Address::rawSize() const {
	return _size;
};

void DarlingServer::Address::setRawSize(size_t newRawSize) {
	_size = newRawSize;
};

DarlingServer::Message::Message(size_t bufferSpace, size_t descriptorSpace, std::function<void()> sendNotificationCallback):
	_sendNotificationCallback(sendNotificationCallback)
{
	size_t controlLen = CMSG_SPACE(DARLING_CRED_CMSG_SIZE) + (descriptorSpace > 0 ? CMSG_SPACE(sizeof(int) * descriptorSpace) : 0);
	_controlHeader = static_cast<decltype(_controlHeader)>(malloc(controlLen));

	if (!_controlHeader) {
		throw std::bad_alloc();
	}

	_controlHeader->cmsg_len = CMSG_LEN(DARLING_CRED_CMSG_SIZE);
	_controlHeader->cmsg_level = SOL_SOCKET;
	_controlHeader->cmsg_type = SCM_CREDENTIALS;
#ifdef DARLING_FREEBSD
	/* struct cmsgcred, not struct sockcred2 — this is a self-fabricated,
	 * OUTGOING placeholder, and SCM_CREDS2 cannot be attached by userspace
	 * sendmsg() at all (kernel rejects it with EINVAL; see sys/socket.h's
	 * comment). copyCredentialsOut() decodes by the header's actual
	 * cmsg_type, so a receive that later replaces this with the kernel's
	 * real SCM_CREDS2 still works. */
	struct cmsgcred ourCreds = {0};
	ourCreds.cmcred_pid = getpid();
	ourCreds.cmcred_uid = getuid();
	ourCreds.cmcred_gid = getgid();
#else
	struct ucred ourCreds;
	ourCreds.pid = getpid();
	ourCreds.uid = getuid();
	ourCreds.gid = getgid();
#endif
	// the cmsg man page says memcpy should be used with CMSG_DATA instead of direct pointer access
	memcpy(CMSG_DATA(_controlHeader), &ourCreds, sizeof(ourCreds));

	if (descriptorSpace > 0) {
		auto fdHeader = reinterpret_cast<decltype(_controlHeader)>(reinterpret_cast<char*>(_controlHeader) + CMSG_SPACE(DARLING_CRED_CMSG_SIZE));
		fdHeader->cmsg_len = CMSG_LEN(sizeof(int) * descriptorSpace);
		fdHeader->cmsg_level = SOL_SOCKET;
		fdHeader->cmsg_type = SCM_RIGHTS;
		for (size_t i = 0; i < descriptorSpace; ++i) {
			const int fd = -1;
			memcpy(CMSG_DATA(fdHeader) + (sizeof(int) * i), &fd, sizeof(int));
		}
	}

	_buffer.resize(bufferSpace);

	_header.msg_name = &_socketAddress.raw();
	_header.msg_namelen = _socketAddress.rawSize();
	_header.msg_iov = &_dataDescriptor;
	_header.msg_iovlen = 1;
	_header.msg_control = _controlHeader;
	_header.msg_controllen = controlLen;
	_header.msg_flags = 0;

	_dataDescriptor.iov_base = _buffer.data();
	_dataDescriptor.iov_len = _buffer.size();
};

void DarlingServer::Message::_initWithOther(Message&& other) {
	_sendNotificationCallback = std::move(other._sendNotificationCallback);
	other._sendNotificationCallback = nullptr;

	_buffer = std::move(other._buffer);
	_socketAddress = std::move(other._socketAddress);
	_controlHeader = std::move(other._controlHeader);

	other._controlHeader = nullptr;

	_header = std::move(other._header);
	_header.msg_name = &_socketAddress.raw();
	_header.msg_iov = &_dataDescriptor;

	_dataDescriptor.iov_base = _buffer.data();
	_dataDescriptor.iov_len = _buffer.size();
};

void DarlingServer::Message::_cleanupSelf() {
	if (_controlHeader) {
		auto fdHeader = _descriptorHeader();
		if (fdHeader) {
			for (size_t i = 0; i < _descriptorSpace(); ++i) {
				int fd = -1;
				memcpy(&fd, CMSG_DATA(fdHeader) + (sizeof(int) * i), sizeof(int));
				if (fd != -1) {
					close(fd);
				}
			}
		}
		free(_controlHeader);
		_controlHeader = nullptr;
	}
};

struct cmsghdr* DarlingServer::Message::_credentialsHeader() {
	return const_cast<struct cmsghdr*>(const_cast<const Message*>(this)->_credentialsHeader());
};

const struct cmsghdr* DarlingServer::Message::_credentialsHeader() const {
	const struct cmsghdr* hdr = CMSG_FIRSTHDR(&_header);

	while (hdr) {
#ifdef DARLING_FREEBSD
		/* SCM_CREDENTIALS (== SCM_CREDS here) is what THIS process attaches
		 * to its own outgoing messages, since SCM_CREDS2 cannot be sent by
		 * userspace at all (see sys/socket.h's comment). But a message just
		 * received off the wire — the case Process::id() actually cares
		 * about — carries the kernel's real SCM_CREDS2/sockcred2 instead, so
		 * both types must be recognized here; copyCredentialsOut() branches
		 * on which one was actually found. */
		if (hdr->cmsg_level == SOL_SOCKET && (hdr->cmsg_type == SCM_CREDENTIALS || hdr->cmsg_type == SCM_CREDS2)) {
			return hdr;
		}
#else
		if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SCM_CREDENTIALS) {
			return hdr;
		}
#endif

		hdr = CMSG_NXTHDR(const_cast<struct msghdr*>(&_header), const_cast<struct cmsghdr*>(hdr));
	}

	return nullptr;
};

struct cmsghdr* DarlingServer::Message::_descriptorHeader() {
	return const_cast<struct cmsghdr*>(const_cast<const Message*>(this)->_descriptorHeader());
};

const struct cmsghdr* DarlingServer::Message::_descriptorHeader() const {
	const struct cmsghdr* hdr = CMSG_FIRSTHDR(&_header);

	while (hdr) {
		if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SCM_RIGHTS) {
			return hdr;
		}

		hdr = CMSG_NXTHDR(const_cast<struct msghdr*>(&_header), const_cast<struct cmsghdr*>(hdr));
	}

	return nullptr;
};

size_t DarlingServer::Message::_descriptorSpace() const {
	auto hdr = _descriptorHeader();

	if (!hdr) {
		return 0;
	}

	return (hdr->cmsg_len - (reinterpret_cast<uintptr_t>(CMSG_DATA(hdr)) - reinterpret_cast<uintptr_t>(hdr))) / sizeof(int);
};

DarlingServer::Message::~Message() {
	_cleanupSelf();
};

DarlingServer::Message::Message(Message&& other) {
	_initWithOther(std::move(other));
};

DarlingServer::Message& DarlingServer::Message::operator=(Message&& other) {
	_cleanupSelf();
	_initWithOther(std::move(other));
	return *this;
};

struct msghdr& DarlingServer::Message::rawHeader() {
	return _header;
};

const struct msghdr& DarlingServer::Message::rawHeader() const {
	return _header;
};

std::vector<uint8_t>& DarlingServer::Message::data() {
	return _buffer;
};

const std::vector<uint8_t>& DarlingServer::Message::data() const {
	return _buffer;
};

DarlingServer::Address DarlingServer::Message::address() const {
	return _socketAddress;
};

void DarlingServer::Message::setAddress(Address address) {
	_socketAddress = address;
	_header.msg_namelen = _socketAddress.rawSize();
};

std::vector<int> DarlingServer::Message::descriptors() const {
	std::vector<int> descriptors;
	auto fdHeader = _descriptorHeader();

	if (fdHeader) {
		for (size_t i = 0; i < _descriptorSpace(); ++i) {
			int fd = -1;
			memcpy(&fd, CMSG_DATA(fdHeader) + (sizeof(int) * i), sizeof(int));
			if (fd != -1) {
				descriptors.push_back(fd);
			}
		}
	}

	return descriptors;
};

void DarlingServer::Message::pushDescriptor(int descriptor) {
	if (auto fdHeader = _descriptorHeader()) {
		for (size_t i = 0; i < _descriptorSpace(); ++i) {
			int fd = -1;
			memcpy(&fd, CMSG_DATA(fdHeader) + (sizeof(int) * i), sizeof(int));
			if (fd != -1) {
				continue;
			}

			memcpy(CMSG_DATA(fdHeader) + (sizeof(int) * i), &descriptor, sizeof(int));
			return;
		}
	}

	auto oldSpace = _descriptorSpace();
	_ensureDescriptorHeader(oldSpace + 1);
	memcpy(CMSG_DATA(_descriptorHeader()) + (sizeof(int) * oldSpace), &descriptor, sizeof(int));
};

int DarlingServer::Message::extractDescriptor(int descriptor) {
	if (auto fdHeader = _descriptorHeader()) {
		for (size_t i = 0; i < _descriptorSpace(); ++i) {
			int fd = -1;
			memcpy(&fd, CMSG_DATA(fdHeader) + (sizeof(int) * i), sizeof(int));
			if (fd != descriptor) {
				continue;
			}

			fd = -1;
			memcpy(CMSG_DATA(fdHeader) + (sizeof(int) * i), &fd, sizeof(int));
			return descriptor;
		}
	}

	return -1;
};

int DarlingServer::Message::extractDescriptorAtIndex(size_t index) {
	if (auto fdHeader = _descriptorHeader()) {
		for (size_t i = 0, presentIndex = 0; i < _descriptorSpace(); ++i) {
			int fd = -1;
			memcpy(&fd, CMSG_DATA(fdHeader) + (sizeof(int) * i), sizeof(int));
			if (fd == -1) {
				continue;
			}

			if (presentIndex++ != index) {
				continue;
			}

			int tmp = -1;
			memcpy(CMSG_DATA(fdHeader) + (sizeof(int) * i), &tmp, sizeof(int));
			return fd;
		}
	}

	return -1;
};

void DarlingServer::Message::replaceDescriptors(const std::vector<int>& newDescriptors) {
	_ensureDescriptorHeader(newDescriptors.size());
	memcpy(CMSG_DATA(_descriptorHeader()), newDescriptors.data(), sizeof(int) * newDescriptors.size());
};

#ifdef DARLING_FREEBSD
bool DarlingServer::Message::copyCredentialsOut(struct bsdos_ucred& outputCredentials) const {
#else
bool DarlingServer::Message::copyCredentialsOut(struct ucred& outputCredentials) const {
#endif
	auto credHeader = _credentialsHeader();

	if (credHeader) {
#ifdef DARLING_FREEBSD
		/*
		 * Two possible shapes land here, distinguished by the actual
		 * cmsg_type found (see sys/socket.h's comment and _credentialsHeader()
		 * for why both exist):
		 *   - SCM_CREDS2: the kernel's own credentials on a just-received
		 *     message (LOCAL_CREDS_PERSISTENT) — struct sockcred2.
		 *   - SCM_CREDS (== SCM_CREDENTIALS here): this process's own
		 *     self-fabricated placeholder, written by copyCredentialsIn()/the
		 *     constructor below — struct cmsgcred. (SCM_CREDS2 can't be used
		 *     for that: the kernel rejects a userspace-attached SCM_CREDS2
		 *     cmsg on sendmsg() with EINVAL outright.)
		 */
		if (credHeader->cmsg_type == SCM_CREDS2) {
			struct sockcred2 fbsdCreds;
			memcpy(&fbsdCreds, CMSG_DATA(credHeader), sizeof(fbsdCreds));
			outputCredentials.pid = fbsdCreds.sc_pid;
			outputCredentials.uid = fbsdCreds.sc_uid;
			outputCredentials.gid = fbsdCreds.sc_gid;
		} else {
			struct cmsgcred fbsdCreds;
			memcpy(&fbsdCreds, CMSG_DATA(credHeader), sizeof(fbsdCreds));
			outputCredentials.pid = fbsdCreds.cmcred_pid;
			outputCredentials.uid = fbsdCreds.cmcred_uid;
			outputCredentials.gid = fbsdCreds.cmcred_gid;
		}
#else
		memcpy(&outputCredentials, CMSG_DATA(credHeader), sizeof(outputCredentials));
#endif
		return true;
	} else {
		return false;
	}
};

#ifdef DARLING_FREEBSD
void DarlingServer::Message::copyCredentialsIn(const struct bsdos_ucred& inputCredentials) {
#else
void DarlingServer::Message::copyCredentialsIn(const struct ucred& inputCredentials) {
#endif
	_ensureCredentialsHeader();
#ifdef DARLING_FREEBSD
	/* Always writes SCM_CREDS/cmsgcred shape — this is a self-fabricated,
	 * outgoing placeholder, and SCM_CREDS2 cannot be sent by userspace at
	 * all (see sys/socket.h's comment). Preserve whatever's already in the
	 * other cmsgcred fields (euid, ngroups, groups) rather than zeroing
	 * them. */
	struct cmsgcred creds;
	memcpy(&creds, CMSG_DATA(_credentialsHeader()), sizeof(creds));
	creds.cmcred_pid = inputCredentials.pid;
	creds.cmcred_uid = inputCredentials.uid;
	creds.cmcred_gid = inputCredentials.gid;
	_credentialsHeader()->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(_credentialsHeader()), &creds, sizeof(creds));
#else
	memcpy(CMSG_DATA(_credentialsHeader()), &inputCredentials, sizeof(inputCredentials));
#endif
};

void DarlingServer::Message::_ensureCredentialsHeader() {
	if (_credentialsHeader()) {
		return;
	}

	auto fdHeader = _descriptorHeader();
	auto descSpace = _descriptorSpace();
	size_t controlLen = CMSG_SPACE(DARLING_CRED_CMSG_SIZE) + (descSpace > 0 ? CMSG_SPACE(sizeof(int) * descSpace) : 0);
	auto tmp = static_cast<decltype(_controlHeader)>(malloc(controlLen));
	auto old = _controlHeader;
	struct cmsghdr* credHeader = nullptr;

	if (!tmp) {
		throw std::bad_alloc();
	}

	_controlHeader = tmp;
	_header.msg_control = _controlHeader;

	credHeader = _controlHeader;

	if (descSpace > 0) {
		auto newFdHeader = reinterpret_cast<decltype(_controlHeader)>(reinterpret_cast<char*>(_controlHeader) + CMSG_SPACE(DARLING_CRED_CMSG_SIZE));
		memcpy(newFdHeader, fdHeader, CMSG_SPACE(sizeof(int) * descSpace));
	}

	free(old);

	_header.msg_controllen = controlLen;

	credHeader->cmsg_len = CMSG_LEN(DARLING_CRED_CMSG_SIZE);
	credHeader->cmsg_level = SOL_SOCKET;
	credHeader->cmsg_type = SCM_CREDENTIALS;

#ifdef DARLING_FREEBSD
	/* struct cmsgcred, not sockcred2 — same reasoning as the constructor
	 * above: this is an outgoing placeholder, and SCM_CREDS2 can't be sent. */
	struct cmsgcred creds = {0};
	creds.cmcred_pid = getpid();
	creds.cmcred_uid = getuid();
	creds.cmcred_gid = getgid();
#else
	msg_ucred_t creds;
	creds.pid = getpid();
	creds.uid = getuid();
	creds.gid = getgid();
#endif
	memcpy(CMSG_DATA(credHeader), &creds, sizeof(creds));
};

void DarlingServer::Message::_ensureDescriptorHeader(size_t newSpace) {
	if (_descriptorSpace() == newSpace) {
		return;
	}

	auto credHeader = _credentialsHeader();
	size_t oldSpace = _descriptorSpace();
	size_t controlLen = (credHeader ? CMSG_SPACE(DARLING_CRED_CMSG_SIZE) : 0) + (newSpace == 0 ? 0 : CMSG_SPACE(sizeof(int) * newSpace));

	if (controlLen == 0) {
		free(_controlHeader);
		_controlHeader = nullptr;
		_header.msg_control = nullptr;
		_header.msg_controllen = 0;
		return;
	}

	auto tmp = static_cast<decltype(_controlHeader)>(malloc(controlLen));
	auto old = _controlHeader;
	struct cmsghdr* fdHeader = nullptr;

	if (!tmp) {
		throw std::bad_alloc();
	}

	_controlHeader = tmp;
	_header.msg_control = _controlHeader;

	if (credHeader) {
		memcpy(_controlHeader, credHeader, CMSG_SPACE(DARLING_CRED_CMSG_SIZE));
		fdHeader = reinterpret_cast<decltype(_controlHeader)>(reinterpret_cast<char*>(_controlHeader) + CMSG_SPACE(DARLING_CRED_CMSG_SIZE));
	} else {
		fdHeader = _controlHeader;
	}

	free(old);

	_header.msg_controllen = controlLen;

	if (newSpace > 0) {
		fdHeader->cmsg_len = CMSG_LEN(sizeof(int) * newSpace);
		fdHeader->cmsg_level = SOL_SOCKET;
		fdHeader->cmsg_type = SCM_RIGHTS;

		for (size_t i = oldSpace; i < newSpace; ++i) {
			int fd = -1;
			memcpy(CMSG_DATA(fdHeader) + (sizeof(int) * i), &fd, sizeof(int));
		}
	}
};

pid_t DarlingServer::Message::pid() const {
	msg_ucred_t creds;

	if (copyCredentialsOut(creds)) {
		return creds.pid;
	} else {
		return -1;
	}
};

void DarlingServer::Message::setPID(pid_t pid) {
	_ensureCredentialsHeader();
	msg_ucred_t creds;
	copyCredentialsOut(creds);
	creds.pid = pid;
	copyCredentialsIn(creds);
};

uid_t DarlingServer::Message::uid() const {
	msg_ucred_t creds;

	if (copyCredentialsOut(creds)) {
		return creds.uid;
	} else {
		return -1;
	}
};

void DarlingServer::Message::setUID(uid_t uid) {
	_ensureCredentialsHeader();
	msg_ucred_t creds;
	copyCredentialsOut(creds);
	creds.uid = uid;
	copyCredentialsIn(creds);
};

gid_t DarlingServer::Message::gid() const {
	msg_ucred_t creds;

	if (copyCredentialsOut(creds)) {
		return creds.gid;
	} else {
		return -1;
	}
};

void DarlingServer::Message::setGID(gid_t gid) {
	_ensureCredentialsHeader();
	msg_ucred_t creds;
	copyCredentialsOut(creds);
	creds.gid = gid;
	copyCredentialsIn(creds);
};

std::function<void()> DarlingServer::Message::sendNotificationCallback() const {
	return _sendNotificationCallback;
};

void DarlingServer::Message::setSendNotificationCallback(std::function<void()> sendNotificationCallback) {
	_sendNotificationCallback = sendNotificationCallback;
};

//
// message queue
//

void DarlingServer::MessageQueue::push(Message&& message) {
	std::unique_lock lock(_lock);
	_messages.push_back(std::move(message));

	if (_messages.size() > 0) {
		auto callback = _messageArrivalNotificationCallback;
		lock.unlock();
		if (callback) {
			callback();
		}
	}
};

std::optional<DarlingServer::Message> DarlingServer::MessageQueue::pop() {
	std::scoped_lock lock(_lock);
	if (_messages.size() > 0) {
		Message message = std::move(_messages.front());
		_messages.pop_front();
		return message;
	} else {
		return std::nullopt;
	}
};

bool DarlingServer::MessageQueue::sendMany(int socket) {
	bool canSendMore = true;
	std::scoped_lock lock(_lock);
	struct mmsghdr mmsgs[16];
	size_t len = 0;
	int ret = 0;

	while (ret >= 0) {
		len = 0;
		for (size_t i = 0; i < _messages.size() && i < sizeof(mmsgs) / sizeof(*mmsgs); ++i) {
			mmsgs[i].msg_hdr = _messages[i].rawHeader();
			mmsgs[i].msg_len = 0;

			// some systems report EINVAL when sending to an address filled with null bytes.
			auto address = reinterpret_cast<sockaddr_un*>(mmsgs[i].msg_hdr.msg_name);
			bool isAddressEmpty = true;
			for (size_t j = 0; j < sizeof(address->sun_path); ++j) {
				if (address->sun_path[j] != '\0') {
					isAddressEmpty = false;
					break;
				}
			}
			if (isAddressEmpty) {
				mmsgs[i].msg_hdr.msg_name = nullptr;
				mmsgs[i].msg_hdr.msg_namelen = 0;
			}

			++len;
		}

		if (len == 0) {
			break;
		}

		ret = sendmmsg(socket, mmsgs, len, MSG_DONTWAIT);

		if (ret < 0) {
			if (errno == EAGAIN) {
				canSendMore = false;
				break;
			} else if (errno == EINTR) {
				ret = 0;
			} else if (errno == EPIPE || errno == ECONNREFUSED) {
				// this means that peer of the first message we tried to send has died.
				// we'll just drop that message and try the others.
				_messages.pop_front();
				ret = 0;
			} else {
				throw std::system_error(errno, std::generic_category(), "Failed to send messages through socket");
			}
		}

		for (size_t i = 0; i < ret; ++i) {
			auto cb = _messages.front().sendNotificationCallback();
			_messages.pop_front();
			if (cb) {
				cb();
			}
		}
	}

	return canSendMore;
};

bool DarlingServer::MessageQueue::receiveMany(int socket) {
	bool canReadMore = true;
	std::unique_lock lock(_lock);
	struct mmsghdr mmsgs[16];
	int ret = 0;

	while (ret >= 0) {
		std::array<Message, sizeof(mmsgs) / sizeof(*mmsgs)> messages;

		for (size_t i = 0; i < messages.size(); ++i) {
			mmsgs[i].msg_hdr = messages[i].rawHeader();
			mmsgs[i].msg_len = 0;
		}

		ret = recvmmsg(socket, mmsgs, sizeof(mmsgs) / sizeof(*mmsgs), MSG_CMSG_CLOEXEC | MSG_DONTWAIT, nullptr);

		if (ret < 0) {
			if (errno == EAGAIN) {
				canReadMore = false;
				break;
			} else if (errno == EINTR) {
				ret = 0;
			} else {
				throw std::system_error(errno, std::generic_category(), "Failed to receive messages through socket");
			}
		}

		for (size_t i = 0; i < ret; ++i) {
			messages[i].rawHeader() = mmsgs[i].msg_hdr;
			messages[i].data().resize(mmsgs[i].msg_len);
			messages[i].setAddress(Address(*(const struct sockaddr_un*)mmsgs[i].msg_hdr.msg_name, mmsgs[i].msg_hdr.msg_namelen));
			_messages.push_back(std::move(messages[i]));
		}
	}

	if (_messages.size() > 0) {
		auto callback = _messageArrivalNotificationCallback;
		lock.unlock();
		if (callback) {
			callback();
		}
	}

	return canReadMore;
};

void DarlingServer::MessageQueue::setMessageArrivalNotificationCallback(std::function<void()> messageArrivalNotificationCallback) {
	std::unique_lock lock(_lock);
	_messageArrivalNotificationCallback = messageArrivalNotificationCallback;
};

bool DarlingServer::MessageQueue::empty() const {
	std::unique_lock lock(_lock);
	return _messages.empty();
};
