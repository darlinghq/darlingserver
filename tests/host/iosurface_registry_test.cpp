// Copyright (C) 2026 Lubos Dolezel
//
// The IOSurface service's registry (src/iosurface.cpp, compiled unchanged): IDs, holds per process,
// global lookup, the GPU buffer, the memory-user counter it writes into the memory object, and
// that every descriptor it took is closed again once no process holds the surface.
#include <darlingserver/iosurface.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static const uint32_t counterOffset = 456;

static int openDescriptors() {
	int count = 0;
	DIR* dir = opendir("/proc/self/fd");
	if (!dir) {
		return -1;
	}
	while (struct dirent* entry = readdir(dir)) {
		if (entry->d_name[0] != '.') {
			++count;
		}
	}
	closedir(dir);
	return count;
}

// a surface's memory object: one page of header plus one of contents
static int newMemory() {
	int fd = memfd_create("iosurface-registry-test", MFD_CLOEXEC);
	if (fd >= 0 && ftruncate(fd, 8192) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static uint32_t counter(int memory) {
	uint32_t value = 0xdeadbeef;
	if (pread(memory, &value, sizeof(value), counterOffset) != sizeof(value)) {
		return 0xdeadbeef;
	}
	return value;
}

static dserver_iosurface_gpu_buffer_t bufferInfo(uint64_t modifier) {
	dserver_iosurface_gpu_buffer_t info;
	std::memset(&info, 0, sizeof(info));
	info.modifier = modifier;
	info.fourcc = 0x34325241; // AR24
	info.width = 64;
	info.height = 32;
	info.stride = 256;
	std::strcpy(info.render_node, "/dev/dri/renderD128");
	return info;
}

int main() {
	const IOSurfaceRegistry::ProcessID producer = 100, consumer = 200, stranger = 300;
	int baseline = openDescriptors();

	{
		IOSurfaceRegistry registry;
		int memory = newMemory();
		int other = newMemory();
		CHECK(memory >= 0 && other >= 0, "memory objects made");

		// IDs
		uint32_t id = 0, otherID = 0, again = 0;
		CHECK(registry.retain(producer, memory, 0, 0, counterOffset, &id) == 0 && id != 0, "a new surface gets an ID");
		CHECK(registry.retain(producer, other, 0, DSERVER_IOSURFACE_GLOBAL, counterOffset, &otherID) == 0 && otherID != 0 && otherID != id, "another surface gets another ID");
		CHECK(registry.retain(consumer, memory, 0, 0, counterOffset, &again) == 0 && again == id, "the same memory object is the same surface");
		int dupped = dup(memory);
		CHECK(registry.retain(consumer, dupped, 999, 0, counterOffset, &again) == 0 && again == id, "a duplicate descriptor is the same surface, the hint is ignored");
		close(dupped);
		CHECK(registry.surfaceCount() == 2, "two surfaces");

		// counter: both hold, neither has imported a buffer
		CHECK(counter(memory) == 2, "two memory users published");
		IOSurfaceRegistry::State state;
		CHECK(registry.getState(id, &state) == 0 && state.holders == 2 && state.memoryUsers == 2 && state.flags == 0, "state: two holders, not global, no buffer");
		CHECK(registry.getState(otherID, &state) == 0 && state.flags == DSERVER_IOSURFACE_STATE_GLOBAL, "state: global");

		// bad arguments
		uint32_t unused;
		CHECK(registry.retain(producer, -1, 0, 0, 0, &unused) == -EBADF, "no descriptor");
		CHECK(registry.retain(producer, memory, 0, 0x8, 0, &unused) == -EINVAL, "unknown flag");
		CHECK(registry.retain(producer, memory, 0, 0, 2, &unused) == -EINVAL, "misaligned counter");
		CHECK(registry.retain(producer, memory, 0, 0, DSERVER_IOSURFACE_COUNTER_LIMIT, &unused) == -EINVAL, "counter past the first page");
		int pipes[2];
		CHECK(pipe(pipes) == 0, "pipe");
		CHECK(registry.retain(producer, pipes[0], 0, 0, 0, &unused) == -EINVAL, "not a memory object");
		close(pipes[0]);
		close(pipes[1]);

		// lookup: global surfaces for everyone, others only for holders
		int found = -1;
		CHECK(registry.lookup(stranger, id, &found) == -ENOENT, "a surface that is not global is not found by others");
		CHECK(registry.lookup(consumer, id, &found) == 0 && found >= 0, "a holder finds it");
		struct stat a, b;
		CHECK(found >= 0 && fstat(found, &a) == 0 && fstat(memory, &b) == 0 && a.st_ino == b.st_ino, "the lookup returns the memory object");
		if (found >= 0) {
			close(found);
		}
		found = -1;
		CHECK(registry.lookup(stranger, otherID, &found) == 0 && found >= 0, "a global surface is found by anyone");
		if (found >= 0) {
			close(found);
		}
		CHECK(registry.lookup(stranger, 12345, &found) == -ENOENT, "an unknown ID is not found");

		// GPU buffer
		int buffer = -1, published = -1;
		dserver_iosurface_gpu_buffer_t info = bufferInfo(0x0300000000e08014ULL), out;
		CHECK(registry.copyGPUBuffer(consumer, id, &buffer, &out) == -ENOENT, "no buffer yet");
		int bufferObject = memfd_create("gpu-buffer", MFD_CLOEXEC);
		CHECK(registry.publishGPUBuffer(stranger, id, bufferObject, info, &published, &out) == -EPERM, "only a holder publishes");
		dserver_iosurface_gpu_buffer_t bad = info;
		bad.render_node[0] = '\0';
		CHECK(registry.publishGPUBuffer(producer, id, bufferObject, bad, &published, &out) == -EINVAL, "a buffer without a render node is refused");
		bad = info;
		std::memset(bad.render_node, 'x', sizeof(bad.render_node));
		CHECK(registry.publishGPUBuffer(producer, id, bufferObject, bad, &published, &out) == -EINVAL, "an unterminated render node is refused");
		CHECK(registry.publishGPUBuffer(producer, id, bufferObject, info, &published, &out) == 0 && published >= 0, "the producer publishes a buffer");
		CHECK(std::memcmp(&out, &info, sizeof(info)) == 0, "and gets its description back");
		CHECK(counter(memory) == 1, "the producer imported it: one memory user left");
		if (published >= 0) {
			close(published);
		}

		// a second buffer loses
		int secondObject = memfd_create("gpu-buffer-2", MFD_CLOEXEC);
		dserver_iosurface_gpu_buffer_t second = bufferInfo(0x0300000000e08015ULL);
		published = -1;
		CHECK(registry.publishGPUBuffer(consumer, id, secondObject, second, &published, &out) == 0, "a racing publisher succeeds");
		CHECK(out.modifier == info.modifier, "and gets the first buffer's description");
		CHECK(published >= 0 && fstat(published, &a) == 0 && fstat(bufferObject, &b) == 0 && a.st_ino == b.st_ino, "and the first buffer");
		if (published >= 0) {
			close(published);
		}
		close(secondObject);
		close(bufferObject);
		CHECK(counter(memory) == 0, "both imported: no memory users");
		CHECK(registry.getState(id, &state) == 0 && state.memoryUsers == 0 && (state.flags & DSERVER_IOSURFACE_STATE_HAS_GPU_BUFFER), "state: buffer, no memory users");

		CHECK(registry.copyGPUBuffer(stranger, id, &buffer, &out) == -EPERM, "a process that does not hold it gets no buffer");
		CHECK(registry.copyGPUBuffer(consumer, id, &buffer, &out) == 0 && buffer >= 0 && out.modifier == info.modifier, "a holder copies the buffer");
		if (buffer >= 0) {
			close(buffer);
		}

		// usage
		CHECK(registry.setUsage(consumer, id, DSERVER_IOSURFACE_USAGE_USES_MEMORY) == 0 && counter(memory) == 1, "a process that uses the memory counts again");
		CHECK(registry.setUsage(consumer, id, 0x80) == -EINVAL, "unknown usage bits");
		CHECK(registry.setUsage(stranger, id, DSERVER_IOSURFACE_USAGE_USES_MEMORY) == -EPERM, "only holders set usage");

		// holds: the consumer holds twice
		CHECK(registry.release(consumer, id) == 0 && registry.getState(id, &state) == 0 && state.holders == 2, "one of two holds released");
		CHECK(registry.release(consumer, id) == 0 && registry.getState(id, &state) == 0 && state.holders == 1, "the consumer's last hold released");
		CHECK(counter(memory) == 0, "the counter follows");
		CHECK(registry.release(consumer, id) == -ENOENT, "nothing left to release");

		// a process that dies drops all its holds; the last holder frees the surface
		CHECK(registry.retain(consumer, other, 0, 0, counterOffset, &again) == 0 && again == otherID, "the consumer holds the global surface");
		registry.forgetProcess(producer);
		CHECK(registry.getState(id, &state) == -ENOENT, "the producer's surface is gone with it");
		CHECK(registry.getState(otherID, &state) == 0 && state.holders == 1, "the shared one stays for the consumer");
		CHECK(registry.surfaceCount() == 1, "one surface left");

		// a surface whose last holder left comes back under its old ID
		uint32_t revived = 0;
		CHECK(registry.retain(consumer, memory, id, 0, counterOffset, &revived) == 0 && revived == id, "the ID hint is taken for a new entry");
		uint32_t taken = 0;
		int third = newMemory();
		CHECK(registry.retain(consumer, third, otherID, 0, 0, &taken) == 0 && taken != otherID && taken != 0, "an ID hint in use is not");
		registry.forgetProcess(consumer);
		CHECK(registry.surfaceCount() == 0, "all surfaces gone");
		close(third);
		close(memory);
		close(other);
	}

	CHECK(openDescriptors() == baseline, "no descriptor leaked");

	std::printf("%s\n", fails == 0 ? "ALL PASS" : "SOME FAILED");
	return fails == 0 ? 0 : 1;
}
