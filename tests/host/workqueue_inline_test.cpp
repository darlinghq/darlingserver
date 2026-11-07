// WorkQueue::tryRunInline: the caller runs the item only when a worker is idle and nothing is queued,
// and items are still processed one at a time and in order. internal-include/darlingserver/workers.hpp
// is used unchanged (header only).
#include <darlingserver/workers.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

using namespace DarlingServer;
static int fails;
#define CHECK(c, what) do { int ok_ = (c); std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static std::atomic<int> inFlight{0};
static std::atomic<int> maxInFlight{0};
static std::mutex logLock;
static std::vector<std::pair<int, std::thread::id>> ran;

static void record(int item) {
	int now = ++inFlight;
	int seen = maxInFlight.load();
	while (now > seen && !maxInFlight.compare_exchange_weak(seen, now)) {}
	std::this_thread::sleep_for(std::chrono::milliseconds(5));
	{
		std::scoped_lock lock(logLock);
		ran.emplace_back(item, std::this_thread::get_id());
	}
	--inFlight;
}

static bool waitFor(std::function<bool()> done) {
	for (int i = 0; i < 400; ++i) {
		if (done()) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	return false;
}

static size_t ranCount() {
	std::scoped_lock lock(logLock);
	return ran.size();
}

int main() {
	const auto self = std::this_thread::get_id();

	if (!Config::singleThreadedWorkQueue) {
		WorkQueue<int> q(record);
		int item = 1;
		CHECK(!q.tryRunInline(item), "[multi-threaded queue] tryRunInline never runs the item");
		std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
		return fails != 0;
	}

	// the worker function may queue more items from the inline run, as a woken thread does
	WorkQueue<int>* qp = nullptr;
	std::atomic<bool> blockWorker{false};
	std::atomic<bool> workerBlocked{false};
	std::mutex gate;
	std::condition_variable gateCv;
	bool released = true;
	WorkQueue<int> q([&](int item) {
		if (item == 100) {
			// queues two follow-up items while running
			qp->push(101);
			qp->push(102);
		}
		if (item == 200 && blockWorker) {
			workerBlocked = true;
			std::unique_lock lock(gate);
			gateCv.wait(lock, [&] { return released; });
		}
		record(item);
	});
	qp = &q;

	std::this_thread::sleep_for(std::chrono::milliseconds(50)); // let the permanent worker start waiting

	{
		int item = 1;
		bool ran1 = q.tryRunInline(item);
		CHECK(ran1, "an idle queue runs the item inline");
		std::scoped_lock lock(logLock);
		CHECK(ran.size() == 1 && ran[0].first == 1 && ran[0].second == self, "the inline item ran on the calling thread, before tryRunInline returned");
	}
	{
		size_t before = ranCount();
		int item = 100;
		CHECK(q.tryRunInline(item), "the item that queues follow-ups runs inline");
		std::scoped_lock lock(logLock);
		bool ok = ran.size() == before + 3 && ran[before].first == 100 && ran[before + 1].first == 101 && ran[before + 2].first == 102;
		CHECK(ok, "follow-up items queued by the inline item run in order before tryRunInline returns");
		bool onSelf = ran[before + 1].second == self && ran[before + 2].second == self;
		CHECK(onSelf, "follow-up items ran on the calling thread, not on a worker");
	}
	{
		// a busy worker: the item has to go through the queue
		blockWorker = true;
		released = false;
		q.push(200);
		CHECK(waitFor([&] { return workerBlocked.load(); }), "the worker picked up the item that blocks it");
		int item = 2;
		CHECK(!q.tryRunInline(item), "a queue whose worker is busy refuses to run inline");
		{
			std::scoped_lock lock(gate);
			released = true;
		}
		gateCv.notify_all();
		q.push(item);
		CHECK(waitFor([&] { return ranCount() >= 6; }), "the busy worker finishes and the refused item still runs via the queue");
	}
	{
		// queued work must not run concurrently with an inline run
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		size_t before = ranCount();
		std::thread pusher([&] {
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
			q.push(301);
			q.push(302);
		});
		int item = 300;
		bool ranIt = q.tryRunInline(item);
		pusher.join();
		CHECK(ranIt, "an idle queue runs the item inline while another thread pushes");
		CHECK(waitFor([&] { return ranCount() >= before + 3; }), "items pushed by another thread meanwhile also run");
		CHECK(maxInFlight.load() == 1, "items never ran concurrently (inline run and worker are mutually exclusive)");
	}

	std::printf("%s (%d failures)\n", fails ? "FAILED" : "OK", fails);
	return fails != 0;
}
