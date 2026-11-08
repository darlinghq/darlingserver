/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Lubos Dolezel
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

// Runs the real pthread cancellation state machine of the duct-tape layer
// (dtape_thread_pthread_{markcancel,testcancel,canceled}, thread_abort_safely,
// thread_mark_wait_locked, dtape_thread_returning_to_user), cut out of duct-tape/src
// by tests/run-pthread-cancel.sh, against a minimal stand-in for the XNU thread.
// The flag values come from the imported XNU headers (PTHREAD_CANCEL_DEFS_INC).
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include PTHREAD_CANCEL_DEFS_INC

typedef int kern_return_t;
typedef int wait_result_t;
typedef int wait_interrupt_t;
typedef int boolean_t;

// block_hint.h: kThreadWaitNone is the first value of an enum
enum { kThreadWaitNone = 0 };

struct thread {
	int sched_flags;
	int state;
	boolean_t at_safe_point;
	wait_result_t wait_result;
	int block_hint;
	int pending_block_hint;

	// test-only bookkeeping
	int lock_depth;
};
typedef struct thread* thread_t;

typedef struct dtape_thread {
	int uu_flag;
	struct thread xnu_thread;
} dtape_thread_t;

static int lock_errors;
static int clear_wait_calls;

static void thread_lock(thread_t thread) {
	if (thread->lock_depth++ != 0)
		lock_errors++;
}

static void thread_unlock(thread_t thread) {
	if (--thread->lock_depth != 0)
		lock_errors++;
}

// stand-in for the waitq code: wakes the thread if it is waiting
static kern_return_t clear_wait_internal(thread_t thread, wait_result_t result) {
	clear_wait_calls++;
	if (thread->lock_depth != 1)
		lock_errors++;
	if (!(thread->state & TH_WAIT))
		return KERN_NOT_WAITING;
	thread->state &= ~TH_WAIT;
	thread->at_safe_point = 0;
	thread->wait_result = result;
	return KERN_SUCCESS;
}

#include PTHREAD_CANCEL_FNS_INC

static int fails;
#define CHECK(c, what) do { int ok_ = (c); printf("%s %s\n", ok_ ? "PASS" : "FAIL", what); if (!ok_) fails++; } while (0)

static void reset(dtape_thread_t* t) {
	memset(t, 0, sizeof(*t));
	clear_wait_calls = 0;
}

// make the thread look like it is blocked in an abort-safe wait (e.g. psynch_cvwait)
static void block_abortsafe(dtape_thread_t* t) {
	CHECK(thread_mark_wait_locked(&t->xnu_thread, THREAD_ABORTSAFE) == THREAD_WAITING, "setup: abort-safe wait starts");
}

static void test_running_target(void) {
	dtape_thread_t t;
	bool interrupt = false;
	reset(&t);

	CHECK(dtape_thread_pthread_markcancel(&t, &interrupt), "running: markcancel reports the thread as marked");
	CHECK(interrupt, "running: markcancel asks for the thread to be interrupted");
	CHECK((t.uu_flag & (UT_CANCEL | UT_CANCELED)) == UT_CANCEL, "running: UT_CANCEL set, UT_CANCELED clear");
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == TH_SFLAG_ABORTED_MASK, "running: a safe abort is left pending");

	CHECK(thread_mark_wait_locked(&t.xnu_thread, THREAD_INTERRUPTIBLE) == THREAD_WAITING,
		"running: pending safe abort does not interrupt a THREAD_INTERRUPTIBLE wait");
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == TH_SFLAG_ABORTED_MASK, "running: ... and stays pending");
	t.xnu_thread.state = 0;

	CHECK(thread_mark_wait_locked(&t.xnu_thread, THREAD_UNINT) == THREAD_WAITING, "running: pending abort does not interrupt a THREAD_UNINT wait");
	t.xnu_thread.state = 0;

	CHECK(thread_mark_wait_locked(&t.xnu_thread, THREAD_ABORTSAFE) == THREAD_INTERRUPTED, "running: the next abort-safe wait is interrupted");
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == 0, "running: the safe abort is one-shot");
	CHECK(thread_mark_wait_locked(&t.xnu_thread, THREAD_ABORTSAFE) == THREAD_WAITING, "running: a second abort-safe wait blocks");

	CHECK(dtape_thread_pthread_canceled(&t, 0) == 0, "running: canceled(0) acts on the mark");
	CHECK((t.uu_flag & (UT_CANCEL | UT_CANCELED)) == UT_CANCELED, "running: UT_CANCEL moved to UT_CANCELED");
	CHECK(dtape_thread_pthread_canceled(&t, 0) == EINVAL, "running: a second canceled(0) returns EINVAL");
	CHECK(!dtape_thread_pthread_testcancel(&t), "running: testcancel is false once cancelled");
}

static void test_blocked_target(void) {
	dtape_thread_t t;
	bool interrupt = false;
	reset(&t);
	block_abortsafe(&t);

	CHECK(dtape_thread_pthread_markcancel(&t, &interrupt), "blocked: markcancel reports the thread as marked");
	CHECK(interrupt, "blocked: markcancel asks for the thread to be interrupted");
	CHECK(clear_wait_calls == 1 && t.xnu_thread.wait_result == THREAD_INTERRUPTED, "blocked: the abort-safe wait is interrupted");
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == 0, "blocked: no abort is left pending");

	CHECK(dtape_thread_pthread_markcancel(&t, &interrupt), "blocked: a second markcancel still reports the thread as marked");
	CHECK(!interrupt, "blocked: a second markcancel does not ask for another interruption");
	CHECK(clear_wait_calls == 1 && (t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == 0, "blocked: a second markcancel does not abort again");
}

static void test_disabled(void) {
	dtape_thread_t t;
	bool interrupt = false;
	reset(&t);

	CHECK(dtape_thread_pthread_canceled(&t, 2) == 0, "disabled: canceled(2) returns 0");
	block_abortsafe(&t);
	CHECK(dtape_thread_pthread_markcancel(&t, &interrupt), "disabled: markcancel still marks the thread");
	CHECK(!interrupt, "disabled: markcancel does not ask for the thread to be interrupted");
	CHECK(clear_wait_calls == 0 && (t.xnu_thread.state & TH_WAIT), "disabled: the wait is not interrupted");
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == 0, "disabled: no abort is left pending");
	CHECK(!dtape_thread_pthread_testcancel(&t), "disabled: testcancel is false");
	CHECK(dtape_thread_pthread_canceled(&t, 0) == EINVAL, "disabled: canceled(0) returns EINVAL");
	CHECK(t.uu_flag & UT_CANCEL, "disabled: the mark is kept");

	CHECK(dtape_thread_pthread_canceled(&t, 1) == 0, "disabled: canceled(1) returns 0");
	CHECK(dtape_thread_pthread_testcancel(&t), "re-enabled: testcancel is true");
	CHECK(dtape_thread_pthread_canceled(&t, 0) == 0, "re-enabled: canceled(0) acts on the kept mark");
}

static void test_testcancel(void) {
	dtape_thread_t t;
	bool interrupt = false;
	reset(&t);

	CHECK(!dtape_thread_pthread_testcancel(&t), "testcancel: false for an unmarked thread");
	t.uu_flag |= UT_NOTCANCELPT;
	CHECK(dtape_thread_pthread_markcancel(&t, &interrupt), "notcancelpt: markcancel marks the thread");
	CHECK(!interrupt, "notcancelpt: markcancel does not ask for the thread to be interrupted");
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == 0, "notcancelpt: no abort inside a non-cancellation point");

	CHECK(dtape_thread_pthread_testcancel(&t), "testcancel: true for a marked, enabled thread");
	CHECK((t.uu_flag & UT_NOTCANCELPT) == 0, "testcancel: clears UT_NOTCANCELPT");
	CHECK(dtape_thread_pthread_testcancel(&t) && (t.uu_flag & UT_CANCEL), "testcancel: does not consume the mark");
	CHECK(dtape_thread_pthread_canceled(&t, 0) == 0, "testcancel: canceled(0) still acts on the mark");
}

static void test_return_to_user(void) {
	dtape_thread_t t;
	bool interrupt = false;
	reset(&t);

	// cancel arrives while the thread runs user code, then it disables cancellation before sleeping
	CHECK(dtape_thread_pthread_markcancel(&t, &interrupt), "return: markcancel marks the running thread");
	CHECK(dtape_thread_pthread_canceled(&t, 2) == 0, "return: canceled(2) returns 0");
	dtape_thread_returning_to_user(&t);
	CHECK((t.xnu_thread.sched_flags & TH_SFLAG_ABORTED_MASK) == 0, "return: the pending safe abort is cleared when the call replies");
	CHECK(thread_mark_wait_locked(&t.xnu_thread, THREAD_ABORTSAFE) == THREAD_WAITING, "return: a later abort-safe wait (nanosleep) blocks");
	CHECK(t.uu_flag & UT_CANCEL, "return: the cancel mark itself is kept");

	reset(&t);
	dtape_thread_returning_to_user(&t);
	CHECK(t.xnu_thread.sched_flags == 0 && t.xnu_thread.lock_depth == 0, "return: no-op without a pending abort");
}

int main(void) {
	test_running_target();
	test_blocked_target();
	test_disabled();
	test_testcancel();
	test_return_to_user();
	CHECK(lock_errors == 0, "the thread lock is held (not recursively) around every flag update");
	printf("%s\n", fails ? "RESULT: FAIL" : "RESULT: PASS");
	return fails ? 1 : 0;
}
