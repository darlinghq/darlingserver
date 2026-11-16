// Hidden kernel symbols the duct-tape objects of tests/run-stub-sweep.sh reference (built without kernel headers):
// locks are no-ops in this single-threaded test.
void usimple_lock_init(void* lock, unsigned short tag) {}
void usimple_lock(void* lock, void* group) {}
void usimple_unlock(void* lock) {}
