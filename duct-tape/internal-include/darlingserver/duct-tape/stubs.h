#ifndef _DARLINGSERVER_DUCT_TAPE_STUBS_H_
#define _DARLINGSERVER_DUCT_TAPE_STUBS_H_

#include <stdbool.h>

void dtape_stub_log(const char* function_name, int safety, const char* subsection);

// for general functions where it's unknown whether they can be safely stubbed or not
#define dtape_stub(...) (dtape_stub_log(__FUNCTION__, 0, "" __VA_ARGS__))

// for functions that have been confirmed to be okay being stubbed
#define dtape_stub_safe(...) (dtape_stub_log(__FUNCTION__, 1, "" __VA_ARGS__))

// for functions that have been confirmed to require an actual implementation (rather than a simple stub)
#define dtape_stub_unsafe(...) ({ \
		dtape_stub_log(__FUNCTION__, -1, "" __VA_ARGS__); \
		__builtin_unreachable(); \
	}) \

#endif // _DARLINGSERVER_DUCT_TAPE_STUBS_H_
