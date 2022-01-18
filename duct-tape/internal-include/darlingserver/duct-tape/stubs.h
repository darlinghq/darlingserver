#ifndef _DARLINGSERVER_DUCT_TAPE_STUBS_H_
#define _DARLINGSERVER_DUCT_TAPE_STUBS_H_

#include <stdbool.h>

void dtape_stub_log(const char* function_name, int safety);

#define dtape_stub() (dtape_stub_log(__FUNCTION__, 0))
#define dtape_stub_safe() (dtape_stub_log(__FUNCTION__, 1))
#define dtape_stub_unsafe() (dtape_stub_log(__FUNCTION__, -1))

#endif // _DARLINGSERVER_DUCT_TAPE_STUBS_H_
