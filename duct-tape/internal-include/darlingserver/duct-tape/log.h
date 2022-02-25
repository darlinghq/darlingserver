#ifndef _DARLINGSERVER_DUCT_TAPE_LOG_H_
#define _DARLINGSERVER_DUCT_TAPE_LOG_H_

#include <darlingserver/duct-tape/types.h>

__attribute__((format(printf, 2, 3)))
extern void dtape_log(dtape_log_level_t level, const char* format, ...);

#define dtape_log_debug(format, ...) dtape_log(dtape_log_level_debug, format, ## __VA_ARGS__)
#define dtape_log_info(format, ...) dtape_log(dtape_log_level_info, format, ## __VA_ARGS__)
#define dtape_log_warning(format, ...) dtape_log(dtape_log_level_warning, format, ## __VA_ARGS__)
#define dtape_log_error(format, ...) dtape_log(dtape_log_level_error, format, ## __VA_ARGS__)

#endif // _DARLINGSERVER_DUCT_TAPE_LOG_H_
