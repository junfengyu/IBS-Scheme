#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>

#include "log.h"

/* Fatal messages.  This function never returns. */

void
fatal(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_FATAL, fmt, args);
	va_end(args);
	cleanup_exit(255);
}
