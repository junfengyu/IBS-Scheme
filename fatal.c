//#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>

#include "log.h"

/* Fatal messages.  This function never returns. */

void
fatal(const char *fmt,...)
{
    exit(255);
}
