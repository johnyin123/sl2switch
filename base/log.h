#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <stdarg.h>

#define EMERG   0
#define ALERT   1
#define ERROR   2
#define WARN    3
#define INFO    4
#define DEBUG   5

#define inner_log(level, fmt, ...) do { __log(level, "[%s]:[%s:%d(%s)] " fmt "\n", #level, __FUNCTION__, __LINE__, __FILE__, ##__VA_ARGS__); }while(0)

extern int logfile;
extern int log_level;
static inline void __log(int priority, const char *fmt, ...)
{
    if ((priority > log_level) || (logfile == 0))
        return;
    va_list ap;
    va_start(ap, fmt);
    vdprintf(logfile, fmt, ap);
    va_end(ap);
}

#endif
