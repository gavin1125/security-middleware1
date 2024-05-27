#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <string.h>

#define LOG_NAME    "security_engine.log"

enum LogLevel {
    LOG_EMERG = 0,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    LOG_MAX
};

#ifdef BUILD_DEBUG
#define ENTRY debug("ENTERING %s()", __func__)
#define debug(...) Log(LOG_DEBUG, __VA_ARGS__)
#define info(...) Log(LOG_INFO, __VA_ARGS__)
#define notice(...) Log(LOG_NOTICE, __VA_ARGS__)
#define warning(...) Log(LOG_WARNING, __VA_ARGS__)
#define err(...) Log(LOG_ERR, __VA_ARGS__)
#define critical(...) Log(LOG_CRIT, __VA_ARGS__)
#define alert(...) Log(LOG_ALERT, __VA_ARGS__)
#define emerge(...) Log(LOG_EMERG, __VA_ARGS__)
#else
#define ENTRY
#define debug(...)
#define info(...)
#define notice(...)
#define warning(...)
#define err(...)
#define critical(...)
#define alert(...)
#define emerge(...)
#endif

#define NOP(x) (void)(x)

// sets logging level for the library
void SetLogLevel(unsigned int level);

void SetLogPath(const char *path);

void SetLogSize(unsigned int size);

#endif /* LOG_H */
