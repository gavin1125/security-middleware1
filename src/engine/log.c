#include <stdarg.h>
#include <stdio.h>

#include "log.h"
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

static char log_path[260] = {0};
static unsigned int log_size = 2 * 1024 * 1024;
static unsigned int log_level = LOG_INFO;

void SetLogPath(const char *path) {
    if (path) {
        strcpy(log_path, path);
        return;
    }
}

void SetLogSize(const unsigned int size) {
    if (size > 0) {
        log_size = size;
        return;
    }
}

void SetLogLevel(const unsigned int level) {
    if (level <= 7) {
        log_level = level;
        return;
    }
}

void Log(int level, char *format, ...) {
    if (log_level < level) {
        return;
    }

    FILE *pFile = NULL;
    va_list args = {0};
    char logBuff[600] = {0};
    char logFile[256] = {0};
    unsigned long fileSize;
    char logHeader[64] = {0};  //format: 2015-09-14 01:33:31 PID=8953 TID=1234

    time_t now;
    struct tm *timenow;
    time(&now);
    timenow = localtime(&now);
    snprintf(logHeader, 60, "%d-%.2d-%.2d %.2d:%.2d:%.2d [PID=%d TID=%d] ", timenow->tm_year + 1900,
             timenow->tm_mon + 1, timenow->tm_mday, timenow->tm_hour, timenow->tm_min, timenow->tm_sec, getpid(),
             (int) pthread_self());

    strncpy(logBuff, logHeader, 60);

    //format
    va_start(args, format);

    vsnprintf(logBuff + strlen(logHeader), 540, format, args);
    va_end(args);
    strcat(logBuff, "\n");

    //write syslog
    syslog((int) level | LOG_USER, "%s\n", logBuff);

    if (0 == strlen(log_path)) {
        //write file
        strcpy(log_path, "/tmp");

    }

    sprintf(logFile, "%s/%s", log_path, LOG_NAME);
    pFile = fopen(logFile, "ab+");//0666
    if (!pFile) {
        return;
    }
    fseek(pFile, 0, SEEK_END);
    fileSize = ftell(pFile);
    if (fileSize > log_size) {
        fclose(pFile);
        pFile = fopen(logFile, "wb+");
        if (!pFile) {
            return;
        }
    }
    fwrite(logBuff, 1, strlen(logBuff), pFile);
    fclose(pFile);
}