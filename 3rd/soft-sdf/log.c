#include "common.h"
#include <stdarg.h>
#include <time.h>

#ifdef LINUX
    #include <syslog.h>
#endif

static char logpath[260] = {0};
static unsigned int logsize = 2 * 1024 * 1024;

void LOG_SetPath_(const char* path)
{
    if (path)
    {
        strcpy(logpath, path);
        return;
    }
}

void LOG_SetSize_(const unsigned int size )
{
    if (size > 0)
    {
        logsize = size;
        return;
    }
}

void LOG_Write(char* filepath, char* format, ...)
{
    FILE *pFile = NULL;
    va_list args = {0};
    char logBuff[600] = {0};
    char logFile[256] = {0};
    unsigned long fileSize = 0;
    char logHeader[64] = {0};  //format: 2015-09-14 01:33:31 PID=8953 TID=1234
    int ret = 0;

#if defined(LINUX)
    time_t now;
    struct tm *timenow;
    time(&now);
    timenow = localtime(&now);
    snprintf(logHeader, 60, "%d-%.2d-%.2d %.2d:%.2d:%.2d [PID=%d TID=%d] ", timenow->tm_year + 1900, timenow->tm_mon + 1, timenow->tm_mday, timenow->tm_hour, timenow->tm_min, timenow->tm_sec, GETPID(),
             GETTID());
#elif defined(WIN32)  //win32 wince
    SYSTEMTIME sTime;
    char *pBuff = logBuff;
    GetLocalTime(&sTime);
    _snprintf(logHeader, 60, "%d-%.2d-%.2d %.2d:%.2d:%.2d [PID=%d TID=%d] ", sTime.wYear, sTime.wMonth, sTime.wDay, sTime.wHour, sTime.wMinute, sTime.wSecond, GETPID(), GETTID());
#else
#endif
    strncpy(logBuff, logHeader, 60);

    //format
    va_start( args, format );
#ifdef WIN32
    _vsnprintf(logBuff + strlen(logHeader), 540, format, args);
#else
    vsnprintf(logBuff + strlen(logHeader), 540, format, args);
#endif
    va_end( args);
    strcat(logBuff, "\n");

    //wirite syslog
#if defined(LINUX)
    syslog(LOG_DEBUG | LOG_USER, "%s\n", logBuff);
#endif

    if (0 == strlen(logpath))
    {
        //wirte file
#if defined(LINUX)
        strcpy(logpath, "/tmp");
#elif defined(WIN32)
        strcpy(logpath, "c:/tmp");
#else
#endif
    }

    sprintf(logFile, "%s/%s", logpath, LOGNAME);
    pFile = fopen(logFile, "ab+");//0666
    if (!pFile)
    {
        return ;
    }
    fseek(pFile, 0, SEEK_END);
    fileSize = ftell(pFile);
    if (fileSize > logsize)
    {
        fclose(pFile);
        pFile = fopen(logFile, "wb+");
        if (!pFile)
        {
            return ;
        }
    }
    ret = (int)fwrite(logBuff, 1, strlen(logBuff), pFile);
    fclose(pFile);
}

void LOG_WriteHex_(char * path, unsigned char* buf, int bufLen)
{
    int loglen = 0;
    char *hexlog = NULL;

    if (bufLen > 200)
    {
        bufLen = 200;
    }
    loglen = bufLen * 2 + 1;
    hexlog = malloc(loglen);
    if (!hexlog)
    {
        return;
    }
    hex2str(buf, bufLen, hexlog, loglen);
    LOG_Write(path, hexlog);
    free(hexlog);
}
