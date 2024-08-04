#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include "log.h"

static int log_mode = LOG_MODE_STDOUT;
static int log_level = LOG_LEVEL_ERROR;
static char log_file[512] = "";

/**
printf("\033[字背景颜色;字体颜色m 字符串 \033[0m" );
字背景颜色范围: 40--49             字颜色: 30—39
 40: 黑                           30: 黑
 41: 红                           31: 红
 42: 绿                           32: 绿
 43: 黄                           33: 黄
 44: 蓝                           34: 蓝
 45: 紫                           35: 紫
 46: 深绿                         36: 深绿
 47: 白色                         37: 白色

\033[0m   关闭所有属性
\033[1m   设置高亮度
\033[4m   下划线
\033[5m   闪烁
\033[7m   反显
\033[8m   消隐
\033[30m   --   \033[37m   设置前景色
\033[40m   --   \033[47m   设置背景色
\033[nA   光标上移n行
\03[nB   光标下移n行
\033[nC   光标右移n行
\033[nD   光标左移n行
*/

static const char *level_str[LOG_LEVEL_MAX] = {
    "",
    "\033[1m\033[31mERROR\033[0m",
    "\033[1m\033[32mINFO\033[0m ",
    "DEBUG"};

int _log_init(int mode, int level, const char *file)
{
    log_mode = LOG_MODE_STDOUT;
    if (mode > LOG_MODE_STDOUT && mode < LOG_MODE_MAX)
    {
        log_mode = mode;
    }

    log_level = LOG_LEVEL_DEBUG;
    if (level > LOG_LEVEL_DEBUG && level < LOG_LEVEL_MAX)
    {
        log_level = level;
    }

    if (mode == LOG_MODE_FILE)
    {
        strncpy(log_file, file, sizeof(log_file));
    }
    return 0;
}

void _log_print(int level, const char *file, const char *function, unsigned int line, const char *format, ...)
{
    FILE *fd = stdout;
    switch (log_mode)
    {
    case LOG_MODE_STDOUT:
        break;

    case LOG_MODE_DISABLE:
        return;

    case LOG_MODE_FILE:
        fd = fopen(log_file, "a");
        if (fd == NULL)
        {
            return;
        }
        break;

    default:
        break;
    }

    time_t timer_t;
    char szTimeBuf[64] = {0};

    timer_t = time(NULL);
    strftime(szTimeBuf, sizeof(szTimeBuf), "%Y/%m/%d %X", localtime(&timer_t));
    // fprintf(fd, "[%s][%s][%s:%d][%s] ", level_str[level], szTimeBuf, file, line, function);
    // fprintf(fd, "[%s][%s][%s:%d] ", level_str[level], szTimeBuf, function, line);
    // fflush(fd);

    va_list ap;
    char szLogBuf[4096] = {0};
    va_start(ap, format);
    vsnprintf(szLogBuf, sizeof(szLogBuf), format, ap);
    va_end(ap);

    char truncated_function[30 + 1];
    if (strlen(function) > 30) {
        strncpy(truncated_function, function, 30);
        truncated_function[30] = '\0';
    } else {
        strcpy(truncated_function, function);
    }

    // fprintf(fd, "[%s][%s][%s:%d] %s", level_str[level], szTimeBuf, function, line, szLogBuf);
    fprintf(fd, "[%s][%30s:%-4d] %s", level_str[level], truncated_function, line, szLogBuf);
    // fprintf(fd, "%s\n", szLogBuf);
    fflush(fd);

    if (fd != stdout)
    {
        fclose(fd);
    }
}