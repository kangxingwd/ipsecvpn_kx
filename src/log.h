#ifndef _DEBUG_LOG_H_
#define _DEBUG_LOG_H_

/* 日志打印模式，默认为 1 */
enum
{
    LOG_MODE_STDOUT = 1,  // 标准输出
    LOG_MODE_FILE = 2,    // 记录文件
    LOG_MODE_DISABLE = 3, // 关闭日志
    LOG_MODE_MAX,
};

/* 日志打印等级，默认为 1 */
enum
{
    LOG_LEVEL_ERROR = 1, //
    LOG_LEVEL_INFO = 2,  //
    LOG_LEVEL_DEBUG = 3, //
    LOG_LEVEL_MAX,
};

/** 内部接口 */
int _log_init(int mode, int level, const char *file);
void _log_print(int level, const char *file, const char *function, unsigned int line, const char *format, ...);

/** 外部接口 */
/* LOG初始化 */
#define LOG_INIT(_log_mode, _log_level, _log_file) ({                 \
    int _log_ret = _log_init((_log_mode), (_log_level), (_log_file)); \
    (_log_ret);                                                       \
})

#define LOG_DEBUG(format, ...)  do {                                                          \
     _log_print((LOG_LEVEL_DEBUG), __FILE__, __FUNCTION__, __LINE__, format,   __VA_ARGS__ );    \
} while (0)

#define LOG_INFO(format, ...) do {                                                          \
    _log_print((LOG_LEVEL_INFO), __FILE__, __FUNCTION__, __LINE__, format,  __VA_ARGS__ );     \
} while (0)

#define LOG_ERROR(format, ...) do {                                                           \
    _log_print((LOG_LEVEL_ERROR), __FILE__, __FUNCTION__, __LINE__, format,   __VA_ARGS__ );     \
} while (0)

#endif
