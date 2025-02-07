#ifndef DHT_LOG_H_
#define DHT_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

// 添加颜色常量定义
#define COLOR_RESET   "\033[0m"
#define COLOR_ERROR   "\033[31m"   // 红色
#define COLOR_WARNING "\033[33m"   // 黄色
#define COLOR_INFO    "\033[92m"   // 浅绿色
#define COLOR_DEBUG   "\033[36m"   // 青色

// 添加日志等级定义
typedef enum {
    LOG_LEVEL_ERRO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DBUG
} LogLevel;

// 声明日志打印函数，支持格式化
void dht_log_message_internal(LogLevel level, const char *file, int line, const char *func, const char *format, ...);
void dht_set_log_file(const char *filename);
#define DHT_LOG_MESSAGE(level, format, ...) \
    dht_log_message_internal(level, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
// ... existing code ...
#define DHT_LOG_SIMPLE(level, format, ...) \
    dht_log_message_internal(level, NULL, 0, NULL, format, ##__VA_ARGS__)
// ... existing code ...


#ifdef __cplusplus
}
#endif

#endif /* DHT_LOG_H_ */
