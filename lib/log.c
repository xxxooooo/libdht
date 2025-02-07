#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "dht/log.h"

static FILE *log_file = NULL;

// 设置日志文件
void dht_set_log_file(const char *filename) {
    if (log_file)
        fclose(log_file);
    log_file = fopen(filename, "a");
}

#define MAX_FILENAME_LENGTH 50

// 辅助函数：获取文件路径的最后四层，并填充到固定长度
void format_filename(const char *full_path, char *formatted_path) {
    const char *last_slash = strrchr(full_path, '/');
    const char *second_last_slash = NULL;
    const char *third_last_slash = NULL;
    const char *fourth_last_slash = NULL;

    if (last_slash) {
        second_last_slash = full_path;
        while (second_last_slash < last_slash) {
            second_last_slash = strchr(second_last_slash + 1, '/');
            if (second_last_slash && second_last_slash < last_slash) {
                fourth_last_slash = third_last_slash;
                third_last_slash = second_last_slash;
            }
        }
    }

    const char *start = fourth_last_slash ? fourth_last_slash :
                        (third_last_slash ? third_last_slash :
                        (second_last_slash ? second_last_slash :
                        (last_slash ? last_slash : full_path)));

    if (start != full_path) {
        start++; // Skip the leading slash
    }

    snprintf(formatted_path, MAX_FILENAME_LENGTH + 1, "%s", start);
}

void dht_log_message_internal(LogLevel level, const char *file, int line, const char *func, const char *format, ...) {
    const char *level_strings[] = {
        "ERRO",
        "WARN",
        "INFO",
        "DBUG"
    };

    const char *level_colors[] = {
        COLOR_ERROR,
        COLOR_WARNING,
        COLOR_INFO,
        COLOR_DEBUG
    };

    // 获取当前时间
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    // 格式化文件名
    char formatted_file[MAX_FILENAME_LENGTH + 1];
    format_filename(file, formatted_file);

    // 构造日志消息
    char msg_buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);

    // 打印到控制台
    printf("%s[%s %-21s:%5d] [%s] %s: %s%s",
        level_colors[level], time_buf, formatted_file, line,
        level_strings[level], func, msg_buf, COLOR_RESET);

    // 写入日志文件
    if (log_file) {
        fprintf(log_file, "[%s %-21s:%5d] [%s] %s: %s",
            time_buf, formatted_file, line, level_strings[level], func, msg_buf);
        fflush(log_file);
    }
}