#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

// 连接状态枚举（优化字符串比较性能）
typedef enum {
    CONN_STATUS_ESTABLISHED,
    CONN_STATUS_LISTEN,
    CONN_STATUS_TIME_WAIT,
    CONN_STATUS_CLOSE_WAIT,
    CONN_STATUS_SYN_SENT,
    CONN_STATUS_SYN_RECV,
    CONN_STATUS_FIN_WAIT1,
    CONN_STATUS_FIN_WAIT2,
    CONN_STATUS_CLOSE,
    CONN_STATUS_CLOSING,
    CONN_STATUS_LAST_ACK,
    CONN_STATUS_NONE,
    CONN_STATUS_UNKNOWN
} ConnectionStatus;


typedef struct {
    char protocol[16];   // TCP or UDP
    char local_addr[128];
    char remote_addr[128];
    char status[32];     // 字符串形式（用于显示）
    ConnectionStatus status_enum;  // 枚举形式（用于比较）
    int32_t pid;
    char process[256];
} ConnectionInfo;

// 统计数据结构
typedef struct {
    int total;
    int established;
    int listening;
    int suspicious;
    char top_process[256];
    int top_process_count;
} ConnectionStats;

// 排序模式
typedef enum {
    SORT_NONE,
    SORT_BY_PID,
    SORT_BY_PROCESS,
    SORT_BY_REMOTE
} SortMode;

// 逻辑层接口
int is_suspicious(const ConnectionInfo *conn);
void calculate_stats(const ConnectionInfo *conns, int count, ConnectionStats *stats);
int is_internal(const char *addr);
int is_external_connection(const ConnectionInfo *conn);
void sort_connections(ConnectionInfo *conns, int count, SortMode mode);

// HTML 导出接口
int export_html_report(const char *filename, ConnectionInfo *conns, int count);

// 获取当前所有连接
ConnectionInfo* scanner_get_connections(int *count);

// 释放连接信息占用的内存
void scanner_free_connections(ConnectionInfo *conns, int count);

#endif // SCANNER_H
