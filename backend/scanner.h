#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

typedef struct {
    char protocol[16];   // TCP or UDP
    char local_addr[128];
    char remote_addr[128];
    char status[32];
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

// 逻辑层接口
int is_suspicious(const ConnectionInfo *conn);
void calculate_stats(const ConnectionInfo *conns, int count, ConnectionStats *stats);
int is_internal(const char *addr);

// 获取当前所有连接
ConnectionInfo* scanner_get_connections(int *count);

// 释放连接信息占用的内存
void scanner_free_connections(ConnectionInfo *conns, int count);

#endif // SCANNER_H
