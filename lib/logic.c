#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "backend/scanner.h"

// 常用端口白名单 (移植自 Go 版)
static const int COMMON_PORTS[] = {80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 8080, 8443, 9000, 27017, 5000};
static const int COMMON_PORTS_COUNT = sizeof(COMMON_PORTS) / sizeof(COMMON_PORTS[0]);

// 判断是否为内部回环地址
int is_internal(const char *addr) {
    return (strncmp(addr, "127.0.0.1", 9) == 0 || 
            strncmp(addr, "localhost", 9) == 0 || 
            strncmp(addr, "::1", 3) == 0 || 
            strncmp(addr, "[::1]", 5) == 0 ||
            strncmp(addr, "0.0.0.0", 7) == 0);
}

// 判断是否为外部连接（排除本地连接）
int is_external_connection(const ConnectionInfo *conn) {
    return !is_internal(conn->remote_addr);
}

// 判定可疑连接逻辑
int is_suspicious(const ConnectionInfo *conn) {
    // 强制类型转换以修改结构体内部用于 UI 显示的字段（虽然建议在 scanner 或 logic 中统一处理）
    ConnectionInfo *c = (ConnectionInfo *)conn;
    c->risk_reason[0] = '\0';

    // 1. 路径审计风险 (Path Audit)
    if (strcmp(c->exe_path, "N/A") != 0 && strcmp(c->exe_path, "Access Denied") != 0) {
        if (strstr(c->exe_path, "/tmp") || strstr(c->exe_path, "/var/tmp") || strstr(c->exe_path, "/dev/shm")) {
            strcpy(c->risk_reason, "TempDir");
            return 1;
        }
        // 检查隐藏路径（如 /home/user/.hidden/proc）
        if (strstr(c->exe_path, "/.")) {
            strcpy(c->risk_reason, "HiddenDir");
            return 1;
        }
    }

    // 2. 仅对已建立的外部通信进行进一步端口判定
    if (c->status_enum != CONN_STATUS_ESTABLISHED) return 0;
    if (is_internal(c->remote_addr)) return 0;

    // 提取端口
    const char *port_ptr = strrchr(c->remote_addr, ':');
    if (!port_ptr) return 0;
    int port = atoi(port_ptr + 1);

    // 非常用端口标记为可疑
    for (int i = 0; i < COMMON_PORTS_COUNT; i++) {
        if (port == COMMON_PORTS[i]) return 0;
    }
    
    strcpy(c->risk_reason, "UnusualPort");
    return 1;
}

void calculate_stats(const ConnectionInfo *conns, int count, ConnectionStats *stats) {
    memset(stats, 0, sizeof(ConnectionStats));
    stats->total = count;
    
    // 用于统计进程名分布
    struct ProcNode {
        char name[256];
        int count;
        struct ProcNode *next;
    } *head = NULL;

    for (int i = 0; i < count; i++) {
        if (conns[i].status_enum == CONN_STATUS_ESTABLISHED) stats->established++;
        if (conns[i].status_enum == CONN_STATUS_LISTEN) stats->listening++;
        if (is_suspicious(&conns[i])) stats->suspicious++;

        // 统计进程活跃度（仅对活跃连接进行统计）
        if (conns[i].status_enum == CONN_STATUS_ESTABLISHED && strcmp(conns[i].process, "N/A") != 0) {
            struct ProcNode *curr = head;
            while (curr) {
                if (strcmp(curr->name, conns[i].process) == 0) {
                    curr->count++;
                    break;
                }
                curr = curr->next;
            }
            if (!curr) {
                struct ProcNode *new_node = malloc(sizeof(struct ProcNode));
                strcpy(new_node->name, conns[i].process);
                new_node->count = 1;
                new_node->next = head;
                head = new_node;
            }
        }
    }

    // 寻找最活跃进程
    struct ProcNode *curr = head;
    while (curr) {
        if (curr->count > stats->top_process_count) {
            stats->top_process_count = curr->count;
            strcpy(stats->top_process, curr->name);
        }
        struct ProcNode *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    if (stats->top_process_count == 0) strcpy(stats->top_process, "-");
}

// 排序比较函数
static int cmp_pid(const void *a, const void *b) {
    return ((ConnectionInfo*)a)->pid - ((ConnectionInfo*)b)->pid;
}

static int cmp_process(const void *a, const void *b) {
    return strcmp(((ConnectionInfo*)a)->process, ((ConnectionInfo*)b)->process);
}

static int cmp_remote(const void *a, const void *b) {
    return strcmp(((ConnectionInfo*)a)->remote_addr, ((ConnectionInfo*)b)->remote_addr);
}

void sort_connections(ConnectionInfo *conns, int count, SortMode mode) {
    if (mode == SORT_NONE || count <= 1) return;
    
    int (*cmp)(const void*, const void*) = NULL;
    switch (mode) {
        case SORT_BY_PID:     cmp = cmp_pid; break;
        case SORT_BY_PROCESS: cmp = cmp_process; break;
        case SORT_BY_REMOTE:  cmp = cmp_remote; break;
        default: return;
    }
    
    if (cmp) qsort(conns, count, sizeof(ConnectionInfo), cmp);
}
