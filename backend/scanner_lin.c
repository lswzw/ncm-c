#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include "backend/scanner.h"

// 将十六进制字符串转为 IP 地址字符串
static void hex_to_ip(const char *hex, char *ip) {
    unsigned int a, b, c, d, port;
    if (sscanf(hex, "%02X%02X%02X%02X:%04X", &d, &c, &b, &a, &port) == 5) {
        sprintf(ip, "%u.%u.%u.%u:%u", a, b, c, d, port);
    } else {
        strcpy(ip, "0.0.0.0:0");
    }
}

// 状态映射（返回枚举）
static ConnectionStatus get_status_enum(const char *proto, int st) {
    if (strcmp(proto, "UDP") == 0) return CONN_STATUS_NONE;
    switch (st) {
        case 0x01: return CONN_STATUS_ESTABLISHED;
        case 0x02: return CONN_STATUS_SYN_SENT;
        case 0x03: return CONN_STATUS_SYN_RECV;
        case 0x04: return CONN_STATUS_FIN_WAIT1;
        case 0x05: return CONN_STATUS_FIN_WAIT2;
        case 0x06: return CONN_STATUS_TIME_WAIT;
        case 0x07: return CONN_STATUS_CLOSE;
        case 0x08: return CONN_STATUS_CLOSE_WAIT;
        case 0x09: return CONN_STATUS_LAST_ACK;
        case 0x0A: return CONN_STATUS_LISTEN;
        case 0x0B: return CONN_STATUS_CLOSING;
        default: return CONN_STATUS_UNKNOWN;
    }
}

// 状态枚举转字符串
static const char* status_enum_to_str(ConnectionStatus status) {
    switch (status) {
        case CONN_STATUS_ESTABLISHED: return "ESTABLISHED";
        case CONN_STATUS_SYN_SENT: return "SYN_SENT";
        case CONN_STATUS_SYN_RECV: return "SYN_RECV";
        case CONN_STATUS_FIN_WAIT1: return "FIN_WAIT1";
        case CONN_STATUS_FIN_WAIT2: return "FIN_WAIT2";
        case CONN_STATUS_TIME_WAIT: return "TIME_WAIT";
        case CONN_STATUS_CLOSE: return "CLOSE";
        case CONN_STATUS_CLOSE_WAIT: return "CLOSE_WAIT";
        case CONN_STATUS_LAST_ACK: return "LAST_ACK";
        case CONN_STATUS_LISTEN: return "LISTEN";
        case CONN_STATUS_CLOSING: return "CLOSING";
        case CONN_STATUS_NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

// 获取进程名和执行路径
static void get_process_name(unsigned long target_inode, int32_t *pid, char *process, char *exe_path) {
    if (exe_path) strcpy(exe_path, "N/A");
    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        // 使用更大的缓冲区避免截断警告
        char fd_path[512];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        int found = 0;
        while ((fd_entry = readdir(fd_dir))) {
            // 使用更大的缓冲区避免截断警告
            char link_path[1024], target[1024];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len != -1) {
                target[len] = '\0';
                unsigned long inode;
                if (sscanf(target, "socket:[%lu]", &inode) == 1) {
                    if (inode == target_inode) {
                        *pid = atoi(entry->d_name);
                        char comm_path[512];
                        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                        FILE *comm_fp = fopen(comm_path, "r");
                        if (comm_fp) {
                            // 使用结构体定义的大小，避免硬编码
                            char temp_buf[256];
                                // 安全复制到目标缓冲区
                                if (fgets(temp_buf, sizeof(temp_buf), comm_fp)) {
                                    size_t l = strlen(temp_buf);
                                    if (l > 0 && temp_buf[l-1] == '\n') temp_buf[l-1] = '\0';
                                    strncpy(process, temp_buf, 255);
                                    process[255] = '\0';
                                }
                            fclose(comm_fp);
                        }
                        
                        // [NEW] 获取进程执行路径
                        char exe_link[512];
                        snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", entry->d_name);
                        ssize_t exe_len = readlink(exe_link, exe_path, 511);
                        if (exe_len != -1) {
                            exe_path[exe_len] = '\0';
                        } else {
                            strcpy(exe_path, "Access Denied");
                        }
                        
                        found = 1;
                        break;
                    }
                }
            }
        }
        closedir(fd_dir);
        if (found) break;
    }
    closedir(dir);
}

static int parse_proc_file(const char *filename, const char *proto, ConnectionInfo **conns, int *count, int *capacity) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;

    char line[256];
    // 检查 fgets 返回值以消除警告
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (*count >= *capacity) {
            *capacity *= 2;
            // 修复内存泄漏：使用临时指针检查 realloc 结果
            ConnectionInfo *temp = realloc(*conns, sizeof(ConnectionInfo) * (*capacity));
            if (!temp) {
                fclose(fp);
                return 0; // 内存分配失败
            }
            *conns = temp;
        }

        char local_addr_hex[64], remote_addr_hex[64];
        int st;
        unsigned long inode;

        if (sscanf(line, "%*d: %63s %63s %X %*X:%*X %*X:%*X %*X %*d %*d %lu",
                   local_addr_hex, remote_addr_hex, &st, &inode) == 4) {
            
            ConnectionInfo *c = &((*conns)[*count]);
            strncpy(c->protocol, proto, sizeof(c->protocol));
            hex_to_ip(local_addr_hex, c->local_addr);
            hex_to_ip(remote_addr_hex, c->remote_addr);
            
            // 设置状态枚举和字符串
            c->status_enum = get_status_enum(proto, st);
            strncpy(c->status, status_enum_to_str(c->status_enum), sizeof(c->status));
            
            c->pid = -1;
            strcpy(c->process, "N/A");
            strcpy(c->exe_path, "N/A");
            strcpy(c->risk_reason, "");
            get_process_name(inode, &c->pid, c->process, c->exe_path);
            (*count)++;
        }
    }

    fclose(fp);
    return 1;
}

ConnectionInfo* scanner_get_connections(int *count) {
    int capacity = 128;
    int n = 0;
    ConnectionInfo *conns = malloc(sizeof(ConnectionInfo) * capacity);
    if (!conns) return NULL;

    parse_proc_file("/proc/net/tcp", "TCP", &conns, &n, &capacity);
    parse_proc_file("/proc/net/udp", "UDP", &conns, &n, &capacity);

    *count = n;
    return conns;
}

void scanner_free_connections(ConnectionInfo *conns, int count) {
    (void)count; // 明确标记未使用参数
    if (conns) free(conns);
}
