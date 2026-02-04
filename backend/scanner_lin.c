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

// 状态映射
static const char* get_status_str(const char *proto, int st) {
    if (strcmp(proto, "UDP") == 0) return "NONE";
    switch (st) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default: return "UNKNOWN";
    }
}

// 获取进程名
static void get_process_name(unsigned long target_inode, int32_t *pid, char *process) {
    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        char fd_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        int found = 0;
        while ((fd_entry = readdir(fd_dir))) {
            char link_path[512], target[512];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len != -1) {
                target[len] = '\0';
                unsigned long inode;
                if (sscanf(target, "socket:[%lu]", &inode) == 1) {
                    if (inode == target_inode) {
                        *pid = atoi(entry->d_name);
                        char comm_path[256];
                        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                        FILE *comm_fp = fopen(comm_path, "r");
                        if (comm_fp) {
                            if (fgets(process, 256, comm_fp)) {
                                size_t l = strlen(process);
                                if (l > 0 && process[l-1] == '\n') process[l-1] = '\0';
                            }
                            fclose(comm_fp);
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
    fgets(line, sizeof(line), fp); // 跳过标题行

    while (fgets(line, sizeof(line), fp)) {
        if (*count >= *capacity) {
            *capacity *= 2;
            *conns = realloc(*conns, sizeof(ConnectionInfo) * (*capacity));
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
            strncpy(c->status, get_status_str(proto, st), sizeof(c->status));
            
            c->pid = -1;
            strcpy(c->process, "N/A");
            get_process_name(inode, &c->pid, c->process);
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
    if (conns) free(conns);
}
