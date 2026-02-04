#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#endif

#include "backend/scanner.h"

#ifdef _WIN32

// 获取进程名的辅助函数
static void get_win_process_name(DWORD pid, char *process_name) {
    strcpy(process_name, "N/A");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameA(hProcess, hMod, process_name, 256);
        }
        CloseHandle(hProcess);
    }
}

// 转换地址为字符串
static void win_addr_to_str(DWORD addr, WORD port, char *out) {
    struct in_addr ip;
    ip.s_addr = addr;
    sprintf(out, "%s:%d", inet_ntoa(ip), ntohs(port));
}

// TCP 状态映射（返回枚举）
static ConnectionStatus win_tcp_status_enum(DWORD st) {
    switch (st) {
        case MIB_TCP_STATE_CLOSED: return CONN_STATUS_CLOSE;
        case MIB_TCP_STATE_LISTEN: return CONN_STATUS_LISTEN;
        case MIB_TCP_STATE_SYN_SENT: return CONN_STATUS_SYN_SENT;
        case MIB_TCP_STATE_SYN_RCVD: return CONN_STATUS_SYN_RECV;
        case MIB_TCP_STATE_ESTAB: return CONN_STATUS_ESTABLISHED;
        case MIB_TCP_STATE_FIN_WAIT1: return CONN_STATUS_FIN_WAIT1;
        case MIB_TCP_STATE_FIN_WAIT2: return CONN_STATUS_FIN_WAIT2;
        case MIB_TCP_STATE_CLOSE_WAIT: return CONN_STATUS_CLOSE_WAIT;
        case MIB_TCP_STATE_CLOSING: return CONN_STATUS_CLOSING;
        case MIB_TCP_STATE_LAST_ACK: return CONN_STATUS_LAST_ACK;
        case MIB_TCP_STATE_TIME_WAIT: return CONN_STATUS_TIME_WAIT;
        default: return CONN_STATUS_UNKNOWN;
    }
}

// 状态枚举转字符串
static const char* status_enum_to_str(ConnectionStatus status) {
    switch (status) {
        case CONN_STATUS_CLOSE: return "CLOSE";
        case CONN_STATUS_LISTEN: return "LISTEN";
        case CONN_STATUS_SYN_SENT: return "SYN_SENT";
        case CONN_STATUS_SYN_RECV: return "SYN_RECV";
        case CONN_STATUS_ESTABLISHED: return "ESTABLISHED";
        case CONN_STATUS_FIN_WAIT1: return "FIN_WAIT1";
        case CONN_STATUS_FIN_WAIT2: return "FIN_WAIT2";
        case CONN_STATUS_CLOSE_WAIT: return "CLOSE_WAIT";
        case CONN_STATUS_CLOSING: return "CLOSING";
        case CONN_STATUS_LAST_ACK: return "LAST_ACK";
        case CONN_STATUS_TIME_WAIT: return "TIME_WAIT";
        case CONN_STATUS_NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

ConnectionInfo* scanner_get_connections(int *count) {
    int capacity = 256;
    int n = 0;
    ConnectionInfo *conns = malloc(sizeof(ConnectionInfo) * capacity);
    if (!conns) return NULL;

    // --- 获取 TCP 表 ---
    ULONG size = 0;
    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (GetExtendedTcpTable(pTcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (n >= capacity) {
                capacity *= 2;
                // 修复内存泄漏：使用临时指针检查 realloc 结果
                ConnectionInfo *temp = realloc(conns, sizeof(ConnectionInfo) * capacity);
                if (!temp) {
                    free(pTcpTable);
                    free(conns);
                    *count = 0;
                    return NULL; // 内存分配失败
                }
                conns = temp;
            }
            ConnectionInfo *c = &conns[n++];
            strcpy(c->protocol, "TCP");
            win_addr_to_str(pTcpTable->table[i].dwLocalAddr, (WORD)pTcpTable->table[i].dwLocalPort, c->local_addr);
            win_addr_to_str(pTcpTable->table[i].dwRemoteAddr, (WORD)pTcpTable->table[i].dwRemotePort, c->remote_addr);
            // 设置状态枚举和字符串
            c->status_enum = win_tcp_status_enum(pTcpTable->table[i].dwState);
            strcpy(c->status, status_enum_to_str(c->status_enum));
            c->pid = pTcpTable->table[i].dwOwningPid;
            get_win_process_name(c->pid, c->process);
        }
    }
    free(pTcpTable);

    // --- 获取 UDP 表 ---
    size = 0;
    GetExtendedUdpTable(NULL, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    PMIB_UDPTABLE_OWNER_PID pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (GetExtendedUdpTable(pUdpTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
            if (n >= capacity) {
                capacity *= 2;
                // 修复内存泄漏：使用临时指针检查 realloc 结果
                ConnectionInfo *temp = realloc(conns, sizeof(ConnectionInfo) * capacity);
                if (!temp) {
                    free(pUdpTable);
                    free(conns);
                    *count = 0;
                    return NULL; // 内存分配失败
                }
                conns = temp;
            }
            ConnectionInfo *c = &conns[n++];
            strcpy(c->protocol, "UDP");
            win_addr_to_str(pUdpTable->table[i].dwLocalAddr, (WORD)pUdpTable->table[i].dwLocalPort, c->local_addr);
            strcpy(c->remote_addr, "0.0.0.0:0");
            // UDP 无状态
            c->status_enum = CONN_STATUS_NONE;
            strcpy(c->status, "NONE");
            c->pid = pUdpTable->table[i].dwOwningPid;
            get_win_process_name(c->pid, c->process);
        }
    }
    free(pUdpTable);

    *count = n;
    return conns;
}

void scanner_free_connections(ConnectionInfo *conns, int count) {
    (void)count; // 明确标记未使用参数
    if (conns) free(conns);
}

#else
// 非 Windows 下的占位
ConnectionInfo* scanner_get_connections(int *count) {
    *count = 0;
    return NULL;
}
void scanner_free_connections(ConnectionInfo *conns, int count) {
    (void)conns; (void)count;
}
#endif
