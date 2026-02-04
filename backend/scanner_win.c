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

// TCP 状态映射
static const char* win_tcp_status(DWORD st) {
    switch (st) {
        case MIB_TCP_STATE_CLOSED: return "CLOSE";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RECV";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE";
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
                conns = realloc(conns, sizeof(ConnectionInfo) * capacity);
            }
            ConnectionInfo *c = &conns[n++];
            strcpy(c->protocol, "TCP");
            win_addr_to_str(pTcpTable->table[i].dwLocalAddr, (WORD)pTcpTable->table[i].dwLocalPort, c->local_addr);
            win_addr_to_str(pTcpTable->table[i].dwRemoteAddr, (WORD)pTcpTable->table[i].dwRemotePort, c->remote_addr);
            strcpy(c->status, win_tcp_status(pTcpTable->table[i].dwState));
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
                conns = realloc(conns, sizeof(ConnectionInfo) * capacity);
            }
            ConnectionInfo *c = &conns[n++];
            strcpy(c->protocol, "UDP");
            win_addr_to_str(pUdpTable->table[i].dwLocalAddr, (WORD)pUdpTable->table[i].dwLocalPort, c->local_addr);
            strcpy(c->remote_addr, "0.0.0.0:0");
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
