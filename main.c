#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#endif

#include "backend/scanner.h"
#include "backend/kernel_probe.h"
#include "backend/nl_listener.h"

// 配置常量
#define MAX_OVERVIEW_DISPLAY 12      // 总览最多显示的连接数
#define REFRESH_POLL_ITERATIONS 20   // 刷新轮询次数
#define POLL_INTERVAL_US 100000      // 轮询间隔（微秒），默认0.1秒


// 颜色定义
#define CLR_RST  "\033[0m"
#define CL_BLD   "\033[1m"
#define CL_GRN   "\033[32m"
#define CL_YLW   "\033[33m"
#define CL_CYN   "\033[36m"
#define CL_MAG   "\033[35m"
#define CL_RED   "\033[31m"
#define BG_RED   "\033[41;37m"

// 语言与视图状态
typedef enum { LANG_CN, LANG_EN } LangType;
typedef enum { VIEW_OVERVIEW = 1, VIEW_ALL, VIEW_ESTABLISHED, VIEW_LISTEN, VIEW_SUSPICIOUS } ViewType;
// 全局配置与状态
LangType current_lang = LANG_CN;
ViewType current_view = VIEW_OVERVIEW;
int scroll_offset = 0;
char search_filter[64] = "";
int is_searching = 0;
SortMode current_sort = SORT_NONE;
int selected_idx = 0; // 当前选中的列表行索引
int show_detail = 0;  // 是否显示详情浮窗
int kill_confirm = 0; // 是否处于终止确认状态

// 驱动状态
DriverTier current_tier = DRIVER_POLLING;
int nl_fd = -1;

// 国际化文本结构
struct {
    const char *title;
    const char *ctrl_hint;
    const char *scroll_hint;
    const char *search_hint;
    const char *sort_hint;
    const char *driver_label;
    const char *search_label;
    const char *sort_label;
    const char *board_total;
    const char *board_est;
    const char *board_listen;
    const char *board_suspicious;
    const char *top_proc_label;
    const char *view_ov;
    const char *view_all;
    const char *view_conn;
    const char *view_list;
    const char *view_susp;
    const char *col_proto;
    const char *col_local;
    const char *col_remote;
    const char *col_status;
    const char *col_proc;
    const char *no_data;
} ui_text;

void update_ui_text() {
    if (current_lang == LANG_CN) {
        ui_text.title = "NCM 网络连接监测器 v2.0";
        ui_text.ctrl_hint = "按 Q 退出 | L 切换 English | 1-5 切换视图";
        ui_text.scroll_hint = "J/K/↑/↓ 滚动";
        ui_text.search_hint = "/ 搜索";
        ui_text.sort_hint = "S 排序";
        ui_text.driver_label = "驱动级别";
        ui_text.search_label = "搜索关键词";
        ui_text.sort_label = "排序模式";
        ui_text.board_total = "总连接数";
        ui_text.board_est = "正在通信";
        ui_text.board_listen = "监听中";
        ui_text.board_suspicious = "可疑连接";
        ui_text.top_proc_label = "最活跃进程";
        ui_text.view_ov = "1.总览";
        ui_text.view_all = "2.全量";
        ui_text.view_conn = "3.通信中";
        ui_text.view_list = "4.监听中";
        ui_text.view_susp = "5.可疑连接";
        ui_text.col_proto = "协议";
        ui_text.col_local = "本地地址";
        ui_text.col_remote = "远端地址";
        ui_text.col_status = "状态";
        ui_text.col_proc = "进程";
        ui_text.no_data = "暂无匹配数据";
    } else {
        ui_text.title = "NCM - Network Monitor v2.0";
        ui_text.ctrl_hint = "Q:Exit | L:Language | 1-5:Switch View";
        ui_text.scroll_hint = "J/K/↑/↓:Scroll";
        ui_text.search_hint = "/:Search";
        ui_text.sort_hint = "S:Sort";
        ui_text.driver_label = "DRIVER";
        ui_text.search_label = "Filter";
        ui_text.sort_label = "Sort";
        ui_text.board_total = "TOTAL CONNS";
        ui_text.board_est = "ESTABLISHED";
        ui_text.board_listen = "LISTENING";
        ui_text.board_suspicious = "SUSPICIOUS";
        ui_text.top_proc_label = "Top Process";
        ui_text.view_ov = "1.Overview";
        ui_text.view_all = "2.All";
        ui_text.view_conn = "3.Comm";
        ui_text.view_list = "4.Listen";
        ui_text.view_susp = "5.Suspicious";
        ui_text.col_proto = "PROTO";
        ui_text.col_local = "LOCAL ADDR";
        ui_text.col_remote = "REMOTE ADDR";
        ui_text.col_status = "STATUS";
        ui_text.col_proc = "PROCESS";
        ui_text.no_data = "No matching data";
    }
}

// 状态翻译
const char* trans_status(const char* st) {
    if (current_lang == LANG_EN) return st;
    if (strcmp(st, "ESTABLISHED") == 0) return "已连接";
    if (strcmp(st, "LISTEN") == 0) return "监听中";
    if (strcmp(st, "TIME_WAIT") == 0) return "等待关闭";
    if (strcmp(st, "CLOSE_WAIT") == 0) return "等待关闭";
    if (strcmp(st, "NONE") == 0) return "无状态";
    return st;
}

// 非阻塞输入处理 (跨平台)
// 特殊按键定义
#define KEY_UP    1001
#define KEY_DOWN  1002

#ifndef _WIN32
void set_non_blocking_input(int enable) {
    static struct termios oldt, newt;
    if (enable) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    } else {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
}
int get_key() {
    unsigned char ch;
    if (read(STDIN_FILENO, &ch, 1) <= 0) return -1;
    
    // 处理方向键 (ANSI 转义序列: ESC [ A / ESC [ B)
    if (ch == 27) {
        // 设置极短的阻塞等待后续序列，防止序列断裂
        unsigned char seq[2];
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK); // 临时切回阻塞
        
        struct timeval tv = {0, 50000}; // 50ms 超时
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        
        if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
            if (read(STDIN_FILENO, &seq[0], 1) > 0 && seq[0] == '[') {
                if (read(STDIN_FILENO, &seq[1], 1) > 0) {
                    fcntl(STDIN_FILENO, F_SETFL, flags); // 恢复原状态
                    if (seq[1] == 'A') return KEY_UP;
                    if (seq[1] == 'B') return KEY_DOWN;
                }
            }
        }
        fcntl(STDIN_FILENO, F_SETFL, flags); // 恢复原状态
        return 27;
    }
    return (int)ch;
}
#else
void set_non_blocking_input(int enable) { (void)enable; }
int get_key() {
    if (_kbhit()) {
        int ch = _getch();
        if (ch == 0 || ch == 224) { // 方向键扩展码
            ch = _getch();
            if (ch == 72) return KEY_UP;
            if (ch == 80) return KEY_DOWN;
        }
        return ch;
    }
    return -1;
}
#endif

// 清屏
void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    // 恢复全屏清除模式以消除视图切换时的样式错乱和残影
    printf("\033[2J\033[H");
#endif
}

// 宽度感知打印 (处理 UTF-8 中文双倍宽度)
void print_padded(const char* s, int target_width) {
    int visual_width = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        if (*p < 128) { visual_width += 1; p += 1; }
        else if (*p < 224) { visual_width += 1; p += 2; }
        else if (*p < 240) { visual_width += 2; p += 3; } // 中文通常是 3 字节，2 列宽
        else { visual_width += 2; p += 4; }
    }
    printf("%s", s);
    for (int i = 0; i < target_width - visual_width; i++) printf(" ");
}

// 绘制单个统计盒子（封装以减少代码重复）
void draw_stat_box(const char *label, int value, const char *color) {
    printf("%s", color);
    print_padded(label, 16);
    printf(CLR_RST);
}

void draw_stats_board(ConnectionStats *stats) {
    // 盒式布局：┌ + 16个─ + ┐ (总宽18)
    printf(CL_BLD "┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐\n");
    
    // 内容行：│ + 16位对齐内容 + │
    printf("│" CL_CYN); print_padded(ui_text.board_total, 16); printf(CLR_RST "│ │" CL_GRN); print_padded(ui_text.board_est, 16); printf(CLR_RST "│ │" CL_YLW); print_padded(ui_text.board_listen, 16); printf(CLR_RST "│ │" CL_RED); print_padded(ui_text.board_suspicious, 16); printf(CLR_RST "│\n");
    
    // 数据行：同样 16 位宽度
    printf("│" CL_BLD "%-16d" CLR_RST "│ │" CL_BLD "%-16d" CLR_RST "│ │" CL_BLD "%-16d" CLR_RST "│ │" CL_BLD "%-16d" CLR_RST "│\n", 
           stats->total, stats->established, stats->listening, stats->suspicious);
           
    printf("└────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘\n");
    printf(CL_BLD " %s: " CLR_RST CL_MAG "%s" CLR_RST " (%d %s) | " CL_CYN "%s" CLR_RST " | " CL_YLW "%s" CLR_RST " | " CL_GRN "%s" CLR_RST "\n", 
           ui_text.top_proc_label, stats->top_process, stats->top_process_count, 
           (current_lang == LANG_CN ? "连接" : "conns"), ui_text.scroll_hint, ui_text.search_hint, ui_text.sort_hint);
    
    // 显示搜索和排序状态
    if (is_searching || strlen(search_filter) > 0 || current_sort != SORT_NONE) {
        printf(CL_CYN " %s: " CLR_RST CL_BLD "[ %s ]" CLR_RST " %s", 
               ui_text.search_label, search_filter, (is_searching ? "_" : ""));
        
        if (current_sort != SORT_NONE) {
            const char *sort_name = "NONE";
            if (current_lang == LANG_CN) {
                if (current_sort == SORT_BY_PID) sort_name = "PID";
                else if (current_sort == SORT_BY_PROCESS) sort_name = "进程名";
                else if (current_sort == SORT_BY_REMOTE) sort_name = "远端地址";
            } else {
                if (current_sort == SORT_BY_PID) sort_name = "PID";
                else if (current_sort == SORT_BY_PROCESS) sort_name = "Process";
                else if (current_sort == SORT_BY_REMOTE) sort_name = "Remote";
            }
            printf(" | " CL_YLW "%s: " CLR_RST CL_BLD "%s" CLR_RST, ui_text.sort_label, sort_name);
        }
        printf("\n");
    }
    printf("────────────────────────────────────────────────────────────────────────────────────\n");
}

// 聚合历史缓存 (60个点)
#define TREND_HISTORY_SIZE 60
int total_conn_history[TREND_HISTORY_SIZE];
int history_idx = 0;

// 全量快照缓存 (5轮)
#define BEHAVIOR_SNAPSHOTS 5
typedef struct {
    ConnectionInfo *conns;
    int count;
} HistorySnapshot;

HistorySnapshot history_snapshots[BEHAVIOR_SNAPSHOTS];
int snapshot_idx = 0;

void push_history(int total) {
    total_conn_history[history_idx] = total;
    history_idx = (history_idx + 1) % TREND_HISTORY_SIZE;
}

// 绘制趋势字符图
void draw_sparkline() {
    const char* bars[] = {" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    int max = 1;
    for (int i=0; i<TREND_HISTORY_SIZE; i++) if(total_conn_history[i] > max) max = total_conn_history[i];
    
    printf(CL_CYN " TREND: " CLR_RST);
    for (int i=0; i<TREND_HISTORY_SIZE; i++) {
        int idx = (history_idx + i) % TREND_HISTORY_SIZE;
        int bar_idx = (total_conn_history[idx] * 7) / max;
        printf("%s", bars[bar_idx]);
    }
    printf("\n");
}

// 显示详情浮窗
void show_detail_overlay(ConnectionInfo *conn) {
    printf("\033[2J\033[H"); // 全屏清除，进入详情
    printf("\n\n" CL_BLD "  ┌────────────────────────────────────────────────────────────┐\n");
    
    // 标题行
    printf("  │ " CL_MAG); print_padded("PROCESS DETAILS", 58); printf(CLR_RST " │\n");
    printf("  ├────────────────────────────────────────────────────────────┤\n");
    
    char buf[64];
    // PID
    snprintf(buf, sizeof(buf), "%d", conn->pid);
    printf("  │ " CL_CYN); print_padded("PID:       ", 11); printf(CLR_RST); print_padded(buf, 47); printf(" │\n");
    
    // COMM
    printf("  │ " CL_CYN); print_padded("COMM:      ", 11); printf(CLR_RST); print_padded(conn->process, 47); printf(" │\n");
    
    // PROTO/ST
    printf("  │ " CL_CYN); print_padded("PROTO/ST:  ", 11); printf(CLR_RST); print_padded(conn->status, 47); printf(" │\n");
    
    // LOCAL
    printf("  │ " CL_CYN); print_padded("LOCAL:     ", 11); printf(CLR_RST); print_padded(conn->local_addr, 47); printf(" │\n");
    
    // REMOTE
    printf("  │ " CL_CYN); print_padded("REMOTE:    ", 11); printf(CLR_RST); print_padded(conn->remote_addr, 47); printf(" │\n");
    
    // EXE PATH (处理换行)
    printf("  │ " CL_CYN); print_padded("EXE PATH:  ", 11); printf(CLR_RST); 
    if (strlen(conn->exe_path) <= 47) {
        print_padded(conn->exe_path, 47); printf(" │\n");
    } else {
        char path_part[48];
        strncpy(path_part, conn->exe_path, 47); path_part[47] = '\0';
        print_padded(path_part, 47); printf(" │\n");
        printf("  │            "); print_padded(conn->exe_path + 47, 47); printf(" │\n");
    }
    
    // RISK
    printf("  │ " CL_RED); print_padded("RISK:      ", 11); printf(CLR_RST); 
    print_padded(strlen(conn->risk_reason) ? conn->risk_reason : "Safe", 47); printf(" │\n");
    
    printf("  ├────────────────────────────────────────────────────────────┤\n");
    // 底部提示
    printf("  │ " CL_YLW); print_padded("Press ANY KEY to return", 58); printf(CLR_RST " │\n");
    printf("  └────────────────────────────────────────────────────────────┘\n");
    fflush(stdout);
}

void push_snapshot(ConnectionInfo *conns, int count) {
    // 释放最旧的
    if (history_snapshots[snapshot_idx].conns) {
        free(history_snapshots[snapshot_idx].conns);
    }
    
    // 深度拷贝当前快照
    history_snapshots[snapshot_idx].count = count;
    history_snapshots[snapshot_idx].conns = malloc(sizeof(ConnectionInfo) * count);
    if (history_snapshots[snapshot_idx].conns) {
        memcpy(history_snapshots[snapshot_idx].conns, conns, sizeof(ConnectionInfo) * count);
    }
    
    snapshot_idx = (snapshot_idx + 1) % BEHAVIOR_SNAPSHOTS;
}

// 检查某个进程是否在短时间内发起了大量新连接
int check_frequency_spike(int32_t pid, int current_count) {
    if (pid <= 0) return 0;
    
    int max_prev = 0;
    for (int s = 0; s < BEHAVIOR_SNAPSHOTS; s++) {
        if (!history_snapshots[s].conns) continue;
        int prev_count = 0;
        for (int i = 0; i < history_snapshots[s].count; i++) {
            if (history_snapshots[s].conns[i].pid == pid) prev_count++;
        }
        if (prev_count > max_prev) max_prev = prev_count;
    }
    
    // 如果当前连接数显著多于历史最高值（例如增加超过 5 个），判定为频率异常
    return (current_count > max_prev + 5);
}

void draw_sidebar() {
    printf(CL_BLD " [%s] " CLR_RST, (current_lang == LANG_CN ? "菜单选择" : "VIEW"));
    printf(current_view == VIEW_OVERVIEW ? BG_RED " %s " CLR_RST : " %s ", ui_text.view_ov);
    printf(current_view == VIEW_ALL ? BG_RED " %s " CLR_RST : " %s ", ui_text.view_all);
    printf(current_view == VIEW_ESTABLISHED ? BG_RED " %s " CLR_RST : " %s ", ui_text.view_conn);
    printf(current_view == VIEW_LISTEN ? BG_RED " %s " CLR_RST : " %s ", ui_text.view_list);
    printf(current_view == VIEW_SUSPICIOUS ? BG_RED " %s " CLR_RST : " %s ", ui_text.view_susp);
    printf("\n");
}

int main(int argc, char **argv) {
    #ifdef _WIN32
    // 设置 Windows 控制台为 UTF-8 编码
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    
    // 启用 ANSI 转义序列支持
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
    #endif
    // 1. 驱动选择
    current_tier = probe_kernel_features();
    if (current_tier == DRIVER_NETLINK) nl_fd = nl_init_listener();
    
    // 原有参数处理
    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        printf("NCM - Network Connection Monitor v2.0\n");
        printf("Usage: %s [options]\n", argv[0]);
        printf("Options:\n");
        printf("  -e <file>  Export connection report to HTML\n");
        printf("  -h, --help Show this help message\n");
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "-e") == 0) {
        int count = 0;
        ConnectionInfo *conns = scanner_get_connections(&count);
        if (!conns && count == 0) return 1;
        int result = export_html_report(argv[2], conns, count);
        scanner_free_connections(conns, count);
        return result;
    }
    
    set_non_blocking_input(1);
    memset(history_snapshots, 0, sizeof(history_snapshots));
    
    int needs_data_scan = 1;
    time_t last_scan_time = 0;
    long long last_interaction_time = 0; // 毫秒级交互记录
    ConnectionInfo *conns = NULL;
    int count = 0;
    ConnectionStats stats;

    while (1) {
        update_ui_text();
        
        long long now_ms;
        time_t now_sec;

        #ifdef _WIN32
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        unsigned long long tt = ft.dwHighDateTime;
        tt <<= 32;
        tt |= ft.dwLowDateTime;
        tt /= 10000;
        tt -= 11644473600000ULL;
        now_ms = (long long)tt;
        now_sec = (time_t)(tt / 1000);
        #else
        struct timeval tv_now;
        gettimeofday(&tv_now, NULL);
        now_ms = (long long)tv_now.tv_sec * 1000 + tv_now.tv_usec / 1000;
        now_sec = tv_now.tv_sec;
        #endif

        // 策略：如果用户正在操作（过去 500ms 内有按键），推迟扫描
        // 除非数据已经超过 5 秒没有更新，必须强制刷新
        int user_is_busy = (now_ms - last_interaction_time < 500);
        if (now_sec - last_scan_time >= 5) needs_data_scan = 1; // 强迫症更新
        else if (now_sec - last_scan_time >= 2 && !user_is_busy) needs_data_scan = 1; // 正常定时更新

        if (needs_data_scan) {
            last_scan_time = now_sec;
            if (conns) scanner_free_connections(conns, count); 
            conns = scanner_get_connections(&count);
            if (!conns && count == 0) {
                printf(CL_BLD CL_RED "Error: Connection Scan Failed\n" CLR_RST);
                sleep(1); continue;
            }
            push_history(count);
            calculate_stats(conns, count, &stats);
            for (int i = 0; i < count; i++) {
                is_suspicious(&conns[i]);
                int cur_proc_conns = 0;
                if (conns[i].pid > 0) {
                    for(int j=0; j<count; j++) if(conns[j].pid == conns[i].pid) cur_proc_conns++;
                    if (check_frequency_spike(conns[i].pid, cur_proc_conns)) strcpy(conns[i].risk_reason, "Spike");
                }
            }
            needs_data_scan = 0;
        }

        if (current_sort != SORT_NONE) sort_connections(conns, count, current_sort);

        clear_screen();
        printf(CL_BLD CL_GRN " %s " CLR_RST "  [%s]  " CL_YLW "[%s: %s]" CLR_RST "\n", 
               ui_text.title, ui_text.ctrl_hint, ui_text.driver_label, get_driver_name(current_tier));
        draw_sparkline();
        printf("\n");
        
        draw_stats_board(&stats);
        draw_sidebar();
        printf("\n");

        printf(CL_BLD);
        print_padded(ui_text.col_proto, 6);
        print_padded(ui_text.col_local, 22);
        print_padded(ui_text.col_remote, 22);
        print_padded(ui_text.col_status, 12);
        print_padded(ui_text.col_proc, 12);
        print_padded("RISK", 10);
        printf(CLR_RST "\n");
        printf(" ───────────────────────────────────────────────────────────────────────────────────\n");

        int match_count = 0;
        ConnectionInfo **filtered_conns = malloc(sizeof(ConnectionInfo*) * (count > 0 ? count : 1));
        if (!filtered_conns) {
            scanner_free_connections(conns, count);
            continue; 
        }

        for (int i = 0; i < count; i++) {
            int vm = 0;
            switch (current_view) {
                case VIEW_OVERVIEW: if (conns[i].status_enum == CONN_STATUS_ESTABLISHED && is_external_connection(&conns[i])) vm = 1; break;
                case VIEW_ALL: vm = 1; break;
                case VIEW_ESTABLISHED: if (conns[i].status_enum == CONN_STATUS_ESTABLISHED) vm = 1; break;
                case VIEW_LISTEN: if (conns[i].status_enum == CONN_STATUS_LISTEN) vm = 1; break;
                case VIEW_SUSPICIOUS: if (strlen(conns[i].risk_reason) > 0) vm = 1; break;
            }

            if (vm && strlen(search_filter) > 0) {
                if (strstr(conns[i].process, search_filter) == NULL && 
                    strstr(conns[i].remote_addr, search_filter) == NULL) {
                    vm = 0;
                }
            }
            if (vm) filtered_conns[match_count++] = &conns[i];
        }

        // 滚动与选择自适应
        int display_limit = 15; 
        if (selected_idx >= match_count && match_count > 0) selected_idx = match_count - 1;
        if (selected_idx < 0) selected_idx = 0;
        
        if (selected_idx < scroll_offset) scroll_offset = selected_idx;
        if (selected_idx >= scroll_offset + display_limit) scroll_offset = selected_idx - display_limit + 1;

        int rendered = 0;
        for (int i = scroll_offset; i < match_count && rendered < display_limit; i++) {
            const char *st_clr = CLR_RST;
            if (filtered_conns[i]->status_enum == CONN_STATUS_ESTABLISHED) st_clr = CL_GRN;
            if (strlen(filtered_conns[i]->risk_reason) > 0) st_clr = BG_RED;

            if (i == selected_idx) printf("\033[7m"); 
            
            print_padded(filtered_conns[i]->protocol, 6);
            print_padded(filtered_conns[i]->local_addr, 22);
            print_padded(filtered_conns[i]->remote_addr, 22);
            printf("%s", st_clr);
            print_padded(trans_status(filtered_conns[i]->status), 12);
            printf(CLR_RST);
            if (i == selected_idx) printf("\033[7m");
            print_padded(filtered_conns[i]->process, 12);
            printf(CL_YLW);
            print_padded(filtered_conns[i]->risk_reason, 10);
            printf(CLR_RST "\n");
            rendered++;
        }

        if (rendered == 0) printf("\n   (%s)\n", ui_text.no_data);
        else {
            printf("\n" CL_CYN "   [#%d/%d %s | Enter:%s | K:%s]\n" CLR_RST, 
                   selected_idx + 1, match_count, 
                   (current_lang == LANG_CN ? "已选中" : "Selected"),
                   (current_lang == LANG_CN ? "详情" : "Detail"),
                   (current_lang == LANG_CN ? "终止" : "Kill"));
        }
        
        if (kill_confirm && match_count > 0 && selected_idx < match_count) {
            printf(BG_RED " CONFIRM KILL PID %d (%s)? [y/N]: " CLR_RST, 
                   filtered_conns[selected_idx]->pid, filtered_conns[selected_idx]->process);
            fflush(stdout);
        }
        // 渲染完成后清除屏幕剩余部分，确保长列表切短列表时没有残影
        printf("\033[J");
        fflush(stdout);

        push_snapshot(conns, count);
        // scanner_free_connections(conns, count); // 现在由 data_scan 逻辑控制释放时机
        fflush(stdout);

        // 统一输入与驱动事件轮询 (双引擎驱动 - Select 优化版)
        int force_refresh = 0;
        
        // 降低轮询强度：将外部 20 次循环改为 1 次阻塞等待
        // 这里的 REFRESH_POLL_ITERATIONS 调整为内部逻辑控制
        for (int i = 0; i < REFRESH_POLL_ITERATIONS; i++) {
            int key = -1;
            int has_netlink = 0;

            #ifdef _WIN32
            Sleep(POLL_INTERVAL_US / 1000);
            if (_kbhit()) {
                key = get_key();
            }
            #else
            int max_fd = (nl_fd > STDIN_FILENO) ? nl_fd : STDIN_FILENO;
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);
            if (current_tier == DRIVER_NETLINK && nl_fd != -1) {
                FD_SET(nl_fd, &readfds);
            }

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = POLL_INTERVAL_US; // 0.1s 阻塞/超时

            int activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);
            
            if (activity < 0 && errno != EINTR) break;
            
            if (activity > 0) {
                if (FD_ISSET(STDIN_FILENO, &readfds)) {
                    key = get_key();
                }
                if (current_tier == DRIVER_NETLINK && nl_fd != -1 && FD_ISSET(nl_fd, &readfds)) {
                    has_netlink = 1;
                }
            }
            #endif

            // A. 处理用户输入
            if (key != -1) {
                #ifdef _WIN32
                FILETIME ft_int;
                GetSystemTimeAsFileTime(&ft_int);
                unsigned long long tt_int = ft_int.dwHighDateTime;
                tt_int <<= 32;
                tt_int |= ft_int.dwLowDateTime;
                tt_int /= 10000;
                tt_int -= 11644473600000ULL;
                last_interaction_time = (long long)tt_int;
                #else
                struct timeval tv_int;
                gettimeofday(&tv_int, NULL);
                last_interaction_time = (long long)tv_int.tv_sec * 1000 + tv_int.tv_usec / 1000;
                #endif

                if (kill_confirm) {
                    if (key == 'y' || key == 'Y') {
                        #ifndef _WIN32
                        if (match_count > 0 && selected_idx < match_count) {
                            kill(filtered_conns[selected_idx]->pid, 15);
                        }
                        #endif
                    }
                    kill_confirm = 0; force_refresh = 1;
                } else if (is_searching) {
                    if (key == 10 || key == 13 || key == 27) is_searching = 0;
                    else if (key == 8 || key == 127) { int l = strlen(search_filter); if (l > 0) search_filter[l - 1] = '\0'; }
                    else if (key >= 32 && key <= 126 && strlen(search_filter) < 63) { 
                        int l = strlen(search_filter); search_filter[l] = (char)key; search_filter[l + 1] = '\0'; 
                        selected_idx = 0; scroll_offset = 0;
                    }
                    force_refresh = 1;
                } else {
                    if (key == 'q' || key == 'Q') { set_non_blocking_input(0); printf("\nExiting...\n"); return 0; }
                    if (key == 'l' || key == 'L') { current_lang = (current_lang == LANG_CN) ? LANG_EN : LANG_CN; force_refresh = 1; }
                    if (key == '/') { is_searching = 1; search_filter[0] = '\0'; force_refresh = 1; }
                    if (key == 's' || key == 'S') { current_sort = (SortMode)((current_sort + 1) % 4); force_refresh = 1; }
                    if (key == 'j' || key == 'J' || key == KEY_UP) { if (selected_idx < match_count - 1) { selected_idx++; force_refresh = 1; } }
                    if (key == 'k' || key == 'K' || key == KEY_UP) { if (selected_idx > 0) { selected_idx--; force_refresh = 1; } }
                    if (key == 'K') { if (match_count > 0 && filtered_conns[selected_idx]->pid > 0) { kill_confirm = 1; force_refresh = 1; } }
                    if (key == 10 || key == 13) { 
                        if (match_count > 0) { show_detail_overlay(filtered_conns[selected_idx]); while(get_key() == -1) 
                            #ifdef _WIN32
                            Sleep(50);
                            #else
                            usleep(50000); 
                            #endif
                        }
                        force_refresh = 1;
                    }
                    if (key >= '1' && key <= '5') { current_view = (ViewType)(key - '0'); selected_idx = 0; scroll_offset = 0; force_refresh = 1; }
                }
            }

            // B. 处理内核驱动事件
            if (has_netlink) {
                if (nl_wait_for_event(nl_fd) == 1) {
                    force_refresh = 1; 
                    needs_data_scan = 1; // 有新驱动事件，标记需要重扫数据
                }
            }

            if (force_refresh) break;
        }
        free(filtered_conns);
    }

    set_non_blocking_input(0);
    return 0;
}
