#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <fcntl.h>
#endif

#include "backend/scanner.h"

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

LangType current_lang = LANG_CN;
ViewType current_view = VIEW_OVERVIEW;

// 国际化文本结构
struct {
    const char *title;
    const char *ctrl_hint;
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
        ui_text.title = "NCM 网络连接监测器 v2.0 (原生C版)";
        ui_text.ctrl_hint = "按 Q 退出 | 按 L 切换 English";
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
        ui_text.title = "NCM - Network Monitor v2.0 (C Native)";
        ui_text.ctrl_hint = "Press Q:Exit | L:切换中文";
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
    char ch;
    if (read(STDIN_FILENO, &ch, 1) > 0) return ch;
    return -1;
}
#else
void set_non_blocking_input(int enable) { (void)enable; }
int get_key() {
    if (_kbhit()) return _getch();
    return -1;
}
#endif

// 清屏
void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
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

void draw_stats_board(ConnectionStats *stats) {
    // 盒式布局：┌ + 16个─ + ┐ (总宽18)
    printf(CL_BLD "┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐\n");
    
    // 内容行：│ + 16位对齐内容 + │
    printf("│" CL_CYN); print_padded(ui_text.board_total, 16); printf(CLR_RST "│ │" CL_GRN); print_padded(ui_text.board_est, 16); printf(CLR_RST "│ │" CL_YLW); print_padded(ui_text.board_listen, 16); printf(CLR_RST "│ │" CL_RED); print_padded(ui_text.board_suspicious, 16); printf(CLR_RST "│\n");
    
    // 数据行：同样 16 位宽度
    printf("│" CL_BLD "%-16d" CLR_RST "│ │" CL_BLD "%-16d" CLR_RST "│ │" CL_BLD "%-16d" CLR_RST "│ │" CL_BLD "%-16d" CLR_RST "│\n", 
           stats->total, stats->established, stats->listening, stats->suspicious);
           
    printf("└────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘\n");
    printf(CL_BLD " %s: " CLR_RST CL_MAG "%s" CLR_RST " (%d %s)\n", 
           ui_text.top_proc_label, stats->top_process, stats->top_process_count, 
           (current_lang == LANG_CN ? "连接" : "conns"));
    printf("────────────────────────────────────────────────────────────────────────────────────\n");
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

int main() {
    set_non_blocking_input(1);
    
    while (1) {
        update_ui_text();
        int count = 0;
        ConnectionInfo *conns = scanner_get_connections(&count);
        ConnectionStats stats;
        calculate_stats(conns, count, &stats);

        clear_screen();
        printf(CL_BLD CL_GRN " %s " CLR_RST "  [%s]\n\n", ui_text.title, ui_text.ctrl_hint);
        
        draw_stats_board(&stats);
        draw_sidebar();
        printf("\n");

        // 列表渲染逻辑
        printf(CL_BLD);
        print_padded(ui_text.col_proto, 8);
        print_padded(ui_text.col_local, 24);
        print_padded(ui_text.col_remote, 24);
        print_padded(ui_text.col_status, 14);
        print_padded(ui_text.col_proc, 12);
        printf(CLR_RST "\n");
        printf(" ───────────────────────────────────────────────────────────────────────────────────\n");

        int rendered = 0;
        for (int i = 0; i < count; i++) {
            int should_render = 0;
            switch (current_view) {
                case VIEW_OVERVIEW: if (strcmp(conns[i].status, "ESTABLISHED") == 0 && rendered < 12) should_render = 1; break;
                case VIEW_ALL: should_render = 1; break;
                case VIEW_ESTABLISHED: if (strcmp(conns[i].status, "ESTABLISHED") == 0) should_render = 1; break;
                case VIEW_LISTEN: if (strcmp(conns[i].status, "LISTEN") == 0) should_render = 1; break;
                case VIEW_SUSPICIOUS: if (is_suspicious(&conns[i])) should_render = 1; break;
            }

            if (should_render) {
                const char *st_clr = CLR_RST;
                if (strcmp(conns[i].status, "ESTABLISHED") == 0) st_clr = CL_GRN;
                else if (strcmp(conns[i].status, "LISTEN") == 0) st_clr = CL_CYN;
                else if (strcmp(conns[i].status, "TIME_WAIT") == 0) st_clr = CL_YLW;
                if (is_suspicious(&conns[i])) st_clr = BG_RED;

                print_padded(conns[i].protocol, 8);
                print_padded(conns[i].local_addr, 24);
                print_padded(conns[i].remote_addr, 24);
                printf("%s", st_clr);
                print_padded(trans_status(conns[i].status), 14);
                printf(CLR_RST);
                print_padded(conns[i].process, 12);
                printf("\n");
                rendered++;
            }
        }

        if (rendered == 0) printf("\n   (%s)\n", ui_text.no_data);
        
        scanner_free_connections(conns, count);
        fflush(stdout);

        for (int i = 0; i < 20; i++) {
            int key = get_key();
            if (key == 'q' || key == 'Q') {
                set_non_blocking_input(0);
                printf("\nExiting...\n");
                return 0;
            }
            if (key == 'l' || key == 'L') {
                current_lang = (current_lang == LANG_CN) ? LANG_EN : LANG_CN;
                break;
            }
            if (key >= '1' && key <= '5') {
                current_view = (ViewType)(key - '0');
                break;
            }
            usleep(100000);
        }
    }

    set_non_blocking_input(0);
    return 0;
}
