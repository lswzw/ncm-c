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

LangType current_lang = LANG_CN;
ViewType current_view = VIEW_OVERVIEW;
int scroll_offset = 0;
char search_filter[64] = "";
int is_searching = 0;
SortMode current_sort = SORT_NONE;

// 国际化文本结构
struct {
    const char *title;
    const char *ctrl_hint;
    const char *scroll_hint;
    const char *search_hint;
    const char *sort_hint;
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
        ui_text.scroll_hint = "J/K 滚动";
        ui_text.search_hint = "/ 搜索";
        ui_text.sort_hint = "S 排序";
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
        ui_text.scroll_hint = "J/K:Scroll";
        ui_text.search_hint = "/:Search";
        ui_text.sort_hint = "S:Sort";
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
    if (read(STDIN_FILENO, &ch, 1) > 0) return (int)ch;
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
    // 处理命令行参数：ncm -e report.html
    if (argc == 3 && strcmp(argv[1], "-e") == 0) {
        int count = 0;
        ConnectionInfo *conns = scanner_get_connections(&count);
        
        if (!conns && count == 0) {
            fprintf(stderr, "错误：无法扫描网络连接\n");
            return 1;
        }
        
        int result = export_html_report(argv[2], conns, count);
        scanner_free_connections(conns, count);
        return result;
    }
    
    // 原有 TUI 模式
    set_non_blocking_input(1);
    
    int internal_count_cache = 0; // 用于平滑滚动限制
    while (1) {
        update_ui_text();
        int count = 0;
        ConnectionInfo *conns = scanner_get_connections(&count);
        
        if (!conns && count == 0) {
            clear_screen();
            printf(CL_BLD CL_RED "Error: Failed to scan network connections\n" CLR_RST);
            sleep(1);
            continue;
        }
        
        ConnectionStats stats;
        calculate_stats(conns, count, &stats);
        
        // 在计算统计后，渲染显示前进行排序
        if (current_sort != SORT_NONE) {
            sort_connections(conns, count, current_sort);
        }

        clear_screen();
        printf(CL_BLD CL_GRN " %s " CLR_RST "  [%s]\n\n", ui_text.title, ui_text.ctrl_hint);
        
        draw_stats_board(&stats);
        draw_sidebar();
        printf("\n");

        // 列表展示头部
        printf(CL_BLD);
        print_padded(ui_text.col_proto, 8);
        print_padded(ui_text.col_local, 24);
        print_padded(ui_text.col_remote, 24);
        print_padded(ui_text.col_status, 14);
        print_padded(ui_text.col_proc, 12);
        printf(CLR_RST "\n");
        printf(" ───────────────────────────────────────────────────────────────────────────────────\n");

        int match_count = 0;
        // 第一遍扫描：计算当前视图下匹配的总数 (包含搜索词过滤)
        for (int i = 0; i < count; i++) {
            int view_matches = 0;
            switch (current_view) {
                case VIEW_OVERVIEW: if (conns[i].status_enum == CONN_STATUS_ESTABLISHED && is_external_connection(&conns[i])) view_matches = 1; break;
                case VIEW_ALL: view_matches = 1; break;
                case VIEW_ESTABLISHED: if (conns[i].status_enum == CONN_STATUS_ESTABLISHED) view_matches = 1; break;
                case VIEW_LISTEN: if (conns[i].status_enum == CONN_STATUS_LISTEN) view_matches = 1; break;
                case VIEW_SUSPICIOUS: if (is_suspicious(&conns[i])) view_matches = 1; break;
            }

            if (view_matches && strlen(search_filter) > 0) {
                if (strstr(conns[i].process, search_filter) == NULL && 
                    strstr(conns[i].remote_addr, search_filter) == NULL) {
                    view_matches = 0;
                }
            }

            if (view_matches) match_count++;
        }
        internal_count_cache = match_count;

        // 滚动边界检查
        int display_limit = 15; 
        if (scroll_offset < 0) scroll_offset = 0;
        if (match_count > display_limit && scroll_offset > match_count - display_limit) 
            scroll_offset = match_count - display_limit;
        if (match_count <= display_limit) scroll_offset = 0;

        int skip = scroll_offset;
        int rendered = 0;
        // 第二遍扫描：实际渲染指定范围的数据
        for (int i = 0; i < count && rendered < display_limit; i++) {
            int view_matches = 0;
            switch (current_view) {
                case VIEW_OVERVIEW: if (conns[i].status_enum == CONN_STATUS_ESTABLISHED && is_external_connection(&conns[i])) view_matches = 1; break;
                case VIEW_ALL: view_matches = 1; break;
                case VIEW_ESTABLISHED: if (conns[i].status_enum == CONN_STATUS_ESTABLISHED) view_matches = 1; break;
                case VIEW_LISTEN: if (conns[i].status_enum == CONN_STATUS_LISTEN) view_matches = 1; break;
                case VIEW_SUSPICIOUS: if (is_suspicious(&conns[i])) view_matches = 1; break;
            }

            if (view_matches && strlen(search_filter) > 0) {
                if (strstr(conns[i].process, search_filter) == NULL && 
                    strstr(conns[i].remote_addr, search_filter) == NULL) {
                    view_matches = 0;
                }
            }

            if (view_matches) {
                if (skip > 0) { skip--; continue; }
                
                const char *st_clr = CLR_RST;
                if (conns[i].status_enum == CONN_STATUS_ESTABLISHED) st_clr = CL_GRN;
                else if (conns[i].status_enum == CONN_STATUS_LISTEN) st_clr = CL_CYN;
                else if (conns[i].status_enum == CONN_STATUS_TIME_WAIT) st_clr = CL_YLW;
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
        else if (match_count > display_limit) {
            printf(CL_CYN "\n   [已显示 %d-%d / 共 %d 项 | 使用 J/K 滚动]\n" CLR_RST, 
                   scroll_offset + 1, scroll_offset + rendered, match_count);
        }
        
        scanner_free_connections(conns, count);
        fflush(stdout);

        // 输入采集与轮询
        for (int i = 0; i < REFRESH_POLL_ITERATIONS; i++) {
            int key = get_key();
            if (key == -1) { usleep(POLL_INTERVAL_US); continue; }

            if (is_searching) {
                if (key == 10 || key == 13 || key == 27) { // Enter or Esc
                    is_searching = 0;
                } else if (key == 8 || key == 127) { // Backspace
                    int len = strlen(search_filter);
                    if (len > 0) search_filter[len - 1] = '\0';
                } else if (key >= 32 && key <= 126 && strlen(search_filter) < 63) {
                    int len = strlen(search_filter);
                    search_filter[len] = (char)key;
                    search_filter[len + 1] = '\0';
                    scroll_offset = 0; // 搜索时重置滚动
                }
                break; // 有输入即刷新
            }

            if (key == 'q' || key == 'Q') {
                set_non_blocking_input(0);
                printf("\nExiting...\n");
                return 0;
            }
            if (key == 'l' || key == 'L') {
                current_lang = (current_lang == LANG_CN) ? LANG_EN : LANG_CN;
                break;
            }
            if (key == '/') {
                is_searching = 1;
                search_filter[0] = '\0';
                break;
            }
            if (key == 's' || key == 'S') {
                current_sort = (SortMode)((current_sort + 1) % 4); // 循环切换模式
                break;
            }
            if (key == 'j' || key == 'J') {
                if (scroll_offset + display_limit < internal_count_cache) scroll_offset++;
                break;
            }
            if (key == 'k' || key == 'K') {
                if (scroll_offset > 0) scroll_offset--;
                break;
            }
            if (key >= '1' && key <= '5') {
                current_view = (ViewType)(key - '0');
                scroll_offset = 0; 
                break;
            }
            usleep(POLL_INTERVAL_US);
        }
    }

    set_non_blocking_input(0);
    return 0;
}
