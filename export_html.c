#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "backend/scanner.h"

// HTML 模板头部（包含内嵌 CSS）
static const char* HTML_HEADER = 
"<!DOCTYPE html>\n"
"<html lang=\"zh-CN\">\n"
"<head>\n"
"    <meta charset=\"UTF-8\">\n"
"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"    <title>NCM 网络连接报告</title>\n"
"    <style>\n"
"        * { margin: 0; padding: 0; box-sizing: border-box; }\n"
"        body {\n"
"            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\n"
"            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);\n"
"            color: #e0e0e0;\n"
"            padding: 20px;\n"
"            min-height: 100vh;\n"
"        }\n"
"        .container { max-width: 1400px; margin: 0 auto; }\n"
"        h1 {\n"
"            text-align: center;\n"
"            color: #4ecca3;\n"
"            margin-bottom: 10px;\n"
"            font-size: 2em;\n"
"            text-shadow: 0 0 10px rgba(78, 204, 163, 0.3);\n"
"        }\n"
"        .timestamp {\n"
"            text-align: center;\n"
"            color: #888;\n"
"            margin-bottom: 30px;\n"
"            font-size: 0.9em;\n"
"        }\n"
"        .dashboard {\n"
"            display: grid;\n"
"            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));\n"
"            gap: 20px;\n"
"            margin-bottom: 30px;\n"
"        }\n"
"        .card {\n"
"            background: rgba(255, 255, 255, 0.05);\n"
"            border: 1px solid rgba(78, 204, 163, 0.3);\n"
"            border-radius: 10px;\n"
"            padding: 20px;\n"
"            text-align: center;\n"
"            transition: transform 0.2s, box-shadow 0.2s;\n"
"        }\n"
"        .card:hover {\n"
"            transform: translateY(-5px);\n"
"            box-shadow: 0 5px 20px rgba(78, 204, 163, 0.2);\n"
"        }\n"
"        .card-label { font-size: 0.9em; color: #aaa; margin-bottom: 5px; }\n"
"        .card-value { font-size: 2em; font-weight: bold; color: #4ecca3; }\n"
"        .card-value.warn { color: #ff6b6b; }\n"
"        .filters {\n"
"            background: rgba(255, 255, 255, 0.05);\n"
"            border-radius: 10px;\n"
"            padding: 15px;\n"
"            margin-bottom: 20px;\n"
"            display: flex;\n"
"            gap: 10px;\n"
"            flex-wrap: wrap;\n"
"        }\n"
"        .filters input, .filters select {\n"
"            padding: 8px 15px;\n"
"            border: 1px solid rgba(78, 204, 163, 0.3);\n"
"            border-radius: 5px;\n"
"            background: rgba(255, 255, 255, 0.1);\n"
"            color: #e0e0e0;\n"
"            font-size: 0.9em;\n"
"        }\n"
"        .filters input { flex: 1; min-width: 200px; }\n"
"        .filters select { min-width: 150px; }\n"
"        table {\n"
"            width: 100%%;\n"
"            border-collapse: collapse;\n"
"            background: rgba(255, 255, 255, 0.05);\n"
"            border-radius: 10px;\n"
"            overflow: hidden;\n"
"        }\n"
"        thead {\n"
"            background: rgba(78, 204, 163, 0.2);\n"
"            position: sticky;\n"
"            top: 0;\n"
"        }\n"
"        th {\n"
"            padding: 15px;\n"
"            text-align: left;\n"
"            font-weight: 600;\n"
"            cursor: pointer;\n"
"            user-select: none;\n"
"        }\n"
"        th:hover { background: rgba(78, 204, 163, 0.3); }\n"
"        td {\n"
"            padding: 12px 15px;\n"
"            border-bottom: 1px solid rgba(255, 255, 255, 0.1);\n"
"        }\n"
"        tr:hover { background: rgba(255, 255, 255, 0.08); }\n"
"        .suspicious {\n"
"            background: rgba(255, 107, 107, 0.2) !important;\n"
"            border-left: 3px solid #ff6b6b;\n"
"        }\n"
"        .icon { font-size: 1.2em; }\n"
"        .status-badge {\n"
"            padding: 3px 8px;\n"
"            border-radius: 3px;\n"
"            font-size: 0.85em;\n"
"            font-weight: 600;\n"
"        }\n"
"        .status-established { background: #4ecca3; color: #000; }\n"
"        .status-listen { background: #00d9ff; color: #000; }\n"
"        .status-other { background: #ffd93d; color: #000; }\n"
"        .copy-btn {\n"
"            cursor: pointer;\n"
"            opacity: 0.6;\n"
"            transition: opacity 0.2s;\n"
"        }\n"
"        .copy-btn:hover { opacity: 1; }\n"
"        @media (max-width: 768px) {\n"
"            .dashboard { grid-template-columns: 1fr; }\n"
"            table { font-size: 0.85em; }\n"
"            th, td { padding: 8px; }\n"
"        }\n"
"    </style>\n"
"</head>\n"
"<body>\n"
"<div class=\"container\">\n"
"    <h1>📊 NCM 网络连接报告</h1>\n";

// HTML 模板尾部（包含内嵌 JavaScript）
static const char* HTML_FOOTER = 
"    <script>\n"
"        const searchInput = document.getElementById('search');\n"
"        const statusFilter = document.getElementById('statusFilter');\n"
"        const protocolFilter = document.getElementById('protocolFilter');\n"
"        const table = document.getElementById('connTable');\n"
"        const rows = table.querySelectorAll('tbody tr');\n"
"\n"
"        // 搜索和过滤\n"
"        function filterRows() {\n"
"            const searchTerm = searchInput.value.toLowerCase();\n"
"            const statusValue = statusFilter.value;\n"
"            const protocolValue = protocolFilter.value;\n"
"            let visibleCount = 0;\n"
"\n"
"            rows.forEach(row => {\n"
"                const text = row.textContent.toLowerCase();\n"
"                const status = row.getAttribute('data-status');\n"
"                const protocol = row.getAttribute('data-protocol');\n"
"\n"
"                const matchSearch = text.includes(searchTerm);\n"
"                const matchStatus = !statusValue || status === statusValue;\n"
"                const matchProtocol = !protocolValue || protocol === protocolValue;\n"
"\n"
"                if (matchSearch && matchStatus && matchProtocol) {\n"
"                    row.style.display = '';\n"
"                    visibleCount++;\n"
"                } else {\n"
"                    row.style.display = 'none';\n"
"                }\n"
"            });\n"
"        }\n"
"\n"
"        searchInput.addEventListener('input', filterRows);\n"
"        statusFilter.addEventListener('change', filterRows);\n"
"        protocolFilter.addEventListener('change', filterRows);\n"
"\n"
"        // 表格排序\n"
"        document.querySelectorAll('th').forEach(th => {\n"
"            th.addEventListener('click', () => {\n"
"                const column = th.cellIndex;\n"
"                const rowsArray = Array.from(rows);\n"
"                const isAscending = th.classList.contains('asc');\n"
"\n"
"                rowsArray.sort((a, b) => {\n"
"                    const aText = a.cells[column].textContent.trim();\n"
"                    const bText = b.cells[column].textContent.trim();\n"
"                    return isAscending ? bText.localeCompare(aText) : aText.localeCompare(bText);\n"
"                });\n"
"\n"
"                document.querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));\n"
"                th.classList.add(isAscending ? 'desc' : 'asc');\n"
"\n"
"                const tbody = table.querySelector('tbody');\n"
"                rowsArray.forEach(row => tbody.appendChild(row));\n"
"            });\n"
"        });\n"
"\n"
"        // 复制到剪贴板\n"
"        function copyToClipboard(text) {\n"
"            navigator.clipboard.writeText(text).then(() => {\n"
"                console.log('已复制: ' + text);\n"
"            });\n"
"        }\n"
"    </script>\n"
"</body>\n"
"</html>\n";

// 转义 HTML 特殊字符
static void escape_html(const char *src, char *dest, size_t dest_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dest_size - 1; i++) {
        if (src[i] == '<') {
            if (j + 4 < dest_size) { strcpy(&dest[j], "&lt;"); j += 4; }
        } else if (src[i] == '>') {
            if (j + 4 < dest_size) { strcpy(&dest[j], "&gt;"); j += 4; }
        } else if (src[i] == '&') {
            if (j + 5 < dest_size) { strcpy(&dest[j], "&amp;"); j += 5; }
        } else {
            dest[j++] = src[i];
        }
    }
    dest[j] = '\0';
}

// 导出 HTML 报告主函数
int export_html_report(const char *filename, ConnectionInfo *conns, int count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "错误：无法创建文件 %s\n", filename);
        return -1;
    }

    // 计算统计数据
    ConnectionStats stats;
    calculate_stats(conns, count, &stats);

    // 获取当前时间
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // 写入 HTML 头部
    fprintf(fp, "%s", HTML_HEADER);
    fprintf(fp, "    <div class=\"timestamp\">生成时间: %s</div>\n", timestamp);

    // 写入统计看板
    fprintf(fp, "    <div class=\"dashboard\">\n");
    fprintf(fp, "        <div class=\"card\"><div class=\"card-label\">总连接数</div><div class=\"card-value\">%d</div></div>\n", stats.total);
    fprintf(fp, "        <div class=\"card\"><div class=\"card-label\">正在通信</div><div class=\"card-value\">%d</div></div>\n", stats.established);
    fprintf(fp, "        <div class=\"card\"><div class=\"card-label\">监听中</div><div class=\"card-value\">%d</div></div>\n", stats.listening);
    fprintf(fp, "        <div class=\"card\"><div class=\"card-label\">可疑连接</div><div class=\"card-value class=\\\"warn\\\">%d</div></div>\n", stats.suspicious);
    fprintf(fp, "    </div>\n");

    // 写入过滤器
    fprintf(fp, "    <div class=\"filters\">\n");
    fprintf(fp, "        <input type=\"text\" id=\"search\" placeholder=\"🔍 搜索进程、IP、端口...\">\n");
    fprintf(fp, "        <select id=\"statusFilter\"><option value=\"\">所有状态</option><option>ESTABLISHED</option><option>LISTEN</option><option>TIME_WAIT</option></select>\n");
    fprintf(fp, "        <select id=\"protocolFilter\"><option value=\"\">所有协议</option><option>TCP</option><option>UDP</option></select>\n");
    fprintf(fp, "    </div>\n");

    // 写入表格
    fprintf(fp, "    <table id=\"connTable\">\n");
    fprintf(fp, "        <thead>\n");
    fprintf(fp, "            <tr><th>图标</th><th>协议</th><th>本地地址</th><th>远端地址</th><th>状态</th><th>进程</th><th>操作</th></tr>\n");
    fprintf(fp, "        </thead>\n");
    fprintf(fp, "        <tbody>\n");

    // 写入连接数据
    char escaped[512];
    for (int i = 0; i < count; i++) {
        ConnectionInfo *c = &conns[i];
        int suspicious = is_suspicious(c);
        int is_ext = is_external_connection(c);
        
        // 确定图标
        const char *icon = "🏠"; // 本地
        if (is_ext) {
            if (suspicious) icon = "⚠️";
            else if (strstr(c->remote_addr, ":443") || strstr(c->remote_addr, ":8443")) icon = "🔒";
            else icon = "🌐";
        }

        // 确定状态样式
        const char *status_class = "status-other";
        if (c->status_enum == CONN_STATUS_ESTABLISHED) status_class = "status-established";
        else if (c->status_enum == CONN_STATUS_LISTEN) status_class = "status-listen";

        fprintf(fp, "            <tr %s data-status=\"%s\" data-protocol=\"%s\">\n",
                suspicious ? "class=\"suspicious\"" : "",
                c->status,
                c->protocol);
        fprintf(fp, "                <td class=\"icon\">%s</td>\n", icon);
        fprintf(fp, "                <td>%s</td>\n", c->protocol);
        
        escape_html(c->local_addr, escaped, sizeof(escaped));
        fprintf(fp, "                <td>%s</td>\n", escaped);
        
        escape_html(c->remote_addr, escaped, sizeof(escaped));
        fprintf(fp, "                <td>%s <span class=\"copy-btn\" onclick=\"copyToClipboard('%s')\" title=\"复制 IP\">📋</span></td>\n", 
                escaped, escaped);
        
        fprintf(fp, "                <td><span class=\"status-badge %s\">%s</span></td>\n", status_class, c->status);
        
        escape_html(c->process, escaped, sizeof(escaped));
        fprintf(fp, "                <td>%s</td>\n", escaped);
        fprintf(fp, "                <td>-</td>\n");
        fprintf(fp, "            </tr>\n");
    }

    fprintf(fp, "        </tbody>\n");
    fprintf(fp, "    </table>\n");
    fprintf(fp, "</div>\n");

    // 写入 HTML 尾部
    fprintf(fp, "%s", HTML_FOOTER);

    fclose(fp);
    printf("✅ HTML 报告已生成: %s\n", filename);
    printf("   包含 %d 个连接，其中 %d 个可疑\n", count, stats.suspicious);
    return 0;
}
