# NCM-C 项目架构分析报告

## 1. 项目概览

NCM-C 是一个轻量级、零依赖的命令行网络连接监控工具。它旨在提供类似 `netstat` 或 `lsof` 的功能，但以交互式 TUI (文本用户界面) 形式呈现，并专注于实时监控和风险发现。

**核心特点：**
- **零依赖**：Linux 下仅通过 `/proc` 文件系统获取信息，不调用外部命令。
- **跨平台**：通过 Backend 抽象层适配 Linux 和 Windows。
- **高性能**：C11 编写，内存占用极低。

## 2. 模块架构

项目采用经典的分层架构：

```mermaid
graph TD
    UI[主要交互层 (main.c)] --> Logic[核心逻辑层 (lib/logic.c)]
    Logic --> Backend[平台适配层 (backend/scanner.h)]
    Backend -.->|Linux| LinImpl[Scanner Linux (backend/scanner_lin.c)]
    Backend -.->|Windows| WinImpl[Scanner Windows (backend/scanner_win.c)]
    
    LinImpl -->|读取| ProcFS[/proc 文件系统/]
    WinImpl -->|调用| WinAPI[Windows API]
```

### 2.1 平台适配层 (Backend)
- **接口定义**：`backend/scanner.h` 提供了统一的接口 `scanner_get_connections`。
- **数据结构**：定义了 `ConnectionInfo` 结构体，包含协议、本地/远程地址、状态、PID 和进程名。
- **Linux 实现 (`backend/scanner_lin.c`)**：
    - **连接获取**：解析 `/proc/net/tcp` 和 `/proc/net/udp` 获取原始连接信息（状态、inode）。
    - **进程映射**：遍历 `/proc/[pid]/fd/` 目录，通过 `readlink` 获取 socket inode，与连接信息中的 inode 匹配，从而找到所属进程。
    - **十六进制解析**：手动解析内核格式的 IP 和端口。

### 2.2 核心逻辑层 (Logic)
- **位置**：`lib/logic.c`
- **统计分析**：`calculate_stats` 遍历连接列表，统计 TCP 状态（ESTABLISHED as 活跃, LISTEN 等），并计算最活跃的进程。
- **风险判定**：`is_suspicious` 函数实现简单的安全规则：
    - 仅检查 ESTABLISHED 的外部连接。
    - 检查远程端口是否在白名单（80, 443, 22 等常用端口）。
    - 若连接非白名单端口，标记为可疑（红色高亮）。

### 2.3 交互展现层 (UI)
- **位置**：`main.c`
- **渲染循环**：主循环负责仅定时刷新（防止闪烁），使用 ANSI Escape Codes 控制颜色和光标。
- **输入处理**：
    - 实现跨平台的非阻塞输入（Linux `termios`, Windows `conio`）。
    - 支持按键切换视图（总览、所有连接、仅监听、可疑连接）。
- **国际化**：内置中英文字符串表，支持运行时一键切换。

## 3. 构建系统
- 使用 CMake 构建。
- 根据 `WIN32` 宏自动选择链接 `backend/scanner_win.c` 或 `backend/scanner_lin.c`。
- Release 模式默认开启尺寸优化 (`-Os`, `--gc-sections`)。

## 4. 关键流程解析：Linux 进程追踪

Linux 下无特权获取连接所属进程是本项目的技术难点，实现流程如下：

1. **读取网络表**：扫描 `/proc/net/tcp` 获得 `local_ip:port`, `remote_ip:port`, `state`, `inode`。
2. **扫描进程表**：打开 `/proc` 目录遍历所有数字命名的子目录（即 PID）。
3. **匹配文件描述符**：
   - 遍历每个进程的 `/proc/[pid]/fd/`。
   - 读取符号链接目标，格式为 `socket:[inode]`。
   - 若 inode 匹配网络表中的 inode，则该进程拥有该连接。
4. **获取进程名**：读取 `/proc/[pid]/comm` 获取简短进程名。

> 注意：此方法在 Linux 下通常需要 root 权限才能完整扫描所有进程的 fd，否则只能看到当前用户进程的连接。

## 5. 总结
代码结构清晰，模块化程度高。核心逻辑简单但有效（特别是通过 `/proc` 关联进程）。主要扩展方向可以是增强协议分析、增加更多安全规则或支持流量统计（目前仅连接状态）。
