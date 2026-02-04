# NCM (Network Connection Monitor) - 原生 C 语言极简版

![Type](https://img.shields.io/badge/Language-C11-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green.svg)
![License](https://img.shields.io/badge/License-MIT-orange.svg)
![Size](https://img.shields.io/badge/Binary-＜200KB-brightgreen.svg)

NCM 是一款高性能、零依赖的跨平台实时网络连接监控工具。它旨在替代臃肿的图形界面监控程序，通过极致优化的 C 语言实现，在终端中提供丝滑的可视化监控体验。

## 🌟 核心特性

- **🚀 极致性能**：采用原生 C11 编写，二进制体积小于 200KB，运行时内存占用极低。
- **📦 零外部依赖**：不依赖任何第三方 GUI 库或复杂的运行环境，只需编译器即可编译运行。
- **💻 跨平台支持**：双内核驱动，完美支持 Linux (通过 `/proc` 文件系统) 和 Windows (基于原生 `iphlpapi.dll`)。
- **📊 交互式 TUI**：精心设计的终端用户界面 (TUI)，包含可视化看板、实时统计和多视图切换。
- **🔍 智能检测**：内置可疑连接识别算法，自动高亮潜在的安全风险。
- **🌐 国际化支持**：支持中英文一键实时切换，自适应中文双倍字符宽度打印。

## 🛠️ 项目结构

```text
ncm-c/
├── main.c              # 交互引擎与 UI 渲染 (TUI 逻辑)
├── backend/            # 系统平台适配层
│   ├── scanner.h       # 统一接口定义
│   ├── scanner_win.c   # Windows 原生驱动
│   └── scanner_lin.c   # Linux 原生驱动
├── lib/                # 核心逻辑与算法
│   ├── logic.c         # 统计、排序、风险判定算法
│   └── cJSON.h/c       # 数据解析支持 (可选)
└── CMakeLists.txt      # 跨平台构建脚本
```

## 🚀 快速开始

### 编译

本项目使用标准的 CMake 构建系统：

```bash
mkdir -p build && cd build
cmake ..
make
```

### 运行

```bash
./ncm
```
*注：对于部分 Linux 系统，查看进程名称可能需要 sudo 权限。*

## ⌨️ 交互指南

| 按键 | 功能说明 |
| :--- | :--- |
| **`1`** | **总览 (Overview)** - 核心网络活动摘要看板 |
| **`2`** | **全量 (All)** - 查看所有活跃的网络连接 |
| **`3`** | **通信中 (Established)** - 仅显示已建立连接的会话 |
| **`4`** | **监听中 (Listening)** - 查看本机正在开放的服务端口 |
| **`5`** | **可疑 (Suspicious)** - 智能判定并展示异常连接 |
| **`L`** | **语言切换 (Language)** - 在中文与英文界面间实时切换 |
| **`Q`** | **退出 (Exit)** - 优雅关闭程序 |

## 🎨 视觉反馈说明

为了提供直观的监控体验，NCM 使用了颜色编码：

- **🟢 绿色**：代表 `ESTABLISHED` (已建立) 的活跃连接。
- **🔵 青色**：代表 `LISTEN` (监听中) 的本地服务。
- **🟡 黄色**：代表 `WAIT` 系列状态或 UDP 协议报文。
- **🔴 红色背景**：高风险！表示该连接符合**可疑特征**，建议立即查验。

## 🧠 技术实现重点

1. **跨平台 IO**：Linux 下采用非阻塞 `read` 与 `termios`；Windows 下则使用 `_kbhit()`。
2. **多进程追踪**：通过扫描 `/proc/[pid]/fd` 为网络连接精准关联所属进程（Linux 端）。
3. **自适应 UI**：手动处理终端刷新，避免闪烁；精准计算 UTF-8 中文宽度以保持列表对齐。
4. **零拷贝设计**：扫描器与逻辑层之间采用高效的数据结构传递，保证高频刷新下的流畅度。

## 📜 许可证

本项目采用 MIT 许可证。
