# NCM (Network Connection Monitor) - 工业级极简网络审计工具

![Type](https://img.shields.io/badge/Language-C11-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green.svg)
![Version](https://img.shields.io/badge/Version-v2.0--Stable-brightgreen.svg)
![Size](https://img.shields.io/badge/Binary-＜50KB-brightgreen.svg)

NCM 是一款高性能、零依赖的实时网络连接审计工具。它不仅能展示当前的 TCP/UDP 连接，更能通过**内核级驱动 (eBPF/Netlink)** 精准捕捉闪断连接，并基于**深度路径审计**识别系统中的异常隐患。

## 🌟 v2.0 震撼特性

- **⚡ 秒级感知 (内核级驱动)**：
    - **Tier 1 (eBPF)**：现代内核下的零拷贝高性能采集。
    - **Tier 2 (Netlink)**：兼容旧内核的实时进程生命周期监控，彻底杜绝短连接漏扫。
- **🛡️ 深度审计与预警**：
    - **路径审计**：跨特权识别运行在 `/tmp`、隐藏目录或内存挂载点 (`/dev/shm`) 的危险进程。
    - **频率监测 (Spike)**：内置 5 轮环形缓冲区，自动发现并警示瞬间爆发大量连接的扫描行为。
- **🎮 极客交互 (TUI)**：
    - **动态趋势图**：实时绘制 60 点连接波动 Sparklines。
    - **详情弹窗 (Enter)**：一键查看进程完整执行路径与风险评分。
    - **管控能力 (K)**：支持在 TUI 中一键确认终止可疑进程。
    - **Vim 式体验**：支持 `/` 实时过滤及 `j/k` 滚动选择。

## 🛠️ 项目结构

```text
ncm-c/
├── main.c              # UI 渲染与双引擎交互 (按键 + 内核事件)
├── backend/            # 系统驱动层
│   ├── kernel_probe.h  # 内核特性侦测器 (eBPF/Netlink/Polling)
│   ├── nl_listener.c   # Netlink Connector 实效驱动
│   └── scanner_lin.c   # ProcFS 审计驱动 (含路径溯源)
├── lib/                # 审计大脑
│   ├── logic.c         # 路径风险算法与异常评分
│   └── html_export.c   # 离线安全报告导出
└── CMakeLists.txt      # 跨平台构建系统
```

## 🚀 快速开始

```bash
# 1. 克隆并编译
mkdir build && cd build
cmake .. && make

# 2. 交互模式运行 (建议赋予 root 权限以获取完整进程审计能力)
sudo ./ncm

# 3. 导出一次性安全报告
./ncm -e report.html
```

## ⌨️ 专家交互指南

| 按键 | 功能说明 | 高级用法 |
| :--- | :--- | :--- |
| **`j / k`** | **上下选中** | 选中的行会反白，用于进一步操作 |
| **`Enter`** | **查看详情** | 在浮窗中展示进程路径、PID 及风险代码 |
| **`K` (Shift+k)** | **强制终止** | 弹出红色确认框，一键杀掉该恶意连接进程 |
| **`/`** | **实时搜索** | 支持按进程名、IP 模糊匹配 |
| **`S`** | **排序切换** | 循环切换 PID -> 进程名 -> 远程地址排序 |
| **`1 - 5`** | **视图视图** | 总览、全量、通信、监听、**风险优先(5)** |

## 🧠 技术实现重点

1. **双引擎轮询**：主循环同时服务于用户键盘 IO 与 Netlink 内核套接字，实现秒级响应。
2. **环形缓冲区 (Ring Buffer)**：在 2MiB 恒定内存水平下，提供高纬度的历史行为回溯。
3. **分级加载机制**：程序启动自动探测环境，实现“有 eBPF 用最优，无 eBPF 用 Netlink 补位”的极致兼容。

## 📜 许可证

本项目采用 MIT 许可证。
