# NCM-C 项目架构分析报告 (v2.0 演进版)

## 1. 项目概览

NCM-C 是一个轻量级、零依赖的命令行网络连接监控工具。它旨在提供高性能、准实时的网络状态审计。在 v2.0 版本中，项目从一个简单的轮询扫描器演进为支持**内核事件驱动**和**深度行为分析**的准专业级工具。

**核心演进特点：**
- **双擎驱动 (Tiered Drivers)**：支持 eBPF (Tier 1) 和 Netlink Connector (Tier 2) 加载，告别死循环轮询。
- **内存无感审计**：利用环形缓冲区 (Ring Buffer) 存储历史快照，实现 10s 级行为回溯而不增加内存负担。
- **深度风险识别**：不仅看端口，还深度审计进程执行路径 (exe_path) 和连接频率突变 (Spike)。

## 2. 模块架构

项目采用插件化驱动与分层逻辑架构：

```mermaid
graph TD
    UI[交互展现层 (main.c)] --> Logic[审计逻辑层 (lib/logic.c)]
    Logic --> History[(环形缓冲区 / 历史快照)]
    
    UI --> DriverAdapter[驱动适配层 (kernel_probe.c)]
    DriverAdapter -.->|Tier 1| EBPF[eBPF 零拷贝监测]
    DriverAdapter -.->|Tier 2| Netlink[Netlink Connector 监听器]
    DriverAdapter -.->|Tier 0| Polling[ProcFS 标准轮询]
    
    Netlink -->|事件触发| Backend[后端适配层 (backend/scanner_lin.c)]
```

### 2.1 驱动适配层 (Driver Adapter)
- **内核侦测**：启动时自动识别 `/proc/config.gz` 和 `bpf()` 系统调用。
- **Netlink 触发器**：在 Tier 2 模式下，实时订阅进程 `exec` 事件，只要有新进程启动，立即强制后端刷新。

### 2.2 核心逻辑与审计 (Logic)
- **路径审计**：穿透识别非法临时目录 (`/tmp`) 或隐藏目录中的可疑进程。
- **行为判定**：
    - **is_suspicious**：多维度风险分值（路径风险、异常端口）。
    - **Spike Detection**：通过对比最近 5 轮快照识别连接数瞬时爆增逻辑。

### 2.3 交互展现 (TUI)
- **双中心循环**：主循环同时服务于用户按键输入（非阻塞）与驱动事件（Netlink FD）。
- **视觉增强**：
    - **Sparklines**：60 点字符趋势图。
    - **Overlays**：ANSI 边框进程详情弹窗。
    - **Selection**：Vim 式行选中与一键 Kill 功能。

## 3. 内存与稳定性设计
- **动态堆分配**：连接列表采用动态 `malloc`，支持数千条连接采集。
- **滚动覆盖机制**：历史数据存储在固定大小的环形缓冲区中，内存占用恒定在 ~2MiB。
- **边界哨兵**：在所有 UI 交互动作中加入严格的 `selected_idx` 校验，防止段错误。

## 4. 关键技术：分级探测与实时性感应
当系统暂不支持 eBPF 时，NCM-C 采用 “Netlink 实时补位” 策略：
1. 建立 `NETLINK_CONNECTOR / PROC_EVENT_EXEC` 原始套接字。
2. 将其 FD 挂载至主循环的轮询列表中。
3. 一旦内核产生进程创建信号，应用立即感知并进行增量扫描。这极大降低了传统监控工具对短连接（如快速发包扫描）的漏扫概率。

## 5. 总结
架构已经从简单的“状态查看”转向“行为监测”。模块化的驱动设计使得 NCM-C 在保证极致轻量（<50KB）的同时，具备了对底层的敏锐感知力和对高并发场景的稳定性。
