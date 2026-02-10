#include "backend/kernel_probe.h"

#ifdef _WIN32
DriverTier probe_kernel_features() {
    return DRIVER_POLLING;
}

const char* get_driver_name(DriverTier tier) {
    return "Standard Polling (Win)";
}
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

// 简单的内核版本检查
static int is_kernel_version_ge(int major, int minor) {
    struct utsname buffer;
    if (uname(&buffer) != 0) return 0;
    int k_major, k_minor;
    if (sscanf(buffer.release, "%d.%d", &k_major, &k_minor) == 2) {
        if (k_major > major) return 1;
        if (k_major == major && k_minor >= minor) return 1;
    }
    return 0;
}

// 模拟 errno 处理（因为 syscall 可能会改变它）
#include <errno.h>
static int prev_errno() { return errno; }

// 检查 BPF 系统调用是否可用
static int check_bpf_syscall() {
    // __NR_bpf 是 bpf 系统调用的编号
    // 尝试执行一个空的 bpf 调用（cmd=0, attr=NULL）
    // 如果返回 -1 且 errno 不是 ENOSYS，则说明内核支持该调用
    #ifdef __NR_bpf
    long ret = syscall(__NR_bpf, 0, NULL, 0);
    if (ret == -1 && (prev_errno() == ENOSYS)) return 0;
    return 1;
    #else
    return 0;
    #endif
}

DriverTier probe_kernel_features() {
    // 1. 尝试检测 eBPF (Tier 1)
    // 现代 eBPF 通常在 4.1 之后引入，4.9+ 比较完善
    if (is_kernel_version_ge(4, 9) && check_bpf_syscall()) {
        return DRIVER_EBPF;
    }

    // 2. 尝试检测 Netlink Connector (Tier 2)
    // 绝大多数 2.6.14+ 内核都支持
    if (is_kernel_version_ge(2, 6)) {
        return DRIVER_NETLINK;
    }

    // 3. 保底
    return DRIVER_POLLING;
}

const char* get_driver_name(DriverTier tier) {
    switch (tier) {
        case DRIVER_EBPF:    return "eBPF (Tier 1)";
        case DRIVER_NETLINK: return "Netlink (Tier 2)";
        default:             return "Standard Polling (Tier 0)";
    }
}
#endif
