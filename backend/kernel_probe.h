#ifndef KERNEL_PROBE_H
#define KERNEL_PROBE_H

typedef enum {
    DRIVER_POLLING, // Tier 0 (Legacy / Standard)
    DRIVER_NETLINK, // Tier 2 (Old Kernel / No eBPF)
    DRIVER_EBPF     // Tier 1 (Modern Kernel)
} DriverTier;

// 探测当前系统支持的最优驱动级别
DriverTier probe_kernel_features();

// 获取驱动名称字符串
const char* get_driver_name(DriverTier tier);

#endif // KERNEL_PROBE_H
