#ifndef NETLINK_LISTENER_H
#define NETLINK_LISTENER_H

#include <stdint.h>

// 启动 Netlink Connector 监听
// 返回套接字描述符，失败返回 -1
int nl_init_listener();

// 等待下一个进程事件
// 返回 1 表示捕获到 exec 事件，需触发扫描；返回 0 表示其他事件；-1 出错
int nl_wait_for_event(int nl_sock);

#endif // NETLINK_LISTENER_H
