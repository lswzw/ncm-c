#include "backend/nl_listener.h"

#ifdef _WIN32
int nl_init_listener() { return -1; }
int nl_wait_for_event(int nl_sock) { return 0; }
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <errno.h>

int nl_init_listener() {
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) return -1;

    struct sockaddr_nl sa_nl;
    memset(&sa_nl, 0, sizeof(sa_nl));
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    if (bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) == -1) {
        close(nl_sock);
        return -1;
    }

    // 订阅进程事件
    struct {
        struct nlmsghdr nl_hdr;
        struct cn_msg cn_msg;
        enum proc_cn_mcast_op op;
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    msg.op = PROC_CN_MCAST_LISTEN;

    if (send(nl_sock, &msg, sizeof(msg), 0) == -1) {
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

int nl_wait_for_event(int nl_sock) {
    char buf[1024];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    
    // 使用 MSG_DONTWAIT 确保在 select 之后调用时不会进入死等
    ssize_t len = recv(nl_sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (len <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; // 无数据
        return -1; // 出错
    }

    for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
        
        struct cn_msg *cn_m = NLMSG_DATA(nlh);
        if (cn_m->id.idx != CN_IDX_PROC || cn_m->id.val != CN_VAL_PROC) continue;

        struct proc_event *event = (struct proc_event *)cn_m->data;
        if (event->what == PROC_EVENT_EXEC) {
            return 1; // 捕获到 exec 事件
        }
    }
    return 0;
}
#endif
