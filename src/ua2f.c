#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include "ipset_hook.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>


#include <libmnl/libmnl.h>

#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#define NF_ACCEPT 1

int child_status;

static struct mnl_socket *nl;
static const int queue_number = 10010;

static long long UAcount = 0;
static long long tcpcount = 0;
static long long UAmark = 0;
static long long noUAmark = 0;
static long long httpcount = 4;

static time_t start_t, current_t;

static char timestr[60];

char *UAstr = NULL;
const char *DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.1.6217.39 Safari/537.36";

static struct ipset *Pipset;

void *memncasemem(const void *l, size_t l_len, const void *s, size_t s_len) {
    const char *cl = (const char *) l;
    const char *cs = (const char *) s;

    if (l_len == 0 || s_len == 0) {
        return NULL;
    }

    if (l_len < s_len) {
        return NULL;
    }

    if (s_len == 1) {
        return memchr(l, (int) *cs, l_len);
    }

    const char *last = cl + l_len - s_len;
    for (; cl <= last && (cl = memchr(cl, cs[0], last - cl + 1)); cl++) {
        if (memcmp(cl, cs, s_len) == 0) {
            return (void *) cl;
        }
    }

    return NULL;
}

static char *time2str(int sec) {
    static const int MINUTE = 60;
    static const int HOUR = 60 * MINUTE;
    static const int DAY = 24 * HOUR;

    static char timestr[32] = {0};

    time_t timestamp = (time_t) sec;
    struct tm *tm_info = localtime(&timestamp);

    if (sec <= 0) {
        sprintf(timestr, "0 seconds");
    } else if (sec < HOUR) {
        strftime(timestr, sizeof(timestr), "%M minutes and %S seconds", tm_info);
    } else if (sec < DAY) {
        strftime(timestr, sizeof(timestr), "%H hours, %M minutes and %S seconds", tm_info);
    } else {
        strftime(timestr, sizeof(timestr), "%d days, %H hours, %M minutes and %S seconds", tm_info);
    }

    return timestr;
}

static int parse_attrs(const struct nlattr *attr, void *data) {
    assert(attr != NULL);
    assert(data != NULL);

    struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (type >= 0 && type < MNL_SOCKET_BUFFER_SIZE) {
        if (!mnl_attr_validate(attr, MNL_TYPE_UNSPEC)) {
            tb[type] = (struct nlattr *) attr;
        }
    }

    return MNL_CB_OK;
}

static void
nfq_send_verdict(int queue_num, uint32_t id, struct pkt_buff *pktb, uint32_t mark, bool noUA,
                 char addcmd[50]) { // http mark = 24, ukn mark = 16-20, no http mark = 23
    char buf[0xffff + (MNL_SOCKET_BUFFER_SIZE / 2)];
    struct nlmsghdr *nlh;
    struct nlattr *nest;
    uint32_t setmark;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, (int) id, NF_ACCEPT);

    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }


    if (noUA) {
        if (mark == 1) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(16));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark >= 16 && mark <= 40) {
            setmark = mark + 1;
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark == 41) { // 21 统计确定此连接为不含UA连接

            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(43));
            mnl_attr_nest_end(nlh, nest); // 加 CONNMARK

            ipset_parse_line(Pipset, addcmd); //加 ipset 标记

            noUAmark++;
        }
    } else {
        if (mark != 44) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(44));
            mnl_attr_nest_end(nlh, nest);
            UAmark++;
        }
    }


    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 1.");
        exit(EXIT_FAILURE);
    }

    tcpcount++;
    pktb_free(pktb);
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
    assert(nlh != NULL);
    assert(data != NULL);

    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    struct nlattr *ctattr[CTA_MAX + 1] = {};
    struct nlattr *originattr[CTA_TUPLE_MAX + 1] = {};
    struct nlattr *ipattr[CTA_IP_MAX + 1] = {};
    struct nlattr *portattr[CTA_PROTO_MAX + 1] = {};
    uint16_t plen;
    struct pkt_buff *pktb;
    struct iphdr *ippkhdl;
    struct tcphdr *tcppkhdl;
    struct nfgenmsg *nfg;
    char *tcppkpayload;
    unsigned int tcppklen;
    unsigned int uaoffset = 0;
    unsigned int ualength = 0;
    void *payload;
    uint32_t mark = 0;
    bool noUA = false;
    char *ip;
    uint16_t port = 0;
    char addcmd[50];

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        syslog(LOG_ERR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_CT]) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctattr);

        if (ctattr[CTA_MARK]) {
            mark = ntohl(mnl_attr_get_u32(ctattr[CTA_MARK]));
        } else {
            mark = 1; // no mark 1
        } // NFQA_CT 一定存在，不存在说明有其他问题

        if (ctattr[CTA_TUPLE_ORIG]) {
            mnl_attr_parse_nested(ctattr[CTA_TUPLE_ORIG], parse_attrs, originattr);
            if (originattr[CTA_TUPLE_IP]) {
                mnl_attr_parse_nested(originattr[CTA_TUPLE_IP], parse_attrs, ipattr);
                if (ipattr[CTA_IP_V4_DST]) {
                    uint32_t tmp = mnl_attr_get_u32(ipattr[CTA_IP_V4_DST]);
                    struct in_addr tmp2;
                    tmp2.s_addr = tmp;
                    ip = inet_ntoa(tmp2);
                } else {
                    ip = "0.0.0.0";
                }
            } else {
                ip = "0.0.0.0";
            }
            if (originattr[CTA_TUPLE_PROTO]) {
                mnl_attr_parse_nested(originattr[CTA_TUPLE_PROTO], parse_attrs, portattr);
                if (portattr[CTA_PROTO_DST_PORT]) {
                    port = ntohs(mnl_attr_get_u16(portattr[CTA_PROTO_DST_PORT]));
                }
            }
            if (ip && port != 0) {
                sprintf(addcmd, "add nohttp %s,%d", ip, port);
            }
        }
    }

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);


    pktb = pktb_alloc(AF_INET, payload, plen, 0); //IP包

    if (!pktb) {
        syslog(LOG_ERR, "pktb malloc failed");
        return MNL_CB_ERROR;
    }

    ippkhdl = nfq_ip_get_hdr(pktb); //获取ip header

    if (nfq_ip_set_transport_header(pktb, ippkhdl) < 0) {
        syslog(LOG_ERR, "set transport header failed");
        pktb_free(pktb);
        return MNL_CB_ERROR;
    }

    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl, pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl, pktb); //获取 tcp长度

    // 修改 TCP 数据包中的 User-Agent 头部
    if (tcppkpayload) {
        const char *uapointer = memncasemem(tcppkpayload, tcppklen, "\r\nUser-Agent: ", 14);
        if (uapointer != NULL) {
            size_t uaOffset = uapointer - tcppkpayload + 14;
            if (uaOffset >= tcppklen - 2) { // User-Agent: XXX\r\n
                syslog(LOG_WARNING, "User-Agent has no content");
                nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA, addcmd);
                return MNL_CB_OK;
            }
            const char *endPointer = memchr(uapointer, '\r', tcppklen - (uapointer - tcppkpayload));
            if (endPointer != NULL) {
                size_t uaLength = endPointer - uapointer - 14;
                if (uaLength > 0) {
                    if (!UAstr) {
                        UAstr = malloc(uaLength + 1);
                        if (!UAstr) {
                            syslog(LOG_ERR, "Failed to allocate memory for UAstr.");
                            pktb_free(pktb);
                            return MNL_CB_ERROR;
                        }
                    } else {
                        UAstr = realloc(UAstr, uaLength + 1);
                        if (!UAstr) {
                            syslog(LOG_ERR, "Failed to reallocate memory for UAstr.");
                            pktb_free(pktb);
                            return MNL_CB_ERROR;
                        }
                    }
                    memcpy(UAstr, uapointer + 14, uaLength);
                    UAstr[uaLength] = '\0';
                    if (nfq_tcp_mangle_ipv4(pktb, uaOffset, uaLength, UAstr, uaLength) == 1) {
                        UAcount++; //记录修改包的数量
                    } else {
                        syslog(LOG_ERR, "Mangle packet failed.");
                        pktb_free(pktb);
                        free(UAstr);
                        return MNL_CB_ERROR;
                    }
                } else {
                    syslog(LOG_WARNING, "User-Agent header length invalid");
                }
            } else {
                syslog(LOG_WARNING, "User-Agent header not terminated with \\r");
            }
        } else {
            noUA = true;
        }
    }

    nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA, addcmd);

    if (UAcount / httpcount == 2 || UAcount - httpcount >= 8192) {
        httpcount = UAcount;
        current_t = time(NULL);
        syslog(LOG_INFO,
               "UA2F has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s",
               UAcount, tcpcount, UAmark, noUAmark,
               time2str((int) difftime(current_t, start_t)));
    }

    return MNL_CB_OK;
}

static void killChild() {
    syslog(LOG_INFO, "Received SIGTERM, kill child %d", child_status);
    kill(child_status, SIGKILL); // Not graceful, but work
    mnl_socket_close(nl);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    char *buf;
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    struct nlmsghdr *nlh;
    ssize_t ret;
    unsigned int portid;

    int errcount = 0;

    signal(SIGTERM, killChild);

    while (true) {
        child_status = fork();
        if (child_status < 0) {
            syslog(LOG_ERR, "Failed to give birth.");
            syslog(LOG_ERR, "Exit at fork.");
            exit(EXIT_FAILURE);
        } else if (child_status == 0) {
            syslog(LOG_NOTICE, "UA2F processor start at [%d].", getpid());
            break;
        } else {
            syslog(LOG_NOTICE, "Try to start UA2F processor at [%d].", child_status);
            int deadstat;
            int deadpid;
            deadpid = wait(&deadstat);
            if (deadpid == -1) {
                syslog(LOG_ERR, "Child suicide.");
            } else {
                syslog(LOG_ERR, "Meet fatal error.[%d] dies by %d", deadpid, deadstat);
            }
        }
        errcount++;
        if (errcount > 10) {
            syslog(LOG_ERR, "Meet too many fatal error, no longer try to recover.");
            syslog(LOG_ERR, "Exit with too many error.");
            exit(EXIT_FAILURE);
        }
    }


    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    start_t = time(NULL);

    ipset_load_types();
    Pipset = ipset_init();

    if (!Pipset) {
        syslog(LOG_ERR, "Pipset not inited.");
        exit(EXIT_FAILURE);
    }

    ipset_custom_printf(Pipset, func, func2, func3, NULL); // hook 掉退出的输出函数

    syslog(LOG_NOTICE, "Pipset inited.");

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == NULL) {
        perror("mnl_socket_open");
        syslog(LOG_ERR, "Exit at mnl_socket_open.");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        syslog(LOG_ERR, "Exit at mnl_socket_bind.");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    buf = malloc(sizeof_buf);
    if (!buf) {
        perror("allocate receive buffer");
        syslog(LOG_ERR, "Exit at breakpoint 6.");
        exit(EXIT_FAILURE);
    }

// 如果未找到 User-Agent 头部，则使用默认值
    if (!UAstr) {
        UAstr = malloc(strlen(DEFAULT_UA) + 1);
        if (!UAstr) {
            syslog(LOG_ERR, "Failed to allocate memory for UAstr.");
            return MNL_CB_ERROR; // 修改返回值，不需要释放 pktb
        }
        memcpy(UAstr, DEFAULT_UA, strlen(DEFAULT_UA) + 1);
    }

// 释放 UAstr 分配的内存块
    free(UAstr);

    return MNL_CB_OK;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 7.");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_FLAGS,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_MASK,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));


    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at mnl_socket_send.");
        exit(EXIT_FAILURE);
    }

    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    syslog(LOG_NOTICE, "UA2F has inited successful.");

    while (1) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret < 0) {
            perror("mnl_socket_recvfrom");
            break;
        }
        ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
        if (ret < 0) {
            perror("mnl_cb_run");
            break;
        }
    }
    mnl_socket_close(nl);
}
