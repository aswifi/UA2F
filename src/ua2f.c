#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include "ipset_hook.h"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>

#include <limits.h>

#include <errno.h>

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

static const char COMMON_UA[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.4.6379.82 Safari/537.36";

static long long UAcount = 0;
static long long tcpcount = 0;
static long long UAmark = 0;
static long long noUAmark = 0;
static long long httpcount = 4;

static time_t start_t, current_t;

static char timestr[60];

char *UAstr = NULL;

static struct ipset *Pipset;

void *memncasemem(const void *l, size_t l_len, const void *s, size_t s_len) {

    register char *cur = (char *) l;
    const char *cs = (const char *) s;

    /* we need something to compare */
    if (l_len == 0 || s_len == 0)
        return NULL;

    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len)
        return NULL;

    /* special case where s_len == 1 */
    if (s_len == 1)
        return memchr(l, (int) *cs, l_len);

    /* Boyer-Moore preprocessing */
    int skip_table[UCHAR_MAX + 1];
    for (int i = 0; i <= UCHAR_MAX; i++)
        skip_table[i] = s_len;
    for (int i = 0; i < s_len - 1; i++)
        skip_table[(unsigned char) cs[i]] = s_len - i - 1;

    /* the last position where its possible to find "s" in "l" */
    char *last = (char *) l + l_len - s_len;

    /* search */
    while (cur <= last) {
        int j = s_len - 1;
        while (j >= 0 && tolower(cur[j]) == tolower(cs[j]))
            j--;
        if (j < 0)
            return cur;
        int skip_value = skip_table[(unsigned char) cur[j]];
        if (skip_value < s_len - j) {
            cur += s_len - j;
        } else {
            cur += skip_value;
        }
    }

    return NULL;
}

typedef enum {
    SECOND = 1,
    MINUTE = 60 * SECOND,
    HOUR = 60 * MINUTE,
    DAY = 24 * HOUR
} TimeUnit;

static char *time2str(int sec) {

    static const TimeUnit UNIT[] = {DAY, HOUR, MINUTE, SECOND};
    static const char *UNIT_NAME[] = {" days", " hours", " minutes", " seconds"};

    memset(timestr, 0, sizeof(timestr));
    int len = 0;
    for (int i = 0; i < sizeof(UNIT) / sizeof(UNIT[0]); ++i) {
        if (sec >= UNIT[i]) {
            int val = sec / UNIT[i];
            sprintf(timestr + len, "%d%s, ", val, UNIT_NAME[i]);
            len += strlen(timestr + len);
            sec %= UNIT[i];
        }
    }
    timestr[len - 2] = '\0';
    return timestr;
}

static int parse_attrs(const struct nlattr *attr, void *data) {

    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);
    tb[type] = attr;

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
        if (mark >= 1 && mark <= 40) {
            setmark = (mark == 1) ? 16 : mark + 1; // 不含 UA 的 HTTP 流量
        } else if (mark == 41) {
            setmark = 43; // 不含 UA 的连接
            ipset_parse_line(Pipset, addcmd); // 添加 IPSET 标记
        }
    } else if (mark != 44) {
        setmark = 44; // 含 UA 的流量
    }

    if (setmark) {
        nest = mnl_attr_nest_start(nlh, NFQA_CT);
        __builtin_prefetch(&mnl_attr_put_u32, 0, 3); // 预取下一条指令
        mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
        mnl_attr_nest_end(nlh, nest);

        // 记录标记数量
        if (setmark == 43) {
            noUAmark++;
        } else if (setmark == 44) {
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
    size_t uaoffset = 0;
    size_t ualength = 0;
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
        struct nlattr *ctattr[CTA_MAX+1] = {0};
        struct nlattr *originattr[CTA_TUPLE_MAX+1] = {0};
        struct nlattr *portattr[CTA_PROTO_MAX+1] = {0};

        if (mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctattr) < 0) {
            perror("Failed to parse NFQA_CT attribute");
            return;
        }

        uint32_t tmp_mark = 0;
        if (ctattr[CTA_MARK]) {
            tmp_mark = ntohl(mnl_attr_get_u32(ctattr[CTA_MARK]));
        }
        mark = tmp_mark ? tmp_mark : 1; // no mark 1

        char tmp_ip[INET_ADDRSTRLEN];
        if (ctattr[CTA_TUPLE_ORIG] &&
            mnl_attr_parse_nested(ctattr[CTA_TUPLE_ORIG], parse_attrs, originattr) >= 0 &&
            originattr[CTA_TUPLE_IP] &&
            mnl_attr_parse_nested(originattr[CTA_TUPLE_IP], parse_attrs, &portattr) >= 0 &&
            portattr && mnl_attr_get_type(portattr) == CTA_IP_V4_DST &&
            portattr[CTA_IP_V4_DST]) {
            uint32_t tmp = mnl_attr_get_u32(portattr[CTA_IP_V4_DST]);
            struct in_addr tmp2 = {.s_addr = tmp};
            inet_ntop(AF_INET, &tmp2, tmp_ip, INET_ADDRSTRLEN);
            port = ntohs(mnl_attr_get_u16(portattr[CTA_PROTO_DST_PORT]));
            strncpy(ip, tmp_ip, sizeof(ip));
            snprintf(addcmd, sizeof(addcmd), "add nohttp %s,%d", ip, port);
        } else {
            fprintf(stderr, "Failed to find valid IP address or protocol attributes\n");
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

    if (tcppkpayload) {
        char *uapointer = tcppkpayload;
        size_t remaining_len = tcppklen;
        while (true) {
            uapointer = memncasemem(uapointer, remaining_len, "\r\nUser-Agent: ", 14);
            if (!uapointer) {
                noUA = true;
                break;
            }
            uaoffset = uapointer - tcppkpayload + 14; // 计算在 TCP 数据包中的偏移量
            uapointer += 14;
            remaining_len = tcppklen - uaoffset - 2;
            char *endpointer = memchr(uapointer, '\r', remaining_len); // 找到 UA 字符串的结尾
            if (endpointer == NULL) {
                syslog(LOG_WARNING, "User-Agent has no content");
                nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA, addcmd);
                return MNL_CB_OK;
            }
            ualength = endpointer - uapointer;
            if (nfq_tcp_mangle_ipv4(pktb, uaoffset, ualength, UAstr, ualength) == 1) {
                UAcount++; // 记录修改包的数量
            } else {
                syslog(LOG_ERR, "Mangle packet failed.");
                pktb_free(pktb);
                return MNL_CB_ERROR;
            }
            uapointer = endpointer;
            remaining_len = tcppklen - (uapointer - tcppkpayload);
        }
    }

    nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA, addcmd);

    if (UAcount / httpcount == 2 || UAcount - httpcount >= 8192) {
        httpcount = UAcount;
        current_t = time(NULL);
        char *timestr = time2str((int) difftime(current_t, start_t));
        syslog(LOG_INFO,
               "UA2F has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s",
               UAcount, tcpcount, UAmark, noUAmark, timestr);
    }
    return MNL_CB_OK;
}

int ua2f_processor(unsigned int error_limit) {
    unsigned int errcount = 0;
    for (; errcount <= error_limit; ++errcount) {
        pid_t child_pid = fork();
        if (child_pid == -1) {
            perror("Failed to create child process");
            exit(EXIT_FAILURE);
        }
        if (child_pid == 0) {
            printf("UA2F processor started at [%d]\n", getpid());
            return 0;
        } else {
            int status;
            if (waitpid(child_pid, &status, 0) == -1) {
                perror("Child process terminated unexpectedly");
            } else {
                if (WIFEXITED(status)) {
                    printf("Child process exited with status %d\n", WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    printf("Child process was terminated by signal %d: %s\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
                }
            }
        }
    }
    printf("Too many errors occurred, no longer trying to recover.\n");
    exit(EXIT_FAILURE);
}

void recv_and_process_messages(int nl, char* buf, size_t sizeof_buf, unsigned int portid) {
    while (true) {
        ssize_t ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) { //stop at failure
            perror("Failed to receive message from netlink socket");
            exit(EXIT_FAILURE);
        }

        ret = mnl_cb_run(buf, ret, 0, portid, (mnl_cb_t) queue_cb, NULL);
        if (ret < 0) { //stop at failure
            perror("Failed to process message with netlink callback");
            exit(EXIT_FAILURE);
        }
    }
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

    signal(SIGTERM, killChild);

    ua2f_processor(10);

    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    start_t = time(NULL);

    ipset_load_types();
    Pipset = ipset_init();

    if (!Pipset) {
        printf("Pipset not inited.\n");
        exit(EXIT_FAILURE);
    }

    ipset_custom_printf(Pipset, func, func2, func3, NULL); // hook 掉退出的输出函数

    syslog(LOG_NOTICE, "Pipset inited.");

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == NULL) {
        perror("mnl_socket_open");
        printf("Exit at mnl_socket_open.\n");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        printf("Exit at mnl_socket_bind.\n");
        exit(EXIT_FAILURE);
    }
    
    portid = mnl_socket_get_portid(nl);

    buf = malloc(sizeof_buf);
    
    if (!buf) {
        perror("allocate receive buffer");
        printf("Exit at breakpoint 6.\n");
        exit(EXIT_FAILURE);
    }

    UAstr = malloc(sizeof_buf);
    memset(UAstr, ' ', sizeof_buf); // 先替换原始UA参数为空格
    // 在需要使用该字符串时直接引用COMMON_UA即可
    memcpy(UAstr, COMMON_UA, sizeof(COMMON_UA) - 1);

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        printf("Exit at breakpoint 7.\n");
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
        printf("Exit at mnl_socket_send.\n");
        exit(EXIT_FAILURE);
    }

    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    syslog(LOG_NOTICE, "UA2F has inited successful.");

    recv_and_process_messages(nl, buf, sizeof_buf, portid);
}
