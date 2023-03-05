#include <libipset/ipset.h>

#ifndef UA2F_IPSET_HOOK_H
#define UA2F_IPSET_HOOK_H

/* ���� */
#define MAX_ENTRIES 1000

/* �ṹ�� */
struct ipset_entry {
    char ip_address[20];
    int port;
};

/* �������� */
int func(struct ipset *ipset, void *p, int status, const char *msg, ...);
int func2(struct ipset *ipset, void *p);
int func3(struct ipset_session *session, void *p, const char *fmt, ...);
void process_entries(struct ipset_entry *entries, int num_entries);

#endif /* UA2F_IPSET_HOOK_H */