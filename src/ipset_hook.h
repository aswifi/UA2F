#include <libipset/ipset.h>

#ifndef UA2F_IPSET_HOOK_H
#define UA2F_IPSET_HOOK_H

int func(struct ipset *ipset, void *p, int status, const char *msg, ...);
int func2(struct ipset *ipset, void *p);
int func3(struct ipset_session *session, void *p, const char *fmt, ...);

#endif //UA2F_IPSET_HOOK_H
