#ifndef UPLINKDNS_H
#define UPLINKDNS_H

#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve hostnames at connect() time through the socket's uplink. */
#define UPLINKDNS_CTX_DEFER	(-1)
/* Resolve hostnames through the system resolver. */
#define UPLINKDNS_CTX_SYSTEM	(-2)

int uplinkdns_uplink_add(const char *spec);
int uplinkdns_context_set(int ctx);
int uplinkdns_context_get(void);
int uplinkdns_getaddrinfo(int ctx, const char *node, const char *service,
			  const struct addrinfo *hints,
			  struct addrinfo **res);
void uplinkdns_freeaddrinfo(struct addrinfo *res);
int uplinkdns_name_get(const struct sockaddr *sa, socklen_t salen,
		       char *name, size_t len);

#ifdef __cplusplus
}
#endif

#endif
