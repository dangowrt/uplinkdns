# uplinkdns

uplinkdns resolves hostnames through the uplink a socket is bound to.

A program that pins its connections to an interface (`SO_BINDTODEVICE`) or
to a source address still resolves names through the system resolver, so
the lookup leaves through whatever the main routing table says and is
answered by the system's DNS server. Content delivery networks pick their
edge by the resolver's location, so a connection pinned to a tunnel ends
up talking to an edge chosen for the other uplink.

uplinkdns is a shared library that interposes the libc resolver and socket
entry points. It works with any library in the process (libcurl, FFmpeg,
GLib/libsoup, CPython, ...) without changes to them, on glibc and on musl.

## How it works

`getaddrinfo()` hands out synthetic addresses for a hostname: one from
198.18.0.0/15 (RFC 2544) for IPv4 and two from a random per-process ULA
/48 (RFC 4193) for IPv6, one standing for the name's AAAA records and one
for its A records as IPv4-mapped addresses. The interposed `connect()`,
`sendto()`, `sendmsg()` and `sendmmsg()` recognise a synthetic
destination, look at the socket's binding and resolve the name there:

- bound to a device: through that device's uplink;
- bound to a source address: through the uplink whose address or prefix
  contains it, or the interface that holds it;
- unbound: through the system resolver.

The connection then goes to the real address, with the caller's port. A
name with several addresses rotates through them on successive connects.
`getnameinfo()` maps a synthetic address back to its name.

The older netdb calls work the same way: `gethostbyname()`,
`gethostbyname2()` and their `_r` forms hand out synthetic addresses, and
`gethostbyaddr()` maps one back to its name.

Lookups for an uplink run on c-ares, from a socket bound to the uplink's
device or source address. If that binding fails, the query is not sent:
lookups for a pinned socket never fall back to another uplink. The c-ares
query cache honours the answers' TTL per uplink.

Code that knows its uplink when it resolves can skip the synthetic
addresses with the explicit API below and gets real addresses and normal
error codes right away.

## Uplinks

An uplink is specified as

    <interface | address | address/prefix>[;dns=<server>[,<server>...]]

for example `wg0;dns=1.1.1.1,2606:4700:4700::1111` or
`192.168.5.0/24;dns=192.168.5.1`. The server list uses the c-ares
nameserver syntax (`ip[:port]`, `[ipv6]:port`). Without `dns=`, the
uplink uses the servers from `/etc/resolv.conf`, still reached through the
uplink.

Uplinks come from the environment variable `UPLINKDNS_UPLINKS`, a
whitespace-separated list of specifications, or from
`uplinkdns_uplink_add()`. Deferred resolution is active only once at least
one uplink is registered; until then the library passes every call
through.

An interface uplink follows the interface's addresses: the kernel picks the
current source address for each connection and each query, for IPv4 and
IPv6 alike.

## API

```c
#include <uplinkdns.h>

int uplinkdns_uplink_add(const char *spec);
int uplinkdns_context_set(int ctx);
int uplinkdns_context_get(void);
int uplinkdns_getaddrinfo(int ctx, const char *node, const char *service,
			  const struct addrinfo *hints,
			  struct addrinfo **res);
void uplinkdns_freeaddrinfo(struct addrinfo *res);
int uplinkdns_name_get(const struct sockaddr *sa, socklen_t salen,
		       char *name, size_t len);
```

`uplinkdns_uplink_add()` returns the uplink's id, or a negative errno.
Adding the same key again returns the same id and updates its servers. A
bare address without a key of its own returns the most specific registered
uplink whose prefix contains it, as a socket bound to that address gets.

The context is per thread and decides what `getaddrinfo()` does in it:

- `UPLINKDNS_CTX_DEFER` (the default): synthetic addresses, resolved at
  connect time;
- `UPLINKDNS_CTX_SYSTEM`: the system resolver, real addresses;
- an uplink id: real addresses resolved through that uplink.

`uplinkdns_context_set()` returns the previous context, or `-EINVAL` for
an unknown id.

An uplink context also covers the lookups that have no socket to go by:
reverse lookups through `getnameinfo()` and `gethostbyaddr()`, and raw
queries through `res_query()`, `res_search()`, `res_querydomain()` and
`res_send()`, with glibc's `res_n*()` forms, run through that uplink. In
the other contexts they go to libc.

On glibc, `getaddrinfo_a()` runs its requests on threads that take over
the caller's context, and `gai_error()`, `gai_suspend()` and
`gai_cancel()` work on those requests. `rcmd()`, `rexec()` and the
`getnetby*()` lookups resolve inside glibc, out of the library's reach, so
they fail while the thread's context names an uplink.

`uplinkdns_name_get()` writes the hostname a synthetic address stands for
and returns 0, or `-ENOENT` for any other address. It never sends a query,
so it suits code that decides by name whether a destination is local.

## Loading

The library has to come before libc in symbol lookup order: either
`LD_PRELOAD=libuplinkdns.so.0`, or linked as a dependency of the
executable. `UPLINKDNS_SONAME` in the header names the library for a
program that preloads it into processes it starts. Results from `getaddrinfo()` must be freed with
`freeaddrinfo()` of the same process image, which is the interposed one.

`UPLINKDNS_DEBUG=1` prints each decision to stderr.

## Limits

- `AI_PASSIVE` lookups, numeric hosts and `localhost` names (RFC 6761) go
  straight to libc.
- A name that does not exist fails at connect time with `EHOSTUNREACH`;
  a resolver timeout fails with `ETIMEDOUT`.
- The first connect to a name on an uplink waits for that uplink's
  resolver, also on a non-blocking socket.
- A synthetic address is only meaningful inside the process. Passed to
  another process, or used by code that makes its own system calls, it
  reaches nothing.
- On 32-bit glibc, a program built with a 64-bit `time_t` sends through
  `__sendmsg64()` and `__sendmmsg64()`, which are not interposed.
- A synthetic address of a family the socket's uplink has no address for,
  IPv6 on an uplink with only a link-local IPv6 address for example, fails
  at connect time with `ENETUNREACH` and sends no query.
- IPv4 synthetic addresses are recycled least recently used once all of
  198.18.0.0/15 is in use; IPv6 ones are never reused.

## Building

    cmake -S . -B build
    cmake --build build

Requires c-ares 1.34 or newer built with thread support.

## Tests

    python3 -I tests/run.py build/libuplinkdns.so

The tests run on the loopback interface only: a small DNS responder and
echo listeners in one process, the client with the library preloaded in
another. One check runs in a network namespace of its own, as root or in a
user namespace, to give an uplink no addresses at all.
