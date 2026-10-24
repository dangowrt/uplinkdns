#define _DEFAULT_SOURCE

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "internal.h"

#define RESOLV_CONF_PATH "/etc/resolv.conf"

struct watch {
	struct uplink *up;
	unsigned int events;
	ares_socket_t fd;
};

union notify_buf {
	struct inotify_event event;
	char bytes[sizeof(struct inotify_event) + NAME_MAX + 1];
};

struct lookup {
	struct ares_addrinfo *result;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int status;
	bool done;
};

static pthread_mutex_t watch_lock = PTHREAD_MUTEX_INITIALIZER;
static struct watch *watches;
static size_t watch_count;
static bool thread_running;
static int notify_fd = -1;
static int wake_fd = -1;

static void resolver_wake(void)
{
	uint64_t one = 1;
	ssize_t ret;

	if (wake_fd < 0)
		return;

	do {
		ret = write(wake_fd, &one, sizeof(one));
	} while (ret < 0 && errno == EINTR);
}

static void watch_remove_locked(size_t i)
{
	watches[i] = watches[--watch_count];
}

static void watch_append_locked(struct uplink *up, ares_socket_t fd,
				unsigned int events)
{
	struct watch *grown;

	grown = realloc(watches, (watch_count + 1) * sizeof(*watches));
	if (!grown)
		return;

	watches = grown;
	watches[watch_count].up = up;
	watches[watch_count].fd = fd;
	watches[watch_count].events = events;
	watch_count++;
}

static void watch_update(void *data, ares_socket_t fd, int readable,
			 int writable)
{
	unsigned int events = 0;
	size_t i;

	if (readable)
		events |= ARES_FD_EVENT_READ;
	if (writable)
		events |= ARES_FD_EVENT_WRITE;

	pthread_mutex_lock(&watch_lock);

	for (i = 0; i < watch_count; i++) {
		if (watches[i].fd == fd)
			break;
	}

	if (i < watch_count && !events)
		watch_remove_locked(i);
	else if (i < watch_count)
		watches[i].events = events;
	else if (events)
		watch_append_locked(data, fd, events);

	pthread_mutex_unlock(&watch_lock);
	resolver_wake();
}

static struct watch *watches_copy(size_t *count)
{
	struct watch *copy;

	pthread_mutex_lock(&watch_lock);

	copy = malloc((watch_count ? watch_count : 1) * sizeof(*copy));
	*count = copy ? watch_count : 0;
	if (copy)
		memcpy(copy, watches, watch_count * sizeof(*copy));

	pthread_mutex_unlock(&watch_lock);
	return copy;
}

static int timeout_get(struct uplink **ups, size_t count)
{
	struct timeval tv;
	int timeout = -1;
	size_t i;
	long ms;

	for (i = 0; i < count; i++) {
		if (!ares_timeout(ups[i]->channel, NULL, &tv))
			continue;

		ms = tv.tv_sec * 1000 + (tv.tv_usec + 999) / 1000;
		if (timeout < 0 || ms < timeout)
			timeout = (int)ms;
	}

	return timeout;
}

static void channel_process(struct uplink *up, const struct watch *ws,
			    const struct pollfd *pfds, size_t count)
{
	ares_fd_events_t *events;
	size_t n = 0;
	size_t i;

	events = malloc((count ? count : 1) * sizeof(*events));
	if (!events)
		return;

	for (i = 0; i < count; i++) {
		if (ws[i].up != up || !pfds[i].revents)
			continue;

		events[n].fd = ws[i].fd;
		events[n].events = 0;
		if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP))
			events[n].events |= ARES_FD_EVENT_READ;
		if (pfds[i].revents & POLLOUT)
			events[n].events |= ARES_FD_EVENT_WRITE;
		n++;
	}

	ares_process_fds(up->channel, n ? events : NULL, n,
			 ARES_PROCESS_FLAG_NONE);
	free(events);
}

static void notify_setup(void)
{
	char path[PATH_MAX];

	if (!realpath(RESOLV_CONF_PATH, path))
		return;

	notify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (notify_fd < 0)
		return;

	if (inotify_add_watch(notify_fd, dirname(path), IN_CLOSE_WRITE |
			      IN_MOVED_TO | IN_CREATE | IN_DELETE) >= 0)
		return;

	close(notify_fd);
	notify_fd = -1;
}

static void notify_handle(struct uplink **ups, size_t count)
{
	union notify_buf buf;
	size_t i;

	while (read(notify_fd, &buf, sizeof(buf)) > 0)
		;

	for (i = 0; i < count; i++) {
		if (uplink_system_servers(ups[i]))
			ares_reinit(ups[i]->channel);
	}
}

static void wake_drain(void)
{
	uint64_t value;

	while (read(wake_fd, &value, sizeof(value)) > 0)
		;
}

static void resolver_iterate(void)
{
	struct pollfd *pfds = NULL;
	struct uplink **ups;
	struct watch *ws;
	size_t nups = 0;
	size_t count;
	size_t i;

	ws = watches_copy(&count);
	ups = uplink_channels_get(&nups);
	if (ws && ups)
		pfds = calloc(count + 2, sizeof(*pfds));

	if (!pfds) {
		count = 0;
		nups = 0;
		pfds = calloc(2, sizeof(*pfds));
		if (!pfds)
			goto out;
	}

	pfds[0].fd = wake_fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = notify_fd;
	pfds[1].events = POLLIN;
	for (i = 0; i < count; i++) {
		pfds[i + 2].fd = ws[i].fd;
		if (ws[i].events & ARES_FD_EVENT_READ)
			pfds[i + 2].events |= POLLIN;
		if (ws[i].events & ARES_FD_EVENT_WRITE)
			pfds[i + 2].events |= POLLOUT;
	}

	if (poll(pfds, count + 2, timeout_get(ups, nups)) < 0)
		goto out;

	if (pfds[0].revents & POLLIN)
		wake_drain();
	if (pfds[1].revents & POLLIN)
		notify_handle(ups, nups);

	for (i = 0; i < nups; i++)
		channel_process(ups[i], ws, pfds + 2, count);

out:
	free(pfds);
	free(ups);
	free(ws);
}

static void *resolver_main(void *arg)
{
	(void)arg;

	for (;;)
		resolver_iterate();

	return NULL;
}

static int resolver_start_locked(void)
{
	pthread_t thread;
	sigset_t blocked;
	sigset_t saved;
	int ret;

	if (thread_running)
		return 0;

	wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (wake_fd < 0)
		return -errno;

	notify_setup();

	sigfillset(&blocked);
	pthread_sigmask(SIG_SETMASK, &blocked, &saved);
	ret = pthread_create(&thread, NULL, resolver_main, NULL);
	pthread_sigmask(SIG_SETMASK, &saved, NULL);
	if (ret) {
		close(wake_fd);
		wake_fd = -1;
		return -ret;
	}

	pthread_detach(thread);
	thread_running = true;
	return 0;
}

static int socket_configure(ares_socket_t fd, int type, void *data)
{
	struct sockaddr_storage ss;
	struct uplink *up = data;
	socklen_t len;
	int family;

	(void)type;
	if (up->ifname[0]) {
		if (!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, up->ifname,
				(socklen_t)strlen(up->ifname)))
			return ARES_SUCCESS;

		debug_log("%s: SO_BINDTODEVICE: %s", up->key, strerror(errno));
		return -1;
	}

	family = AF_UNSPEC;
	len = sizeof(family);
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &family, &len) ||
	    !uplink_source_get(up, family, &ss)) {
		debug_log("%s: no source address for family %d", up->key,
			  family);
		return -1;
	}

	len = family == AF_INET ? sizeof(struct sockaddr_in) :
				  sizeof(struct sockaddr_in6);
	if (real.bind(fd, (struct sockaddr *)&ss, len)) {
		debug_log("%s: bind: %s", up->key, strerror(errno));
		return -1;
	}

	return ARES_SUCCESS;
}

int resolver_channel_create(struct uplink *up)
{
	struct ares_options opts;
	ares_channel_t *channel;
	int ret;

	ret = resolver_start_locked();
	if (ret)
		return ret;

	memset(&opts, 0, sizeof(opts));
	opts.sock_state_cb = watch_update;
	opts.sock_state_cb_data = up;
	if (ares_init_options(&channel, &opts, ARES_OPT_SOCK_STATE_CB) !=
	    ARES_SUCCESS)
		return -EIO;

	if (up->servers &&
	    ares_set_servers_csv(channel, up->servers) != ARES_SUCCESS) {
		ares_destroy(channel);
		return -EINVAL;
	}

	ares_set_socket_configure_callback(channel, socket_configure, up);
	up->channel = channel;

	return 0;
}

void resolver_servers_set(struct uplink *up)
{
	if (ares_set_servers_csv(up->channel, up->servers) != ARES_SUCCESS)
		debug_log("%s: invalid servers '%s'", up->key, up->servers);
}

static void lookup_done(void *arg, int status, int timeouts,
			struct ares_addrinfo *result)
{
	struct lookup *lk = arg;

	(void)timeouts;
	pthread_mutex_lock(&lk->lock);
	lk->status = status;
	lk->result = result;
	lk->done = true;
	pthread_cond_signal(&lk->cond);
	pthread_mutex_unlock(&lk->lock);
}

static int status_to_eai(int status)
{
	switch (status) {
	case ARES_SUCCESS:
		return 0;
	case ARES_ENOTFOUND:
	case ARES_ENODATA:
	case ARES_EBADNAME:
		return EAI_NONAME;
	case ARES_ENOMEM:
		return EAI_MEMORY;
	case ARES_ENOTIMP:
		return EAI_FAMILY;
	case ARES_ETIMEOUT:
	case ARES_ECONNREFUSED:
	case ARES_ESERVFAIL:
	case ARES_EREFUSED:
		return EAI_AGAIN;
	default:
		return EAI_FAIL;
	}
}

void addr_list_free(struct addr_list *list)
{
	free(list->addrs);
	list->addrs = NULL;
	list->count = 0;
}

static int canon_set(char **canon, const char *name)
{
	*canon = strdup(name ? name : "");
	return *canon ? 0 : EAI_MEMORY;
}

static int result_convert(const struct ares_addrinfo *res,
			  struct addr_list *list, char **canon)
{
	const struct ares_addrinfo_cname *cname;
	const struct ares_addrinfo_node *node;
	size_t count = 0;
	int ret;

	for (node = res->nodes; node; node = node->ai_next)
		count++;

	if (!count)
		return EAI_NONAME;

	list->addrs = calloc(count, sizeof(*list->addrs));
	if (!list->addrs)
		return EAI_MEMORY;

	for (node = res->nodes; node; node = node->ai_next) {
		if (node->ai_addrlen > sizeof(*list->addrs))
			continue;

		memcpy(&list->addrs[list->count++], node->ai_addr,
		       node->ai_addrlen);
	}

	if (!list->count) {
		addr_list_free(list);
		return EAI_NONAME;
	}

	if (!canon)
		return 0;

	for (cname = res->cnames; cname && cname->next; cname = cname->next)
		;

	ret = canon_set(canon, cname ? cname->name : res->name);
	if (ret)
		addr_list_free(list);

	return ret;
}

static void lookup_wait(struct lookup *lk)
{
	pthread_mutex_lock(&lk->lock);
	while (!lk->done)
		pthread_cond_wait(&lk->cond, &lk->lock);
	pthread_mutex_unlock(&lk->lock);
}

int resolver_lookup(struct uplink *up, const char *name, int family,
		    struct addr_list *list, char **canon)
{
	struct ares_addrinfo_hints hints;
	int cancel_state;
	struct lookup lk;
	int ret;

	memset(list, 0, sizeof(*list));
	ret = uplink_channel_ensure(up);
	if (ret) {
		errno = -ret;
		return EAI_SYSTEM;
	}

	memset(&lk, 0, sizeof(lk));
	pthread_mutex_init(&lk.lock, NULL);
	pthread_cond_init(&lk.cond, NULL);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = canon ? ARES_AI_CANONNAME : 0;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	ares_getaddrinfo(up->channel, name, NULL, &hints, lookup_done, &lk);
	resolver_wake();
	lookup_wait(&lk);
	pthread_setcancelstate(cancel_state, NULL);

	pthread_cond_destroy(&lk.cond);
	pthread_mutex_destroy(&lk.lock);

	ret = status_to_eai(lk.status);
	if (!ret)
		ret = result_convert(lk.result, list, canon);
	if (lk.result)
		ares_freeaddrinfo(lk.result);

	debug_log("lookup %s family %d via %s: %s", name, family, up->key,
		  ret ? ares_strerror(lk.status) : "ok");
	return ret;
}

int system_lookup(const char *name, int family, struct addr_list *list,
		  char **canon)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *ai;
	size_t count = 0;
	int ret;

	memset(list, 0, sizeof(*list));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = canon ? AI_CANONNAME : 0;

	ret = real.getaddrinfo(name, NULL, &hints, &res);
	if (ret)
		return ret;

	for (ai = res; ai; ai = ai->ai_next)
		count++;

	list->addrs = calloc(count ? count : 1, sizeof(*list->addrs));
	if (!list->addrs) {
		real.freeaddrinfo(res);
		return EAI_MEMORY;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_addrlen > sizeof(*list->addrs))
			continue;

		memcpy(&list->addrs[list->count++], ai->ai_addr, ai->ai_addrlen);
	}

	ret = list->count ? 0 : EAI_NONAME;
	if (!ret && canon)
		ret = canon_set(canon, res->ai_canonname ? res->ai_canonname :
							   name);
	if (ret)
		addr_list_free(list);

	real.freeaddrinfo(res);
	debug_log("lookup %s family %d via system: %s", name, family,
		  ret ? "failed" : "ok");
	return ret;
}

void resolver_fork_prepare(void)
{
	pthread_mutex_lock(&watch_lock);
}

void resolver_fork_parent(void)
{
	pthread_mutex_unlock(&watch_lock);
}

void resolver_fork_child(void)
{
	watch_count = 0;
	thread_running = false;
	if (wake_fd >= 0)
		close(wake_fd);
	if (notify_fd >= 0)
		close(notify_fd);
	wake_fd = -1;
	notify_fd = -1;

	pthread_mutex_unlock(&watch_lock);
}
