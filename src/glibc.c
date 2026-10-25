/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "internal.h"

#ifdef __GLIBC__

#define NSEC_PER_SEC 1000000000L

struct async_batch {
	struct sigevent sev;
	size_t pending;
	bool notify;
	bool waited;
};

struct async_job {
	struct async_batch *batch;
	struct gaicb *req;
	int ctx;
};

struct async_notify {
	void (*func)(union sigval value);
	union sigval value;
};

static struct {
	int (*rcmd_af)(char **ahost, unsigned short port, const char *locuser,
		       const char *remuser, const char *cmd, int *fd2p,
		       sa_family_t af);
	int (*rexec_af)(char **ahost, int port, const char *name,
			const char *pass, const char *cmd, int *fd2p,
			sa_family_t af);
	struct netent *(*getnetbyname)(const char *name);
	struct netent *(*getnetbyaddr)(uint32_t net, int type);
	int (*getnetbyname_r)(const char *name, struct netent *ne, char *buf,
			      size_t buflen, struct netent **result, int *err);
	int (*getnetbyaddr_r)(uint32_t net, int type, struct netent *ne,
			      char *buf, size_t buflen, struct netent **result,
			      int *err);
} netdb_real;

static pthread_once_t async_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t async_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t async_cond;
static size_t async_pending;

static void async_init(void)
{
	pthread_condattr_t attr;

	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&async_cond, &attr);
	pthread_condattr_destroy(&attr);

	netdb_real.rcmd_af = real_optional("rcmd_af", NULL);
	netdb_real.rexec_af = real_optional("rexec_af", NULL);
	netdb_real.getnetbyname = real_optional("getnetbyname", NULL);
	netdb_real.getnetbyaddr = real_optional("getnetbyaddr", NULL);
	netdb_real.getnetbyname_r = real_optional("getnetbyname_r", NULL);
	netdb_real.getnetbyaddr_r = real_optional("getnetbyaddr_r", NULL);
}

static void async_setup(void)
{
	real_init();
	pthread_once(&async_once, async_init);
}

static void *notify_main(void *arg)
{
	struct async_notify *notify = arg;

	notify->func(notify->value);
	free(notify);
	return NULL;
}

static void notify_thread(const struct sigevent *sev)
{
	struct async_notify *notify;
	pthread_attr_t attr;
	pthread_t thread;
	int ret;

	notify = malloc(sizeof(*notify));
	if (!notify)
		return;

	notify->func = sev->sigev_notify_function;
	notify->value = sev->sigev_value;
	if (sev->sigev_notify_attributes) {
		ret = pthread_create(&thread, sev->sigev_notify_attributes,
				     notify_main, notify);
	} else {
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		ret = pthread_create(&thread, &attr, notify_main, notify);
		pthread_attr_destroy(&attr);
	}

	if (ret)
		free(notify);
}

static void batch_notify(const struct sigevent *sev)
{
	siginfo_t info;

	if (sev->sigev_notify == SIGEV_THREAD) {
		notify_thread(sev);
		return;
	}

	if (sev->sigev_notify != SIGEV_SIGNAL)
		return;

	memset(&info, 0, sizeof(info));
	info.si_signo = sev->sigev_signo;
	info.si_code = SI_ASYNCNL;
	info.si_pid = getpid();
	info.si_uid = getuid();
	info.si_value = sev->sigev_value;
	syscall(SYS_rt_sigqueueinfo, getpid(), sev->sigev_signo, &info);
}

static void *job_main(void *arg)
{
	struct async_batch *batch;
	struct async_job *job;
	struct addrinfo *res;
	struct gaicb *req;
	bool finished;
	int ret;

	job = arg;
	batch = job->batch;
	req = job->req;
	res = NULL;
	context_put(job->ctx);
	ret = addrinfo_resolve(job->ctx, req->ar_name, req->ar_service,
			       req->ar_request, &res);
	free(job);

	pthread_mutex_lock(&async_lock);
	req->ar_result = ret ? NULL : res;
	req->__return = ret;
	async_pending--;
	finished = !--batch->pending && !batch->waited;
	pthread_cond_broadcast(&async_cond);
	pthread_mutex_unlock(&async_lock);

	if (!finished)
		return NULL;

	if (batch->notify)
		batch_notify(&batch->sev);
	free(batch);
	return NULL;
}

static int job_start(struct async_batch *batch, struct gaicb *req)
{
	struct async_job *job;
	pthread_attr_t attr;
	pthread_t thread;
	sigset_t blocked;
	sigset_t saved;
	int ret;

	job = malloc(sizeof(*job));
	if (!job) {
		req->__return = EAI_MEMORY;
		return -1;
	}

	job->batch = batch;
	job->req = req;
	job->ctx = context_get();
	req->ar_result = NULL;
	req->__return = EAI_INPROGRESS;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	sigfillset(&blocked);
	pthread_sigmask(SIG_SETMASK, &blocked, &saved);
	ret = pthread_create(&thread, &attr, job_main, job);
	pthread_sigmask(SIG_SETMASK, &saved, NULL);
	pthread_attr_destroy(&attr);
	if (ret) {
		free(job);
		req->__return = EAI_AGAIN;
		return -1;
	}

	batch->pending++;
	async_pending++;
	return 0;
}

UPLINKDNS_EXPORT int getaddrinfo_a(int mode, struct gaicb *list[], int nitems,
				   struct sigevent *sevp)
{
	struct async_batch *batch;
	int ret = 0;
	int i;

	async_setup();
	if (mode != GAI_WAIT && mode != GAI_NOWAIT) {
		errno = EINVAL;
		return EAI_SYSTEM;
	}

	batch = calloc(1, sizeof(*batch));
	if (!batch)
		return EAI_MEMORY;

	batch->waited = mode == GAI_WAIT;
	if (mode == GAI_NOWAIT && sevp) {
		batch->sev = *sevp;
		batch->notify = true;
	}

	pthread_mutex_lock(&async_lock);
	for (i = 0; i < nitems; i++) {
		if (list[i] && job_start(batch, list[i]))
			ret = EAI_AGAIN;
	}

	if (batch->pending && !batch->waited) {
		pthread_mutex_unlock(&async_lock);
		return ret;
	}

	while (batch->pending)
		pthread_cond_wait(&async_cond, &async_lock);
	pthread_mutex_unlock(&async_lock);

	free(batch);
	return ret;
}

UPLINKDNS_EXPORT int gai_error(struct gaicb *req)
{
	int ret;

	async_setup();
	pthread_mutex_lock(&async_lock);
	ret = req->__return;
	pthread_mutex_unlock(&async_lock);

	return ret;
}

UPLINKDNS_EXPORT int gai_cancel(struct gaicb *req)
{
	int ret;

	async_setup();
	pthread_mutex_lock(&async_lock);
	if (req)
		ret = req->__return == EAI_INPROGRESS ? EAI_NOTCANCELED :
							EAI_ALLDONE;
	else
		ret = async_pending ? EAI_NOTCANCELED : EAI_ALLDONE;
	pthread_mutex_unlock(&async_lock);

	return ret;
}

static int suspend_state(const struct gaicb *const list[], int nitems)
{
	bool listed = false;
	int i;

	for (i = 0; i < nitems; i++) {
		if (!list[i])
			continue;

		if (list[i]->__return != EAI_INPROGRESS)
			return 0;

		listed = true;
	}

	return listed ? EAI_INPROGRESS : EAI_ALLDONE;
}

static void deadline_get(struct timespec *deadline,
			 const struct timespec *timeout)
{
	clock_gettime(CLOCK_MONOTONIC, deadline);
	deadline->tv_sec += timeout->tv_sec;
	deadline->tv_nsec += timeout->tv_nsec;
	if (deadline->tv_nsec >= NSEC_PER_SEC) {
		deadline->tv_sec++;
		deadline->tv_nsec -= NSEC_PER_SEC;
	}
}

UPLINKDNS_EXPORT int gai_suspend(const struct gaicb *const list[], int nitems,
				 const struct timespec *timeout)
{
	struct timespec deadline;
	bool expired = false;
	int ret;

	async_setup();
	if (timeout)
		deadline_get(&deadline, timeout);

	pthread_mutex_lock(&async_lock);
	ret = suspend_state(list, nitems);
	while (ret == EAI_INPROGRESS && !expired) {
		if (!timeout)
			pthread_cond_wait(&async_cond, &async_lock);
		else if (pthread_cond_timedwait(&async_cond, &async_lock,
						&deadline) == ETIMEDOUT)
			expired = true;

		ret = suspend_state(list, nitems);
	}
	pthread_mutex_unlock(&async_lock);

	return ret == EAI_INPROGRESS ? EAI_AGAIN : ret;
}

/* glibc resolves the host of these internally, past the interposer */
UPLINKDNS_EXPORT int rcmd_af(char **ahost, unsigned short port,
			     const char *locuser, const char *remuser,
			     const char *cmd, int *fd2p, sa_family_t af)
{
	async_setup();
	if (context_uplink() || !netdb_real.rcmd_af) {
		errno = EHOSTUNREACH;
		return -1;
	}

	return netdb_real.rcmd_af(ahost, port, locuser, remuser, cmd, fd2p,
				  af);
}

UPLINKDNS_EXPORT int rcmd(char **ahost, unsigned short port,
			  const char *locuser, const char *remuser,
			  const char *cmd, int *fd2p)
{
	return rcmd_af(ahost, port, locuser, remuser, cmd, fd2p, AF_INET);
}

UPLINKDNS_EXPORT int rexec_af(char **ahost, int port, const char *name,
			      const char *pass, const char *cmd, int *fd2p,
			      sa_family_t af)
{
	async_setup();
	if (context_uplink() || !netdb_real.rexec_af) {
		errno = EHOSTUNREACH;
		return -1;
	}

	return netdb_real.rexec_af(ahost, port, name, pass, cmd, fd2p, af);
}

UPLINKDNS_EXPORT int rexec(char **ahost, int port, const char *name,
			   const char *pass, const char *cmd, int *fd2p)
{
	return rexec_af(ahost, port, name, pass, cmd, fd2p, AF_INET);
}

UPLINKDNS_EXPORT struct netent *getnetbyname(const char *name)
{
	async_setup();
	if (context_uplink() || !netdb_real.getnetbyname) {
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}

	return netdb_real.getnetbyname(name);
}

UPLINKDNS_EXPORT struct netent *getnetbyaddr(uint32_t net, int type)
{
	async_setup();
	if (context_uplink() || !netdb_real.getnetbyaddr) {
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}

	return netdb_real.getnetbyaddr(net, type);
}

UPLINKDNS_EXPORT int getnetbyname_r(const char *name, struct netent *ne,
				    char *buf, size_t buflen,
				    struct netent **result, int *err)
{
	async_setup();
	if (context_uplink() || !netdb_real.getnetbyname_r) {
		*result = NULL;
		*err = HOST_NOT_FOUND;
		return ENOENT;
	}

	return netdb_real.getnetbyname_r(name, ne, buf, buflen, result, err);
}

UPLINKDNS_EXPORT int getnetbyaddr_r(uint32_t net, int type, struct netent *ne,
				    char *buf, size_t buflen,
				    struct netent **result, int *err)
{
	async_setup();
	if (context_uplink() || !netdb_real.getnetbyaddr_r) {
		*result = NULL;
		*err = HOST_NOT_FOUND;
		return ENOENT;
	}

	return netdb_real.getnetbyaddr_r(net, type, ne, buf, buflen, result,
					 err);
}
#endif
