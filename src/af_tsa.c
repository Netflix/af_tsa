// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause-No-Nuclear-Warranty
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/syscall.h>
#include <linux/tracehook.h>
#include <linux/version.h>

#include "include/uapi/af_tsa.h"

MODULE_DESCRIPTION("AF TSA Family");
MODULE_AUTHOR("Sargun Dhillon <sargun@sargun.me>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS_NET_PF_PROTO_NAME(PF_NETLINK, NETLINK_GENERIC, TSA_GENL_NAME);

DEFINE_MUTEX(tsa_mutex);
static struct genl_family genl_family;

struct tsa_worker {
	struct list_head list;
	struct task_struct *task;
};

struct tsa_proto_ops {
	struct proto_ops real_ops;
	struct socket *realsock;
	struct socket *tsasock;
	struct module *owner;
	struct rcu_head task_rcu_head;
	struct work_struct work_close;
	struct work_struct work_shutdown;

	spinlock_t worker_lock;
	struct list_head workers;
	bool dying;
	bool shutdown;
};

static int __tsa_swap(struct net *net, struct socket *sock);

/*
 * TODO: If the TSA is dying, we should probably do something to stop the call.
 * Maybe return EINTR?
 */
static void tsa_worker_start(struct tsa_proto_ops *tops,
			     struct tsa_worker *worker)
{
	spin_lock(&tops->worker_lock);
	WARN_ON(tops->dying);
	worker->task = current;
	list_add(&worker->list, &tops->workers);
	spin_unlock(&tops->worker_lock);
}

static bool tsa_worker_end(struct tsa_proto_ops *tops,
			   struct tsa_worker *worker)
{
	bool dying;

	spin_lock(&tops->worker_lock);
	list_del(&worker->list);
	dying = tops->dying;
	if (dying && tops->shutdown && list_empty(&tops->workers))
		schedule_work(&tops->work_close);
	spin_unlock(&tops->worker_lock);

	return dying;
}

static int tsa_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->setsockopt(realsock, level, optname, optval,
					optlen);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->getsockopt(realsock, level, optname, optval,
					optlen);
	tsa_worker_end(tops, &worker);
	return ret;
}

static __poll_t tsa_poll(struct file *file, struct socket *sock, poll_table *p)
{
	/* TODO: Make it so when we swap out the sockets, we can properly *re-wake* out of this function */
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	__poll_t ret = 0;

	sock_poll_wait(file, sock, p);

	/* Wait to dereference the operations. There's a write memory barrier elsewhere to protect this. */
	smp_rmb();
	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);

	realsock = tops->realsock;
	ret = realsock->ops->poll(file, realsock, p);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_bind(struct socket *sock, struct sockaddr *myaddr,
		    int sockaddr_len)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->bind(realsock, myaddr, sockaddr_len);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_connect(struct socket *sock, struct sockaddr *vaddr,
		       int sockaddr_len, int flags)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->connect(realsock, vaddr, sockaddr_len, flags);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_accept(struct socket *sock, struct socket *newsock, int flags,
		      bool kern)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	module_put(newsock->ops->owner);
	newsock->ops = realsock->ops;
	__module_get(realsock->ops->owner);
	newsock->ops = realsock->ops;
	pr_warn("Running accept, newsock's file: %p\n", newsock->file);
	ret = realsock->ops->accept(realsock, newsock, flags, kern);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->getname(realsock, addr, peer);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_gettstamp(struct socket *sock, void __user *userstamp,
			 bool timeval, bool time32)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->gettstamp(realsock, userstamp, timeval, time32);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_listen(struct socket *sock, int len)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->listen(realsock, len);
	/* Shouldn't block? */
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_shutdown(struct socket *sock, int flags)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->shutdown(realsock, flags);
	/* Shouldn't block */
	tsa_worker_end(tops, &worker);
	return ret;
}

static void tsa_show_fdinfo(struct seq_file *m, struct socket *sock)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	realsock->ops->show_fdinfo(m, realsock);
	tsa_worker_end(tops, &worker);
}

static int tsa_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->sendmsg(realsock, m, total_len);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		       int flags)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->recvmsg(realsock, m, total_len, flags);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static ssize_t tsa_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->sendpage(realsock, page, offset, size, flags);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static ssize_t tsa_splice_read(struct socket *sock, loff_t *ppos,
			       struct pipe_inode_info *pipe, size_t len,
			       unsigned int flags)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	realsock = tops->realsock;
	ret = realsock->ops->splice_read(realsock, ppos, pipe, len, flags);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int __tsa_ioctl_swap(struct socket *sock, unsigned int cmd,
			    unsigned long arg)
{
	struct net *net;
	int ret;

	pr_info("Performing ioctl based swap on to ns %ld\n", arg);
	net = get_net_ns_by_fd(arg);
	if (IS_ERR(net))
		return PTR_ERR(net);

	ret = __tsa_swap(net, sock);

	put_net(net);
	return ret;
}

static int tsa_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	switch (cmd) {
	case SIOCTSASWAP:
		ret = __tsa_ioctl_swap(sock, cmd, arg);
		break;
	default:
		ret = realsock->ops->ioctl(realsock, cmd, arg);
	}
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_read_sock(struct sock *sk, read_descriptor_t *desc,
			 sk_read_actor_t recv_actor)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sk->sk_socket->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->read_sock(realsock->sk, desc, recv_actor);
	if (tsa_worker_end(tops, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_sendpage_locked(struct sock *sk, struct page *page, int offset,
			       size_t size, int flags)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sk->sk_socket->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->sendpage_locked(realsock->sk, page, offset, size,
					     flags);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sk->sk_socket->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->sendmsg_locked(realsock->sk, msg, size);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_set_rcvlowat(struct sock *sk, int val)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sk->sk_socket->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->set_rcvlowat(realsock->sk, val);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_set_peek_off(struct sock *sk, int val)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sk->sk_socket->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->set_peek_off(realsock->sk, val);
	tsa_worker_end(tops, &worker);
	return ret;
}

static int tsa_peek_len(struct socket *sock)
{
	const struct proto_ops *fake_ops;
	struct tsa_proto_ops *tops;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	fake_ops = sock->ops;
	tops = container_of(fake_ops, struct tsa_proto_ops, real_ops);
	tsa_worker_start(tops, &worker);
	realsock = tops->realsock;
	ret = realsock->ops->peek_len(realsock);
	tsa_worker_end(tops, &worker);
	return ret;
}

static void __tsa_close_cb(struct work_struct *wq)
{
	struct tsa_proto_ops *tops;

	tops = container_of(wq, struct tsa_proto_ops, work_close);
	pr_info("TSA Close CB called back on: %p\n", tops->realsock);
	sock_release(tops->realsock);
	module_put(tops->owner);
	kfree(tops);
}

static void __tsa_shutdown_cb(struct work_struct *wq)
{
	struct tsa_proto_ops *tops;

	tops = container_of(wq, struct tsa_proto_ops, work_shutdown);
	pr_info("TSA shutdown CB called back on: %p\n", tops->realsock);
	tops->realsock->ops->shutdown(tops->realsock, SHUT_RDWR);
	spin_lock(&tops->worker_lock);
	tops->shutdown = true;
	if (list_empty(&tops->workers))
		schedule_work(&tops->work_close);
	spin_unlock(&tops->worker_lock);
}

static void tsa_rcu_tasks_cb(struct rcu_head *head)
{
	struct tsa_proto_ops *tops;

	tops = container_of(head, struct tsa_proto_ops, task_rcu_head);
	pr_info("tsa_rcu_tasks_cb callback called on: %p\n", tops->realsock);
	spin_lock(&tops->worker_lock);
	tops->dying = true;
	spin_unlock(&tops->worker_lock);
	/* Shutdown must be called on a workqueue because it might block */
	schedule_work(&tops->work_shutdown);
}

/* This function may block */
static void start_release_old_tops(const struct proto_ops *ops)
{
	struct tsa_proto_ops *tops;

	tops = container_of(ops, struct tsa_proto_ops, real_ops);
	pr_info("Starting release of: %p\n", tops->realsock);
	WARN_ON(!tops->realsock);
	WARN_ON(!tops->realsock->file);
	tops->realsock->file = NULL;
	write_lock_bh(&tops->realsock->sk->sk_callback_lock);
	tops->realsock->sk->sk_wq = &tops->realsock->wq;
	write_unlock_bh(&tops->realsock->sk->sk_callback_lock);

	call_rcu_tasks(&tops->task_rcu_head, tsa_rcu_tasks_cb);
}

static int tsa_release(struct socket *sock)
{
	pr_info("TSA release of top level socket: %p\n", sock);
	start_release_old_tops(sock->ops);

	return 0;
}

/* There's not unwind code for this yet */
static int init_proto_ops(struct tsa_proto_ops *tops, struct socket *newsock)
{
	struct proto_ops *fake_real_ops = &tops->real_ops;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	pr_info("Creating underlying socket: %p\n", newsock);
	spin_lock_init(&tops->worker_lock);
	INIT_LIST_HEAD(&tops->workers);
	tops->dying = false;
	tops->shutdown = false;
	tops->owner = THIS_MODULE;

	fake_real_ops->family = newsock->ops->family;
	fake_real_ops->owner = THIS_MODULE;
	fake_real_ops->release = tsa_release;
	fake_real_ops->bind = tsa_bind;
	fake_real_ops->connect = tsa_connect;
	/* This is ugly. Let's not support anything that can do socketpair */
	fake_real_ops->socketpair = sock_no_socketpair;
	fake_real_ops->accept = tsa_accept;
	fake_real_ops->getname = tsa_getname;
	fake_real_ops->poll = tsa_poll;
	fake_real_ops->ioctl = tsa_ioctl;
	if (newsock->ops->gettstamp)
		fake_real_ops->gettstamp = tsa_gettstamp;
	fake_real_ops->listen = tsa_listen;
	fake_real_ops->shutdown = tsa_shutdown;
	fake_real_ops->setsockopt = tsa_setsockopt;
	fake_real_ops->getsockopt = tsa_getsockopt;
	if (newsock->ops->show_fdinfo)
		fake_real_ops->show_fdinfo = tsa_show_fdinfo;
	fake_real_ops->sendmsg = tsa_sendmsg;
	fake_real_ops->recvmsg = tsa_recvmsg;
	/* No supporting mmap, because that creates "interesting" problems if we release the underlying socket */
	fake_real_ops->mmap = sock_no_mmap;
	if (newsock->ops->sendpage)
		fake_real_ops->sendpage = tsa_sendpage;
	if (newsock->ops->splice_read)
		fake_real_ops->splice_read = tsa_splice_read;

	/* These are weird because they're not actually called through this layer. */

	if (newsock->ops->set_peek_off)
		fake_real_ops->set_peek_off = tsa_set_peek_off;
	if (newsock->ops->peek_len)
		fake_real_ops->peek_len = tsa_peek_len;
	if (newsock->ops->read_sock)
		fake_real_ops->read_sock = tsa_read_sock;
	if (newsock->ops->sendpage_locked)
		fake_real_ops->sendpage_locked = tsa_sendpage_locked;
	if (newsock->ops->sendmsg_locked)
		fake_real_ops->sendmsg_locked = tsa_sendmsg_locked;
	if (newsock->ops->set_rcvlowat)
		fake_real_ops->set_rcvlowat = tsa_set_rcvlowat;

	tops->realsock = newsock;
	init_rcu_head(&tops->task_rcu_head);
	INIT_WORK(&tops->work_close, __tsa_close_cb);
	INIT_WORK(&tops->work_shutdown, __tsa_shutdown_cb);

	return 0;
}

/* Underlying socket has to be a socket that was built in kernel, and is unused */
static int tsa_make_socket(struct socket *sock, struct socket *underlyingsock)
{
	const struct proto_ops *oldops;
	struct tsa_proto_ops *tops;
	int ret;

	WARN_ON(!sock);
	WARN_ON(!underlyingsock);
	WARN_ON(!underlyingsock->ops);

	oldops = sock->ops;
	tops = kzalloc(sizeof(*tops), GFP_KERNEL);
	if (!tops)
		return -ENOMEM;

	tops->tsasock = sock;
	underlyingsock->file = sock->file;
	ret = init_proto_ops(tops, underlyingsock);
	if (ret) {
		kfree(tops);
		return ret;
	}

	write_lock_bh(&underlyingsock->sk->sk_callback_lock);
	underlyingsock->sk->sk_wq = &sock->wq;
	write_unlock_bh(&underlyingsock->sk->sk_callback_lock);

	WRITE_ONCE(sock->sk, underlyingsock->sk);
	smp_wmb();
	WRITE_ONCE(sock->ops, &tops->real_ops);
	smp_wmb();
	/* Synchronization:
	1. First do tasks RCU, that way we know that all tasks are at a "safepoint"
	2. Wait for the refcnt to hit 0.
	3. SRCU callback
	 */
	if (oldops)
		start_release_old_tops(oldops);

	return 0;
}

const static enum sock_flags copied_bits[] = {
	SO_DEBUG,
	SO_REUSEADDR,
	SO_REUSEPORT,
	SO_DONTROUTE,
	SO_BROADCAST,
	SOCK_URGINLINE,
	SOCK_RXQ_OVFL,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_PASSCRED,
	SOCK_TSTAMP_NEW,
	SOCK_RCVTSTAMPNS,
	SOCK_RCVTSTAMP,
	SOCK_NOFCS,
	SOCK_WIFI_STATUS,
	SOCK_SELECT_ERR_QUEUE,
	SOCK_ZEROCOPY,
	/*
	 * Even those these have a more complicated implementation in sock.c, we can be lazy
	 * because effectively what it does is call net_enable_timestamp after timestamps
	 * are turned on.
	 */
	SOCK_TIMESTAMP,
	SOCK_TIMESTAMPING_RX_SOFTWARE,
	SOCK_FASYNC,
};

static void copy_sockopts(struct sock *oldsk, struct sock *newsk)
{
	enum sock_flags flag;
	int rcvlowat;
	bool val;
	int i;

	for (i = 0; i < ARRAY_SIZE(copied_bits); i++) {
		flag = copied_bits[i];
		val = sock_flag(oldsk, flag);
		if (val && flag == SOCK_KEEPOPEN && newsk->sk_prot->keepalive)
			newsk->sk_prot->keepalive(newsk, val);
		if (val && flag == SOCK_LINGER)
			newsk->sk_lingertime = oldsk->sk_lingertime;
		if (val && flag == SOCK_TXTIME) {
			newsk->sk_clockid = oldsk->sk_clockid;
			newsk->sk_txtime_deadline_mode =
				oldsk->sk_txtime_deadline_mode;
			newsk->sk_txtime_report_errors =
				oldsk->sk_txtime_report_errors;
		}
		/* We might be able to reduce the guarantees here and not require atomic ops */
		sock_valbool_flag(newsk, flag, val);
	}

	WRITE_ONCE(newsk->sk_sndbuf, READ_ONCE(oldsk->sk_sndbuf));
	WRITE_ONCE(newsk->sk_rcvbuf, READ_ONCE(oldsk->sk_rcvbuf));

	newsk->sk_userlocks |=
		oldsk->sk_userlocks & (SOCK_RCVBUF_LOCK | SOCK_SNDBUF_LOCK);
	newsk->sk_no_check_tx = oldsk->sk_no_check_tx;
	newsk->sk_priority = oldsk->sk_priority;
	newsk->sk_tsflags = oldsk->sk_tsflags;
	newsk->sk_tskey = oldsk->sk_tskey;

	rcvlowat = READ_ONCE(oldsk->sk_rcvlowat);
	if (rcvlowat != 1) {
		if (newsk->sk_socket->ops->set_rcvlowat)
			newsk->sk_socket->ops->set_rcvlowat(newsk, rcvlowat);
		else
			WRITE_ONCE(newsk->sk_rcvlowat, rcvlowat ?: 1);
	}

	newsk->sk_rcvtimeo = oldsk->sk_rcvtimeo;
	newsk->sk_sndtimeo = oldsk->sk_sndtimeo;
	/*
	 * Explicitly no support for BPF filters. Supporting them is too complicated right now.
	 * This includes:
	 * SO_ATTACH_FILTER
	 * SO_ATTACH_BPF
	 * SO_ATTACH_REUSEPORT_CBPF
	 * SO_ATTACH_REUSEPORT_EBPF
	 * SO_LOCK_FILTER
	 */

	if (oldsk->sk_socket->ops->set_peek_off &&
	    newsk->sk_socket->ops->set_peek_off)
		newsk->sk_socket->ops->set_peek_off(
			newsk, READ_ONCE(oldsk->sk_peek_off));

	WRITE_ONCE(newsk->sk_ll_usec, READ_ONCE(oldsk->sk_ll_usec));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
	WRITE_ONCE(newsk->sk_prefer_busy_poll,
		READ_ONCE(oldsk->sk_prefer_busy_poll));
	WRITE_ONCE(newsk->sk_busy_poll_budget,
		READ_ONCE(oldsk->sk_busy_poll_budget));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
#error "Untested kernel version"
#endif
	newsk->sk_pacing_status = oldsk->sk_pacing_status;
	newsk->sk_max_pacing_rate = oldsk->sk_max_pacing_rate;
	newsk->sk_pacing_rate = oldsk->sk_pacing_rate;
}

static int __tsa_swap(struct net *net, struct socket *sock)
{
	int ret, domain, type, protocol;
	struct socket *newsock;
	struct sock *oldsk;

	oldsk = sock->sk;
	lock_sock(oldsk);
	domain = oldsk->sk_family;
	type = oldsk->sk_type;
	protocol = oldsk->sk_protocol;
	release_sock(oldsk);

	ret = __sock_create(net, domain, type, protocol, &newsock, 0);
	if (ret)
		return ret;

	lock_sock(oldsk);
	lock_sock(newsock->sk);
	copy_sockopts(oldsk, newsock->sk);
	release_sock(newsock->sk);
	release_sock(oldsk);

	ret = tsa_make_socket(sock, newsock);
	if (ret)
		sock_release(newsock);

	return ret;
}

static int tsa_swap(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *afd, *anetnsfd;
	struct net *net = NULL;
	struct socket *sock;
	int err, fd;

	afd = info->attrs[TSA_C_SWAP_A_FD];
	if (!afd) {
		NL_SET_ERR_MSG_MOD(info->extack, "Missing FD to swap");
		return -EINVAL;
	}

	anetnsfd = info->attrs[TCA_C_SWAP_A_NETNS_FD];

	fd = nla_get_u32(afd);
	sock = sockfd_lookup(fd, &err);
	if (!sock) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "Could not perform sockfd_lookup");
		return err;
	}

	if (sock->ops->release != tsa_release) {
		err = -EINVAL;
		NL_SET_ERR_MSG_MOD(
			info->extack,
			"Tried to swap FD that was not created by AF_TSA");
		pr_warn_ratelimited(
			"af_tsa: Tried to swap FD that was not created by AF_TSA\n");
		goto out;
	}

	if (anetnsfd) {
		net = get_net_ns_by_fd(nla_get_u32(anetnsfd));
		if (IS_ERR(net)) {
			err = PTR_ERR(net);
			goto out;
		}
	} else {
		net = get_net(current->nsproxy->net_ns);
	}

	err = mutex_lock_killable(&tsa_mutex);
	err = __tsa_swap(net, sock);
	mutex_unlock(&tsa_mutex);

	put_net(net);
out:
	sockfd_put(sock);
	return err;
}

int tsa_create_reply(int fd, struct sk_buff *skb, struct genl_info *info)
{
	void *head;
	int err = -EMSGSIZE;

	head = genlmsg_put(skb, info->snd_portid, info->snd_seq, &genl_family,
			   0, TSA_C_CREATE);
	if (!head)
		goto err;

	if (nla_put_u32(skb, TSA_A_FD, fd))
		goto err;

	genlmsg_end(skb, head);

	return genlmsg_reply(skb, info);
err:
	genlmsg_cancel(skb, head);
	return err;
}

static int tsa_create(struct sk_buff *skb, struct genl_info *info)
{
	/* message handling code goes here; return 0 on success, negative
	* values on failure */
	struct nlattr *adomain, *atype, *aprotocol, *aflags, *anetnsfd;
	struct socket *sock, *underlyingsock;
	int domain, type, protocol, flags;
	struct net *net = NULL;
	struct sk_buff *reply;
	struct file *newfile;
	int err, fd;

	adomain = info->attrs[TSA_C_CREATE_A_DOMAIN];
	if (!adomain) {
		NL_SET_ERR_MSG_MOD(info->extack, "Missing domain");
		return -EINVAL;
	}

	atype = info->attrs[TSA_C_CREATE_A_TYPE];
	if (!atype) {
		NL_SET_ERR_MSG_MOD(info->extack, "Missing type");
		return -EINVAL;
	}

	aprotocol = info->attrs[TSA_C_CREATE_A_PROTOCOL];
	aflags = info->attrs[TSA_C_CREATE_A_FLAGS];
	anetnsfd = info->attrs[TCA_C_CREATE_A_NETNS_FD];

	domain = nla_get_u32(adomain);
	type = nla_get_u32(atype);
	protocol = aprotocol ? nla_get_u32(aprotocol) : 0;
	flags = aflags ? nla_get_u32(aflags) : 0;

	/* TODO: Copy ops and lie about family */
	if (domain != AF_INET && domain != AF_INET6)
		return -EAFNOSUPPORT;
	if (type != SOCK_STREAM && type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	if (anetnsfd) {
		net = get_net_ns_by_fd(nla_get_u32(anetnsfd));
		if (IS_ERR(net)) {
			NL_SET_ERR_MSG_MOD(info->extack, "could not get netns");
			return PTR_ERR(net);
		}
	} else {
		net = get_net(current->nsproxy->net_ns);
	}

	err = __sock_create(net, domain, type, protocol, &underlyingsock, 0);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "could not create underlying socket");
		goto out_put_net;
	}

	reply = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "could not allocate memory for reply");
		err = -ENOMEM;
		goto out_put_sock;
	}

	if (!try_module_get(THIS_MODULE)) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "could not fetch module failed");
		err = -EBUSY;
		goto out_put_msg;
	}

	/* TODO: Figure this out
	err = security_socket_create(domain, type, protocol, 0);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "security_socket_create failed");
		goto out_put_module;
	}
	*/

	sock = sock_alloc();
	if (!sock) {
		NL_SET_ERR_MSG_MOD(info->extack, "socket: no more sockets");
		err = -ENFILE;
		goto out_put_module;
	}
	pr_info("TSA creation of top level socket: %p\n", sock);

	sock->type = type;

	WARN_ON(!sock);
	WARN_ON(!underlyingsock);
	newfile = sock_alloc_file(sock, flags, NULL);
	if (IS_ERR(newfile)) {
		NL_SET_ERR_MSG_MOD(info->extack, "sock_alloc_file failed");
		goto out_put_tsa_socket;
	}

	err = tsa_make_socket(sock, underlyingsock);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack, "Could not create socket");
		goto out_put_file;
	}

	/* TODO: Figure this out
	err = security_socket_post_create(sock, domain, type, protocol, 0);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "security_socket_post_create failed");
		goto out_put_socket;
	}
	*/

	fd = get_unused_fd_flags(flags);
	if (fd < 0) {
		NL_SET_ERR_MSG_MOD(info->extack, "get_unused_fd_flags failed");
		err = fd;
		goto out_put_file;
	}

	err = tsa_create_reply(fd, reply, info);
	if (!err) {
		fd_install(fd, newfile);
		err = 0;
		goto out_put_net;
	}

	put_unused_fd(fd);

out_put_file:
	fput(newfile);
out_put_tsa_socket:
	sock_release(sock);
out_put_module:
	module_put(THIS_MODULE);
out_put_msg:
	nlmsg_free(reply);
out_put_sock:
	sock_release(underlyingsock);
out_put_net:
	put_net(net);
	return err;
}

static struct nla_policy tsa_create_policy[TSA_C_CREATE_A_MAX + 1] = {
	[TSA_C_CREATE_A_DOMAIN] = { .type = NLA_U32, },
	[TSA_C_CREATE_A_TYPE] = { .type = NLA_U32, },
	[TSA_C_CREATE_A_PROTOCOL] = { .type = NLA_U32, },
	[TSA_C_CREATE_A_FLAGS] = { .type = NLA_U32, },
	[TCA_C_CREATE_A_NETNS_FD] = { .type = NLA_U32, },
};

static struct nla_policy tsa_swap_policy[TSA_C_SWAP_A_MAX + 1] = {
	[TSA_C_SWAP_A_FD] = { .type = NLA_U32, },
	[TCA_C_SWAP_A_NETNS_FD] = { .type = NLA_U32, },
};

static const struct genl_ops genl_ops[] = {
	{
		.cmd = TSA_C_CREATE,
		.doit = tsa_create,
		.policy = tsa_create_policy,
		.maxattr = TSA_C_CREATE_A_MAX,
	},
	{
		.cmd = TSA_C_SWAP,
		.doit = tsa_swap,
		.policy = tsa_swap_policy,
		.maxattr = TSA_C_SWAP_A_MAX,
	},
};

static struct genl_family genl_family = {
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
	.name = TSA_GENL_NAME,
	.version = TSA_GENL_VERSION,
	.module = THIS_MODULE,
	.netnsok = true,
};

static int __init tsa_init(void)
{
	return genl_register_family(&genl_family);
}

static void __exit tsa_exit(void)
{
	genl_unregister_family(&genl_family);
}

module_init(tsa_init);
module_exit(tsa_exit);
