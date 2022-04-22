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

/*
 * Brain dump:
 *                                                                                                                                         
 *                                                                                                                                        
 *                                                                                                                                        
 * |----------------------------------------------------------------------------------------------------------------+                     
 * |         tsa socket               tsa_proto_ops_wrapper            tsa_realsock             "real" socket       |"real" sk            
 * |      +---------------+            +-----------------+          +-----------------+          +---------+        |---------------+     
 * |      |               |            |                 |          |                 |          |         |        |               |     
 * |      |  proto_ops------------------   tsa_realsock--------------     realsock----------------  sk--------------- sk_destruct   |     
 * +------------sk        |            |                 |          |                 |          |         |        |               |     
 * +--------               |            |                 |          |     tsasock     +---+      |         |        | sk_user_data  |     
 * |       |               |            |                 |          |        |        |   |      |         |        |      |        |     
 * |       |               |            |                 |          |        |        |   |      |         |        |      |        |     
 * |       +---------------+            +-----------------+          +--------|--------+   |      +---------+        +------|--------+     
 * |    Lifetime: Userspace Socket        Lifetime: TSA Sock's       Lifetime: Real socket |                                |              
 * |                                                                          |            |                                |              
 * |                                                                          |            |                                |              
 * |                                                                          |            |                                |              
 * |--------------------------------------------------------------------------+            +---------------------------------              
 */

/*
 * TODO:
 *
 * - Clear sock_nospace flag on socket
 */
static DEFINE_SEQLOCK(tsa_seqlock);
static DEFINE_MUTEX(tsa_mutex);
static struct genl_family genl_family;

struct tsa_worker {
	int srcu_idx;
};

struct tsa_proto_ops_wrapper;
struct tsa_realsock {
	/* Pointer back to the TSA sock that built this real sock */
	struct socket *realsock;
	struct socket *tsasock;

	void (*save_state_change)(struct sock *sk);
	void (*save_data_ready)(struct sock *sk);
	void (*save_write_space)(struct sock *sk);
	void (*save_error_report)(struct sock *sk);
	void (*save_destruct)(struct sock *sk);

	/* Is this socket shutting down? */
	bool shutting_down;

	/*
	1. SRCU Wait
	2. Close
	*/
	struct work_struct work_shutdown;
	struct rcu_head srcu_head;
	struct work_struct work_release;

	struct tsa_proto_ops_wrapper *tpow;
};

struct tsa_proto_ops_wrapper {
	struct proto_ops real_ops;
	struct tsa_realsock *tsa_realsock;
	struct srcu_struct srcu;

	struct work_struct work_free;
	struct kref kref;
};

static int __tsa_swap(struct net *net, struct socket *sock);
static int tsa_release(struct socket *sock);
static void release_tpow(struct kref *kref);

struct tsa_proto_ops_wrapper* sock_tpow(struct socket *sock)
{
	struct tsa_proto_ops_wrapper *tpow;
	const struct proto_ops *po;

	WARN_ON(!sock);
	po = sock->ops;
	WARN_ON(!po);
	WARN_ON(po->release != tsa_release);
	tpow = container_of(po, struct tsa_proto_ops_wrapper, real_ops);
	return tpow;
}

static void put_tpow(struct tsa_proto_ops_wrapper *tpow)
{
	kref_put(&tpow->kref, release_tpow);
}

static struct tsa_realsock* tsa_worker_start(struct socket *sock,
			     		     struct tsa_worker *worker)
{
	struct tsa_proto_ops_wrapper *tpow;
	struct tsa_realsock *tsa_realsock;
	unsigned seq;

retry:
	seq = read_seqbegin(&tsa_seqlock);
	tpow = sock_tpow(sock);
	tsa_realsock = tpow->tsa_realsock;
	if (read_seqretry(&tsa_seqlock, seq)) {
		goto retry;
	}

	WARN_ON(tsa_realsock->shutting_down);
	worker->srcu_idx = srcu_read_lock(&tpow->srcu);

	return tsa_realsock;
}

static struct tsa_realsock* tsa_worker_start_sk(struct sock *sk,
						struct tsa_worker *worker)
{
	return tsa_worker_start(sk->sk_socket, worker);
}

static bool tsa_worker_end(struct tsa_realsock *realsock,
			   struct tsa_worker *worker)
{
	struct tsa_proto_ops_wrapper *tpow;
	bool shutting_down;

	tpow = sock_tpow(realsock->tsasock);
	smp_rmb();
	shutting_down = realsock->shutting_down;
	srcu_read_unlock(&tpow->srcu, worker->srcu_idx);

	return shutting_down;
}

static int tsa_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	ret = trealsock->realsock->ops->setsockopt(trealsock->realsock, level, optname, optval, optlen);
	tsa_worker_end(trealsock, &worker);

	return ret;
}

static int tsa_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->getsockopt(trealsock->realsock, level, optname, optval, optlen);
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static __poll_t tsa_poll(struct file *file, struct socket *sock, poll_table *p)
{
	/* TODO: Make it so when we swap out the sockets, we can properly *re-wake* out of this function */
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	__poll_t ret = 0;

	sock_poll_wait(file, sock, p);

	/* Wait to dereference the operations. There's a write memory barrier elsewhere to protect this. */
	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->poll(file, trealsock->realsock, p);
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_bind(struct socket *sock, struct sockaddr *myaddr,
		    int sockaddr_len)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	pr_debug("tsa: trealsock: %px\n", trealsock);
	realsock = trealsock->realsock;
	pr_debug("tsa: realsock: %px\n", realsock);
	pr_debug("tsa: ops: %px\n", realsock->ops);
	pr_debug("tsa: bind: %px\n", realsock->ops);
	ret = realsock->ops->bind(realsock, myaddr, sockaddr_len);
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_connect(struct socket *sock, struct sockaddr *vaddr,
		       int sockaddr_len, int flags)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->connect(realsock, vaddr, sockaddr_len, flags);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_accept(struct socket *sock, struct socket *newsock, int flags,
		      bool kern)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	module_put(newsock->ops->owner);
	newsock->ops = realsock->ops;
	smp_wmb();
	__module_get(realsock->ops->owner);
	newsock->ops = realsock->ops;
	pr_debug("Running accept, newsock's file: %px\n", newsock->file);
	ret = realsock->ops->accept(realsock, newsock, flags, kern);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->getname(realsock, addr, peer);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_gettstamp(struct socket *sock, void __user *userstamp,
			 bool timeval, bool time32)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	if (realsock->ops->gettstamp)
		ret = realsock->ops->gettstamp(realsock, userstamp, timeval, time32);
	else
		ret = -ENOIOCTLCMD;
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_listen(struct socket *sock, int len)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->listen(realsock, len);
	/* Shouldn't block? */
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_shutdown(struct socket *sock, int flags)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	struct socket_wq *wq;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->shutdown(realsock, flags);
	/* Shouldn't block */
	tsa_worker_end(trealsock, &worker);

	rcu_read_lock();
	wq = rcu_dereference(realsock->sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_all(&wq->wait);
	rcu_read_unlock();

	return ret;
}

static void tsa_show_fdinfo(struct seq_file *m, struct socket *sock)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	if (realsock->ops->show_fdinfo)
		realsock->ops->show_fdinfo(m, realsock);
	tsa_worker_end(trealsock, &worker);
}

static int tsa_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->sendmsg(realsock, m, total_len);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		       int flags)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->recvmsg(realsock, m, total_len, flags);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static ssize_t tsa_sendpage(struct socket *sock, struct page *page, int offset,
			    size_t size, int flags)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	if (realsock->ops->sendpage)
		ret = realsock->ops->sendpage(realsock, page, offset, size, flags);
	else
		ret = sock_no_sendpage(sock, page, offset, size, flags);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static ssize_t tsa_splice_read(struct socket *sock, loff_t *ppos,
			       struct pipe_inode_info *pipe, size_t len,
			       unsigned int flags)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	ret = realsock->ops->splice_read(realsock, ppos, pipe, len, flags);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int __tsa_ioctl_swap(struct socket *sock, unsigned int cmd,
			    unsigned long arg)
{
	struct net *net;
	int ret;

	pr_debug("Performing ioctl based swap on to ns %ld\n", arg);
	net = get_net_ns_by_fd(arg);
	if (IS_ERR(net))
		return PTR_ERR(net);

	ret = __tsa_swap(net, sock);

	put_net(net);
	return ret;
}

static int tsa_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	switch (cmd) {
	case SIOCTSASWAP:
		ret = __tsa_ioctl_swap(sock, cmd, arg);
		break;
	default:
		ret = realsock->ops->ioctl(realsock, cmd, arg);
	}
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_read_sock(struct sock *sk, read_descriptor_t *desc,
			 sk_read_actor_t recv_actor)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start_sk(sk, &worker);
	realsock = trealsock->realsock;
	if (!realsock->ops->read_sock)
		ret = -EBUSY;
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_sendpage_locked(struct sock *sk, struct page *page, int offset,
			       size_t size, int flags)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start_sk(sk, &worker);
	realsock = trealsock->realsock;
	if (realsock->ops->sendpage_locked)
		ret = realsock->ops->sendpage_locked(sk, page, offset, size, flags);
	else
		ret = sock_no_sendpage_locked(sk, page, offset, size, flags);
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start_sk(sk, &worker);
	realsock = trealsock->realsock;
	if (realsock->ops->sendmsg_locked)
		ret = realsock->ops->sendmsg_locked(sk, msg, size);
	else
		ret = sock_no_sendmsg_locked(sk, msg, size);
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static int tsa_set_rcvlowat(struct sock *sk, int val)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret = 0;

	trealsock = tsa_worker_start_sk(sk, &worker);
	realsock = trealsock->realsock;
	if (val < 0)
		val = INT_MAX;
	if (realsock->ops->set_rcvlowat)
		ret = realsock->ops->set_rcvlowat(sk, val);
	else
		WRITE_ONCE(sk->sk_rcvlowat, val ? : 1);
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();
	return ret;
}

static int tsa_set_peek_off(struct sock *sk, int val)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start_sk(sk, &worker);
	realsock = trealsock->realsock;
	if (realsock->ops->set_peek_off)
		ret = realsock->ops->set_peek_off(sk, val);
	else
		ret = -EOPNOTSUPP;
	if (tsa_worker_end(trealsock, &worker))
		return restart_syscall();

	return ret;
}

static int tsa_peek_len(struct socket *sock)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;
	int ret;

	trealsock = tsa_worker_start(sock, &worker);
	realsock = trealsock->realsock;
	WARN_ON(!realsock->ops->peek_len);
	ret = realsock->ops->peek_len(realsock);
	tsa_worker_end(trealsock, &worker);
	return ret;
}

static void tsa_srcu_realsock_cb(struct rcu_head *head)
{
	struct tsa_realsock *trealsock;

	trealsock = container_of(head, struct tsa_realsock, srcu_head);
	schedule_work(&trealsock->work_release);
}

static void __tsa_realsock_shutdown_cb(struct work_struct *wq)
{
	struct tsa_realsock *trealsock;
	int ret;

	trealsock = container_of(wq, struct tsa_realsock, work_shutdown);
	pr_debug("TSA Shutdown CB called back on: %px %px\n", trealsock, trealsock->realsock);
	ret = trealsock->realsock->ops->shutdown(trealsock->realsock, SHUT_RDWR);
	if (ret)
		pr_info("tsa: Issue shutting down socket %p: %d\n", trealsock, ret);

	pr_debug("Calling srcu (%px / %px)\n", trealsock, trealsock->realsock);
	call_srcu(&trealsock->tpow->srcu, &trealsock->srcu_head, tsa_srcu_realsock_cb);
}

static void __tsa_realsock_release_cb(struct work_struct *wq)
{
	struct tsa_proto_ops_wrapper *tpow;
	struct tsa_realsock *trealsock;

	trealsock = container_of(wq, struct tsa_realsock, work_release);
	pr_debug("__tsa_realsock_release_cb: TSA Close CB called back on: %px / %px / %px\n", trealsock, trealsock->realsock, trealsock->tsasock);
	tpow = trealsock->tpow;
	pr_debug("__tsa_realsock_release_cb: tpow: %px\n", tpow);
	sock_release(trealsock->realsock);
}

static void release_tpow(struct kref *kref)
{
	struct tsa_proto_ops_wrapper *tpow;

	tpow = container_of(kref, struct tsa_proto_ops_wrapper, kref);
	pr_debug("release tpow: %px\n", tpow);
	srcu_barrier(&tpow->srcu);
	cleanup_srcu_struct(&tpow->srcu);
	kfree(tpow);
}

/* This function may block */
static void start_release_old_tsa_realsock(struct tsa_realsock *trealsock)
{
	struct socket *realsock = trealsock->realsock;

	pr_debug("Starting release of: %px\n", trealsock);
	pr_debug("trealsock: %px\n", trealsock->realsock);
	WARN_ON(!trealsock->realsock);
	trealsock->shutting_down = true;
	smp_wmb();

	/* Save real callbacks */
	pr_debug("SK: %px\n", realsock->sk);
	if (realsock->sk) {
		write_lock_bh(&realsock->sk->sk_callback_lock);
		write_seqlock(&tsa_seqlock);
		realsock->sk->sk_data_ready = trealsock->save_data_ready;
		realsock->sk->sk_write_space = trealsock->save_write_space;
		realsock->sk->sk_state_change = trealsock->save_state_change;
		realsock->sk->sk_error_report = trealsock->save_error_report;
		rcu_assign_pointer(realsock->sk->sk_wq, &realsock->wq);
		realsock->sk->sk_socket = trealsock->realsock;
		write_sequnlock(&tsa_seqlock);
		write_unlock_bh(&realsock->sk->sk_callback_lock);
	}

	pr_debug("Calling shutdown\n");
	schedule_work(&trealsock->work_shutdown);
}

static void start_release_old_sk(struct sock *sk)
{
	struct tsa_realsock *trealsock;

	trealsock = sk->sk_user_data;
	start_release_old_tsa_realsock(trealsock);
}

static void __tsa_free_tpow_cb(struct work_struct *wh)
{
	struct tsa_proto_ops_wrapper *tpow;

	tpow = container_of(wh, struct tsa_proto_ops_wrapper, work_free);
	pr_debug("__tsa_free_tpow_cb: %px\n", tpow);
	put_tpow(tpow);
}

/*
 * After this point the struct socket (which is the tsa socket)
 * is uninitialized
 */
static int tsa_release(struct socket *sock)
{
	struct tsa_proto_ops_wrapper *tpow;
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *realsock;

	pr_debug("tsa_release: TSA release of top level socket: %px\n", sock);

	tpow = sock_tpow(sock);
	pr_debug("tsa_release: trealsock: %px\n", tpow->tsa_realsock);
	start_release_old_tsa_realsock(tpow->tsa_realsock);
	synchronize_rcu();
	schedule_work(&tpow->work_free);
	/* TODO: Release / free top-level socket */
	return 0;
}


static void tsa_data_ready(struct sock *sk)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *tsasock;

	read_lock_bh(&sk->sk_callback_lock);
	trealsock = sk->sk_user_data;
	if (!trealsock) {
		read_unlock_bh(&sk->sk_callback_lock);
		return;
	}

	tsa_worker_start(trealsock->tsasock, &worker);
	trealsock->save_data_ready(sk);
	tsa_worker_end(trealsock, &worker);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tsa_write_space(struct sock *sk)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *tsasock;

	read_lock_bh(&sk->sk_callback_lock);
	trealsock = sk->sk_user_data;
	if (!trealsock) {
		read_unlock_bh(&sk->sk_callback_lock);
		return;
	}

	tsa_worker_start(trealsock->tsasock, &worker);
	trealsock->save_write_space(sk);
	tsa_worker_end(trealsock, &worker);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tsa_state_change(struct sock *sk)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *tsasock;

	read_lock_bh(&sk->sk_callback_lock);
	trealsock = sk->sk_user_data;
	if (!trealsock) {
		read_unlock_bh(&sk->sk_callback_lock);
		return;
	}

	tsa_worker_start(trealsock->tsasock, &worker);
	trealsock->save_state_change(sk);
	tsa_worker_end(trealsock, &worker);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tsa_error_report(struct sock *sk)
{
	struct tsa_realsock *trealsock;
	struct tsa_worker worker;
	struct socket *tsasock;

	read_lock_bh(&sk->sk_callback_lock);
	trealsock = sk->sk_user_data;
	if (!trealsock) {
		read_unlock_bh(&sk->sk_callback_lock);
		return;
	}

	tsa_worker_start(trealsock->tsasock, &worker);
	trealsock->save_error_report(sk);
	tsa_worker_end(trealsock, &worker);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tsa_destruct(struct sock *sk)
{
	struct tsa_realsock *trealsock;

	pr_debug("tsa_destruct (start): sk: %px\n", sk);
	WARN_ON(!sk);
	trealsock = sk->sk_user_data;
	WARN_ON(!trealsock);
	trealsock->save_destruct(sk);
	put_tpow(trealsock->tpow);
	module_put(THIS_MODULE);
	kfree(trealsock);
	pr_debug("tsa_destruct: trealsock: %px sk: %px sk_socket: %px\n", trealsock, sk, sk->sk_socket);
}

/* There's not unwind code for this yet */
static struct tsa_realsock* make_trealsock(struct socket *sock, struct socket *newsock)
{
	struct tsa_proto_ops_wrapper *tpow;
	struct tsa_realsock *trealsock;

	tpow = sock_tpow(sock);
	WARN_ON(sock->ops->release != tsa_release);
	trealsock = kzalloc(sizeof(*trealsock), GFP_KERNEL);
	if (!trealsock)
		return ERR_PTR(-ENOMEM);

	if (!try_module_get(THIS_MODULE)) {
		kfree(trealsock);
		return ERR_PTR(-EBUSY);
	}

	kref_get(&tpow->kref);
	pr_debug("Wiring parent socket %px to newsock %px with trealsock %px, and tpow: %px\n", sock, newsock, trealsock, tpow);

	WARN_ON(!newsock);
	WARN_ON(!sock);
	WARN_ON(!sock->ops);

	trealsock->realsock = newsock;
	trealsock->tsasock = sock;
	trealsock->tpow = tpow;
	INIT_WORK(&trealsock->work_shutdown, __tsa_realsock_shutdown_cb);
	INIT_WORK(&trealsock->work_release, __tsa_realsock_release_cb);
	init_rcu_head(&trealsock->srcu_head);

	/* Save real callbacks */
	write_lock_bh(&newsock->sk->sk_callback_lock);
	WARN_ON(newsock->sk->sk_user_data);
	trealsock->save_data_ready = newsock->sk->sk_data_ready;
	trealsock->save_write_space = newsock->sk->sk_write_space;
	trealsock->save_state_change = newsock->sk->sk_state_change;
	trealsock->save_error_report = newsock->sk->sk_error_report;
	trealsock->save_destruct = newsock->sk->sk_destruct;
	trealsock->realsock->sk->sk_user_data = trealsock;

	newsock->sk->sk_data_ready = tsa_data_ready;
	newsock->sk->sk_write_space = tsa_write_space;
	newsock->sk->sk_state_change = tsa_state_change;
	newsock->sk->sk_error_report = tsa_error_report;
	newsock->sk->sk_destruct = tsa_destruct;
	newsock->sk->sk_socket = sock;
	rcu_assign_pointer(newsock->sk->sk_wq, &sock->wq);
	write_unlock_bh(&newsock->sk->sk_callback_lock);

	return trealsock;
}

/* Underlying socket has to be a socket that was built in kernel, and is unused */
static int tsa_make_socket(struct socket *sock, struct socket *underlyingsock)
{
	struct tsa_proto_ops_wrapper *tpow;
	struct tsa_realsock *trealsock;
	struct socket_wq *wq;
	struct sock *sk;
	int ret;

	sk = sock->sk;
	tpow = sock_tpow(sock);

	trealsock = make_trealsock(sock, underlyingsock);
	if (IS_ERR(trealsock))
		return PTR_ERR(trealsock);

	write_seqlock(&tsa_seqlock);
	sock->sk = underlyingsock->sk;
	tpow->tsa_realsock = trealsock;
	write_sequnlock(&tsa_seqlock);

	/* To make sure all the head callbacks are consistent */
	synchronize_rcu();

	if (sk)
		start_release_old_sk(sk);

	/* Wake up any outstanding waiters */
	rcu_read_lock();
	wq = &sock->wq;
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_all(&wq->wait);
	rcu_read_unlock();

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

static void tsa_make_wrapper(struct tsa_proto_ops_wrapper *tpow, int family)
{
	struct proto_ops *po = &tpow->real_ops;

	po->family = family;
	po->release = tsa_release;
	po->bind = tsa_bind;
	po->connect = tsa_connect;
	/* This is ugly. Let's not support anything that can do socketpair */
	po->socketpair = sock_no_socketpair;
	po->accept = tsa_accept;
	po->getname = tsa_getname;
	po->poll = tsa_poll;
	po->ioctl = tsa_ioctl;
	po->gettstamp = tsa_gettstamp;
	po->listen = tsa_listen;
	po->shutdown = tsa_shutdown;
	po->setsockopt = tsa_setsockopt;
	po->getsockopt = tsa_getsockopt;
	po->show_fdinfo = tsa_show_fdinfo;
	po->sendmsg = tsa_sendmsg;
	po->recvmsg = tsa_recvmsg;
	/* No supporting mmap, because that creates "interesting" problems if we release the underlying socket */
	po->mmap = sock_no_mmap;
	po->sendpage = tsa_sendpage;
	po->splice_read = tsa_splice_read;

	/* These are weird because they're not actually called through this layer. */

	po->set_peek_off = tsa_set_peek_off;
	po->peek_len = tsa_peek_len;
	po->read_sock = tsa_read_sock;
	po->sendpage_locked = tsa_sendpage_locked;
	po->sendmsg_locked = tsa_sendmsg_locked;
	po->set_rcvlowat = tsa_set_rcvlowat;
	po->owner = THIS_MODULE;

	pr_debug("Making tpow: %px\n", tpow);
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
	ret = tsa_make_socket(sock, newsock);
	release_sock(newsock->sk);
	release_sock(oldsk);
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
	if (err)
		goto out_put_net;
	err = __tsa_swap(net, sock);
	mutex_unlock(&tsa_mutex);

out_put_net:
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
	struct tsa_proto_ops_wrapper *tpow;
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
	pr_debug("TSA creation of top level socket: %px\n", sock);

	sock->type = type;

	WARN_ON(!sock);
	WARN_ON(!underlyingsock);
	newfile = sock_alloc_file(sock, flags, NULL);
	if (IS_ERR(newfile)) {
		NL_SET_ERR_MSG_MOD(info->extack, "sock_alloc_file failed");
		goto out_put_tsa_socket;
	}

	tpow = kzalloc(sizeof(*tpow), GFP_KERNEL);
	if (!tpow) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "could not allocate tsa socket operations wrapper");
		err = -ENOMEM;
		goto out_put_tsa_socket;
	}

	err = init_srcu_struct(&tpow->srcu);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "could not allocate srcu");
		kfree(tpow);
		goto out_put_tsa_socket;
	}
	INIT_WORK(&tpow->work_free, __tsa_free_tpow_cb);
	kref_init(&tpow->kref);

	tsa_make_wrapper(tpow, domain);
	sock->ops = &tpow->real_ops;
	WARN_ON(!sock->ops);

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
