// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause-No-Nuclear-Warranty
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/sock.h>

#include "af_tsa.h"

MODULE_DESCRIPTION("AF TSA Family");
MODULE_AUTHOR("Sargun Dhillon <sargun@sargun.me>");
MODULE_LICENSE("Dual BSD/GPL");

#define PF_TSA PF_SNA
#define AF_TSA PF_TSA

DEFINE_MUTEX(tsa_mutex);

struct tsa_sock {
	struct sock sk;
	struct socket *real;
};

static struct proto tsa_proto = {
	.name = "TSA",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct tsa_sock),
};

static inline struct tsa_sock *tsa_sk(const struct sock *sk)
{
	return (struct tsa_sock *)sk;
}

static int tsa_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tsa_sock *tsk = tsa_sk(sk);

	mutex_lock(&tsa_mutex);
	if (tsk->real) {
		kfree(sock->ops);
		WRITE_ONCE(sock->ops, (const struct proto_ops *)0xdeadbeef);
		smp_wmb();
	}
	mutex_unlock(&tsa_mutex);

	sock_orphan(sk);
	sock->sk = NULL;
	sock_put(sk);

	return 0;
}

static int tsa_swap(struct socket *sock);

static int tsa_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOIOCTLCMD;

	switch (cmd) {
	case SIOCTSASWAP:
		pr_info("Ran Split!\n");
		ret = tsa_swap(sock);
		break;
	}

	return ret;
}

static int tsa_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	return -ENOPROTOOPT;
}

static int tsa_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	return -ENOPROTOOPT;
}

static __poll_t tsa_poll(struct file *file, struct socket *sock,
			 poll_table *wait)
{
	__poll_t mask = EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;

	/* TODO: Make this wake upable via *magic*/
	sock_poll_wait(file, sock, wait);

	return mask;
}

int tsa_dgram_bind(struct socket *sock, struct sockaddr *myaddr,
		   int sockaddr_len)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->bind(tsk->real, myaddr, sockaddr_len);
}

int tsa_dgram_connect(struct socket *sock, struct sockaddr *vaddr,
		      int sockaddr_len, int flags)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->connect(tsk->real, vaddr, sockaddr_len, flags);
}

int tsa_dgram_accept(struct socket *sock, struct socket *newsock, int flags,
		     bool kern)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->accept(tsk->real, newsock, flags, kern);
}

int tsa_dgram_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->getname(tsk->real, addr, peer);
}

__poll_t tsa_dgram_poll(struct file *file, struct socket *sock,
			struct poll_table_struct *wait)
{
	/* TODO:
	 * If there is an existing thing waiting in poll, we need to wake it, and reset it to look
	 * at this real function
	 */
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->poll(file, tsk->real, wait);
}

int tsa_dgram_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->ioctl(tsk->real, cmd, arg);
}

int tsa_dgram_gettstamp(struct socket *sock, void __user *userstamp,
			bool timeval, bool time32)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	/* Poor man's reimplementation from socket.c */
	if (!tsk->real->ops->gettstamp)
		return -ENOIOCTLCMD;

	return tsk->real->ops->gettstamp(tsk->real, userstamp, timeval, time32);
}

int tsa_dgram_listen(struct socket *sock, int len)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->listen(tsk->real, len);
}

int tsa_dgram_shutdown(struct socket *sock, int flags)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->shutdown(tsk->real, flags);
}

int tsa_dgram_setsockopt(struct socket *sock, int level, int optname,
			 sockptr_t optval, unsigned int optlen)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->setsockopt(tsk->real, level, optname, optval,
					  optlen);
}

int tsa_dgram_getsockopt(struct socket *sock, int level, int optname,
			 char __user *optval, int __user *optlen)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->getsockopt(tsk->real, level, optname, optval,
					  optlen);
}

void tsa_dgram_show_fdinfo(struct seq_file *m, struct socket *sock)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->show_fdinfo(m, tsk->real);
}

int tsa_dgram_sendmsg(struct socket *sock, struct msghdr *m,
				      size_t total_len)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->sendmsg(tsk->real, m, total_len);
}

int tsa_dgram_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		      int flags)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->recvmsg(tsk->real, m, total_len, flags);
}

int tsa_dgram_mmap(struct file *file, struct socket *sock,
		   struct vm_area_struct *vma)
{
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->mmap(file, tsk->real, vma);
}

ssize_t tsa_dgram_sendpage(struct socket *sock, struct page *page,
				      int offset, size_t size, int flags) {
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->sendpage(tsk->real, page, offset, size, flags);
}

ssize_t tsa_dgram_splice_read(struct socket *sock,  loff_t *ppos,
				       struct pipe_inode_info *pipe, size_t len, unsigned int flags) {
	struct tsa_sock *tsk = tsa_sk(sock->sk);

	return tsk->real->ops->splice_read(tsk->real, ppos, pipe, len, flags);
}

static int tsa_swap(struct socket *sock)
{
	struct proto_ops *fake_real_ops;
	struct socket *newsock;
	struct tsa_sock *tsk;
	int ret;

	fake_real_ops = kzalloc(sizeof(*fake_real_ops), GFP_KERNEL);
	if (!fake_real_ops)
		return -ENOMEM;

	mutex_lock(&tsa_mutex);
	tsk = tsa_sk(sock->sk);
	ret = sock_create(AF_INET, SOCK_DGRAM, 0, &newsock);
	if (ret) {
		kfree(fake_real_ops);
		goto out;
	}

	tsk->real = newsock;
	newsock->file = get_file(sock->file);
	/* This is in order based on net.h */
	fake_real_ops->family = newsock->ops->family;
	fake_real_ops->owner = newsock->ops->owner;
	fake_real_ops->release = tsa_release;
	fake_real_ops->bind = tsa_dgram_bind;
	fake_real_ops->connect = tsa_dgram_connect;
	/* This is ugly. Let's not support anything that can do socketpair */
	fake_real_ops->socketpair = sock_no_socketpair;
	fake_real_ops->accept = tsa_dgram_accept;
	fake_real_ops->getname = tsa_dgram_getname;
	fake_real_ops->poll = tsa_dgram_poll;
	fake_real_ops->ioctl = tsa_dgram_ioctl;
	if (newsock->ops->gettstamp)
		fake_real_ops->gettstamp = tsa_dgram_gettstamp;
	fake_real_ops->listen = tsa_dgram_listen;
	fake_real_ops->shutdown = tsa_dgram_shutdown;
	fake_real_ops->setsockopt = tsa_dgram_setsockopt;
	fake_real_ops->getsockopt = tsa_dgram_getsockopt;
	if (newsock->ops->show_fdinfo)
		fake_real_ops->show_fdinfo = tsa_dgram_show_fdinfo;
	fake_real_ops->sendmsg = tsa_dgram_sendmsg;
	fake_real_ops->recvmsg = tsa_dgram_recvmsg;
	if (newsock->ops->sendpage)
		fake_real_ops->sendpage = tsa_dgram_sendpage;
	if (newsock->ops->splice_read)
		fake_real_ops->splice_read = tsa_dgram_splice_read;
	/*
	These are weird because they're not actually called through this layer.
	if (newsock->ops->set_peek_off)
		fake_real_ops->ops->set_peek_off = tsa_dgram_set_peek_off;
	if (newsock->ops->peek_len)
		fake_real_ops->ops->peek_len = tsa_dgram_peek_len;
	if (newsock->ops->read_sock)
		fake_real_ops->ops->read_sock = tsa_dgram_read_sock;
	if (newsock->ops->sendmsg_locked)
		fake_real_ops->ops->sendmsg_locked = tsa_dgram_sendmsg_locked;
	if (newsock->ops->set_rcvlowat)
		fake_real_ops->ops->set_rcvlowat = tsa_dgram_set_rcvlowat;
	*/
	smp_wmb();
	WRITE_ONCE(sock->ops, fake_real_ops);
	smp_wmb();

out:
	mutex_unlock(&tsa_mutex);
	return ret;
}

static const struct proto_ops tsa_base_real_dgram_ops = {
	.family = PF_TSA,
	.owner = THIS_MODULE,
	.release = tsa_release,
	.bind = tsa_dgram_bind,
	.connect = tsa_dgram_connect,
	.socketpair = sock_no_socketpair,
	.accept = tsa_dgram_accept,
	.getname = tsa_dgram_getname,
	.poll = tsa_dgram_poll,
	/* TODO: gettstamp */
	.ioctl = tsa_dgram_ioctl,
	.listen = tsa_dgram_listen,
	.shutdown = tsa_dgram_shutdown,
	.setsockopt = tsa_dgram_setsockopt,
	.getsockopt = tsa_dgram_getsockopt,
	.sendmsg = sock_no_sendmsg,
	.recvmsg = sock_no_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static const struct proto_ops tsa_dgram_ops = {
	.family = PF_TSA,
	.owner = THIS_MODULE,
	.release = tsa_release,
	.bind = sock_no_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = tsa_poll,
	/* TODO: gettstamp */
	.ioctl = tsa_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = tsa_setsockopt,
	.getsockopt = tsa_getsockopt,
	.sendmsg = sock_no_sendmsg,
	.recvmsg = sock_no_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
	/* TODO:
	 * -set_peek_off
	 */
};

static void tsa_sk_destruct(struct sock *sk)
{
	struct tsa_sock *tsk = tsa_sk(sk);

	/* Idk man, some locking here */
	if (tsk->real) {
		fput(tsk->real->file);
		tsk->real->file = NULL;
		sock_release(tsk->real);
	}
}

static int tsa_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct tsa_sock *tsk;
	struct sock *sk;

	sock->state = SS_UNCONNECTED;

	/* TODO: Copy ops and lie about family */
	switch (sock->type) {
	case SOCK_DGRAM:
		sock->ops = &tsa_dgram_ops;
		break;
		//	case SOCK_STREAM:
		//		sock->ops = &tsa_stream_ops;
		//		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	sk = sk_alloc(net, PF_TSA, GFP_KERNEL, &tsa_proto, kern);
	if (!sk)
		return -ENOMEM;

	/* TODO: Add some locks and mutexes and stuff */
	sock_init_data(sock, sk);

	sk->sk_destruct = tsa_sk_destruct;
	sk->sk_user_data = 0xbeefdead;
	sock_set_flag(sk, SOCK_RCU_FREE);

	tsk = tsa_sk(sk);
	tsk->real = NULL;

	return 0;
}

static const struct net_proto_family tsa_family_ops = {
	.family = PF_TSA,
	.create = tsa_create,
	.owner = THIS_MODULE,
};

static int __init tsa_init(void)
{
	int err;

	err = proto_register(&tsa_proto, 1);
	if (err)
		return err;

	err = sock_register(&tsa_family_ops);
	if (err)
		proto_unregister(&tsa_proto);

	return err;
}

static void __exit tsa_exit(void)
{
	sock_unregister(PF_TSA);
	proto_unregister(&tsa_proto);
}

module_init(tsa_init);
module_exit(tsa_exit);