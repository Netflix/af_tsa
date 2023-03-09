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

MODULE_DESCRIPTION("Socket Net Namespace Switcher");
MODULE_AUTHOR("Alok Tiagi <atiagi@netflix.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS_NET_PF_PROTO_NAME(PF_NETLINK, NETLINK_GENERIC, TSA_GENL_NAME);

static struct genl_family genl_family;

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
			newsk->sk_txtime_deadline_mode = oldsk->sk_txtime_deadline_mode;
			newsk->sk_txtime_report_errors = oldsk->sk_txtime_report_errors;
		}
		/* We might be able to reduce the guarantees here and not require atomic ops */
		sock_valbool_flag(newsk, flag, val);
	}

	WRITE_ONCE(newsk->sk_sndbuf, READ_ONCE(oldsk->sk_sndbuf));
	WRITE_ONCE(newsk->sk_rcvbuf, READ_ONCE(oldsk->sk_rcvbuf));

	newsk->sk_userlocks |= oldsk->sk_userlocks & (SOCK_RCVBUF_LOCK | SOCK_SNDBUF_LOCK);
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

	if (oldsk->sk_socket->ops->set_peek_off && newsk->sk_socket->ops->set_peek_off)
		newsk->sk_socket->ops->set_peek_off(newsk, READ_ONCE(oldsk->sk_peek_off));

	WRITE_ONCE(newsk->sk_ll_usec, READ_ONCE(oldsk->sk_ll_usec));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	WRITE_ONCE(newsk->sk_prefer_busy_poll, READ_ONCE(oldsk->sk_prefer_busy_poll));
	WRITE_ONCE(newsk->sk_busy_poll_budget, READ_ONCE(oldsk->sk_busy_poll_budget));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#error "Untested kernel version"
#endif
	newsk->sk_pacing_status = oldsk->sk_pacing_status;
	newsk->sk_max_pacing_rate = oldsk->sk_max_pacing_rate;
	newsk->sk_pacing_rate = oldsk->sk_pacing_rate;
}

static int tsa_swap(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *adomain, *atype, *aprotocol;
	int domain, type, protocol;
	struct nlattr *afd, *anetnsfd;
	struct net *other_ns, *my_ns;
	struct socket *sock;
	struct socket *newsock;
	int err = 0, fd;

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

	domain = nla_get_u32(adomain);
	type = nla_get_u32(atype);
	protocol = aprotocol ? nla_get_u32(aprotocol) : 0;

	afd = info->attrs[TSA_C_SWAP_A_FD];
	if (!afd) {
		NL_SET_ERR_MSG_MOD(info->extack, "Missing FD to swap");
		return -EINVAL;
	}

	anetnsfd = info->attrs[TCA_C_SWAP_A_NETNS_FD];

	fd = nla_get_u32(afd);
	sock = sockfd_lookup(fd, &err);
	if (!sock) {
		NL_SET_ERR_MSG_MOD(info->extack, "Could not perform sockfd_lookup");
		return err;
	}

	if (anetnsfd) {
		other_ns = get_net_ns_by_fd(nla_get_u32(anetnsfd));
		if (IS_ERR(other_ns)) {
			err = PTR_ERR(other_ns);
			return err;
		}
	} else {
		other_ns = get_net(current->nsproxy->net_ns);
	}

	// Ensure socket is in an unconnected state and is
	// not bound to a device to ensure switching network
	// namespaces does not result in undesired behavior.

	err = __sock_create(other_ns, domain, type, 0, &newsock, 0);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack, "could not create underlying socket");
		goto out_put_net;
	}

	newsock->file = sock->file;
	sock->file->private_data = newsock;

	copy_sockopts(sock->sk, newsock->sk);

	printk("swap succeeded %d", newsock->file->f_op->poll;);
	my_ns = sock_net(sock->sk);
	sock_release(sock);
	put_net(my_ns);

	return err;

out_put_net:
	put_net(other_ns);
	return err;
}

static struct nla_policy tsa_swap_policy[TSA_C_SWAP_A_MAX + 1] = {
	[TSA_C_SWAP_A_DOMAIN] = { .type = NLA_U32, },
	[TSA_C_SWAP_A_TYPE] = { .type = NLA_U32, },
	[TSA_C_SWAP_A_PROTOCOL] = { .type = NLA_U32, },
	[TSA_C_SWAP_A_FD] = { .type = NLA_U32, },
	[TCA_C_SWAP_A_NETNS_FD] = { .type = NLA_U32, },
};

static const struct genl_ops genl_ops[] = {
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
	.parallel_ops = true,
};

static int __init tsa_init(void)
{
	int ret = 0;

	ret = genl_register_family(&genl_family);
	if (ret)
		goto fail;
	return 0;

fail:
	return ret;
}

static void __exit tsa_exit(void)
{
	genl_unregister_family(&genl_family);
}

module_init(tsa_init);
module_exit(tsa_exit);
