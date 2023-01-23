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

static int tsa_swap(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *afd, *anetnsfd;
	struct net *other_ns, *my_ns;
	struct socket *sock;
	struct sock *sk;
	int err = 0, fd;

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
			goto out;
		}
	} else {
		other_ns = get_net(current->nsproxy->net_ns);
	}

	// Ensure socket is in an unconnected state and is
	// not bound to a device to ensure switching network
	// namespaces does not result in undesired behavior.
	sk = sock->sk;
	if (!sk) {
		err = -EINVAL;
		goto out;
	}

	lock_sock(sk);
	if (sk->sk_type != SOCK_STREAM && sk->sk_type != SOCK_DGRAM) {
		NL_SET_ERR_MSG_MOD(info->extack, "Unsupported socket type");
		goto out_put_release;
	}
	if (sk->sk_state != TCP_CLOSE || sk->sk_shutdown == SHUTDOWN_MASK) {
		NL_SET_ERR_MSG_MOD(info->extack, "Socket is not in an unconnected state");
		goto out_put_release;
	}

	if (sk->sk_bound_dev_if != 0) {
		NL_SET_ERR_MSG_MOD(info->extack, "Socket is bound to a device");
		goto out_put_release;
	}
	my_ns = sock_net(sk);
	sock_net_set(sk, other_ns);
	put_net(my_ns);
	release_sock(sk);
	goto out;

out_put_release:
	release_sock(sk);
	put_net(other_ns);
out:
	sockfd_put(sock);
	return err;
}

static struct nla_policy tsa_swap_policy[TSA_C_SWAP_A_MAX + 1] = {
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
