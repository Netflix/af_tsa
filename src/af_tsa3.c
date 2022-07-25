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

static DEFINE_MUTEX(tsa_mutex);
static struct genl_family genl_family;

static void __tsa_swap(struct net *net, struct socket *sock)
{
	struct sock *oldsk;

	oldsk = sock->sk;
	lock_sock(oldsk);
	write_pnet(&oldsk->sk_net, net);
	release_sock(oldsk);
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
		NL_SET_ERR_MSG_MOD(info->extack, "Could not perform sockfd_lookup");
		return err;
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
	__tsa_swap(net, sock);
	mutex_unlock(&tsa_mutex);

out_put_net:
	put_net(net);
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
