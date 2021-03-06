#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <linux/socket.h>
#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <signal.h>


#include "af_tsa.h"

struct fam {
	int version;
	int hdrsize;
	int id;
};

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct fam *fam = data;
	struct nlattr *attr;
	int type;

	mnl_attr_for_each(attr, nlh, sizeof(*genl))
	{
		type = mnl_attr_get_type(attr);
		if (type == CTRL_ATTR_VERSION)
			fam->version = mnl_attr_get_u32(attr);
		if (type == CTRL_ATTR_HDRSIZE)
			fam->hdrsize = mnl_attr_get_u32(attr);
		if (type == CTRL_ATTR_FAMILY_ID)
			fam->id = mnl_attr_get_u16(attr);
	}

	return MNL_CB_OK;
}

static int create_data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	int *newfd = data;
	struct nlattr *attr;
	int type;

	mnl_attr_for_each(attr, nlh, sizeof(*genl))
	{
		type = mnl_attr_get_type(attr);
		if (type == TSA_A_FD)
			*newfd = mnl_attr_get_u32(attr);
	}

	return MNL_CB_OK;
}

static bool fasync_callback = false;

void poll_handler(int signum) {
	fasync_callback = true;
	printf("Got poll callback\n");
}

int main()
{
	struct sockaddr_in servaddr = {
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(4554),
		.sin_family = AF_INET,
	};
	struct sockaddr_in publicaddr = {
		.sin_addr.s_addr = inet_addr("198.51.100.0"),
		.sin_port = htons(4554),
		.sin_family = AF_INET,
	};
	struct sockaddr_in localaddr = {
		.sin_addr.s_addr = inet_addr("0.0.0.0"),
		.sin_port = htons(0),
		.sin_family = AF_INET,
	};
	int flags, ret, seq, portid, one = 1, newfd = -1;
	char *hello = "Hello, how you doin\n";
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct sigaction new_action = {};
	struct pollfd pollfds[] = {};
	struct genlmsghdr *genl;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct fam fam = {};
	socklen_t addrlen;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, TSA_GENL_NAME);

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (nl == NULL) {
		perror("mnl_socket_open");
		return 1;
	}

	assert(mnl_socket_setsockopt(nl, NETLINK_EXT_ACK, &one, sizeof(one)) ==
	       0);

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return 1;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return 1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, data_cb, &fam);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = fam.id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++seq;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = TSA_C_CREATE;
	genl->version = fam.version;

	mnl_attr_put_u32(nlh, TSA_C_CREATE_A_DOMAIN, AF_INET);
	mnl_attr_put_u32(nlh, TSA_C_CREATE_A_TYPE, SOCK_DGRAM);
	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		perror("mnl_socket_sendto");
		return 1;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, create_data_cb, &newfd);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	printf("New FD: %d\n", newfd);
	assert(newfd >= 0);
	assert(bind(newfd, &localaddr, sizeof(localaddr)) == 0);
	assert(sendto(newfd, hello, strlen(hello), MSG_CONFIRM,
		      (struct sockaddr *)&publicaddr, sizeof(publicaddr)) >= 0);
	assert(sendto(newfd, hello, strlen(hello), MSG_CONFIRM,
		      (struct sockaddr *)&servaddr, sizeof(servaddr)) >= 0);
	addrlen = sizeof(localaddr);
	assert(getsockname(newfd, &localaddr, &addrlen) == 0);
	printf("Listening on port: %d\n", ntohs(localaddr.sin_port));

	sigemptyset(&new_action.sa_mask);
	new_action.sa_handler = poll_handler;
	sigaction(SIGPOLL, &new_action, NULL);

	fcntl(newfd, F_SETOWN, getpid());
	flags = fcntl(newfd, F_GETFL);
	fcntl(newfd, F_SETFL, flags | FASYNC);

	if (fork() == 0) {
		struct sockaddr_in newlocaladdr = {};
		int originalnetns, newnetns;

		assert(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0);
		originalnetns = open("/proc/thread-self/ns/net", O_RDONLY);
		assert(originalnetns >= 0);
		assert(unshare(CLONE_NEWNET) == 0);
		newnetns = open("/proc/thread-self/ns/net", O_RDONLY);
		assert(newnetns >= 0);
		system("ip link set lo up");
		assert(setns(originalnetns, CLONE_NEWNET) == 0);

		nlh = mnl_nlmsg_put_header(buf);
		nlh->nlmsg_type = fam.id;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		nlh->nlmsg_seq = ++seq;

		genl = mnl_nlmsg_put_extra_header(nlh,
						  sizeof(struct genlmsghdr));
		genl->cmd = TSA_C_SWAP;
		genl->version = fam.version;

		mnl_attr_put_u32(nlh, TSA_C_SWAP_A_FD, newfd);
		mnl_attr_put_u32(nlh, TCA_C_SWAP_A_NETNS_FD, newnetns);
		/* Wait for the poll in the other process to start */
		sleep(1);
		/*
		ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
		if (ret < 0) {
			perror("mnl_socket_sendto");
			return 1;
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		while (ret > 0) {
			ret = mnl_cb_run(buf, ret, seq, portid, create_data_cb,
					 &newfd);
			if (ret <= 0)
				break;
			ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		}
		*/
		ret = ioctl(newfd, SIOCTSASWAP, newnetns);
		printf("Completed swap: %d\n", ret);
		assert(ret == 0);
		assert(sendto(newfd, hello, strlen(hello), MSG_CONFIRM,
			      (struct sockaddr *)&publicaddr,
			      sizeof(publicaddr)) == -1);
		addrlen = sizeof(newlocaladdr);
		assert(getsockname(newfd, &newlocaladdr, &addrlen) == 0);
		printf("New Socket listening on port: %d\n",
		       ntohs(newlocaladdr.sin_port));
		assert(sendto(newfd, hello, strlen(hello), MSG_CONFIRM,
			      (struct sockaddr *)&newlocaladdr,
			      sizeof(newlocaladdr)) >= 0);

		_exit(0);
	}

	pollfds[0].fd = newfd;
	pollfds[0].events = POLLIN;
	/* Make sure there's not any standing poll events */
	assert(poll(pollfds, 1, 0) == 0);
	if (fork() == 0) {

		assert(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0);
		ret = recv(newfd, &hello, sizeof(hello), 0);
		printf("Receive ret: %d\n", ret);
		assert(ret > 0);
		_exit(0);
	}
	assert(poll(pollfds, 1, 10000) == 1);
	assert(pollfds[0].revents & POLLIN);

	/* TODO: Add testing that we actually read / received data */
	do {
		poll(pollfds, 1, 0);
	} while(pollfds[0].revents & POLLIN);
	assert(fasync_callback);

	printf("Close: %d\n", close(newfd));

	return 0;
}