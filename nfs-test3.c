#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <atf-c.h>

#include "utils.h"

#define SERVER "192.168.56.105"
#define EXPORT "/usr/home/shivank/TEST_NFS"

static struct pollfd fds[1];
static const char *auclass = "nfs";
static const char *path = "fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";

static void
nfs3_mkdir_status_cb(__unused struct rpc_context *rpc, int status, __unused void * data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_SUCCESS)
		printf("success\n");
	if (status == RPC_STATUS_ERROR)
		printf("mkdir error\n");
	if (status == RPC_STATUS_CANCEL)
		printf("mkdir cancel\n");

	client->au_rpc_status = status;
	client->is_finished = 1;
	printf("complete\n");
}

static void
nfs3_mkdir_cb(struct rpc_context *rpc, int status, __unused void *data, void *private_data)
{
	struct client *client = private_data;

	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to RPC.MOUNTD on server %s failed\n", client->server);
		exit(10);
	}

	MKDIR3args args;
	memset(&args, 0, sizeof(MKDIR3args));
	args.where.dir = client->rootfh;
	args.where.name = "TEST_DIR_AU";
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 420;

	printf("Connected to RPC.NFSD on %s:%d\n", client->server, client->mount_port);
	if (rpc_nfs3_mkdir_async(rpc, nfs3_mkdir_status_cb, &args, client) != 0) {
		printf("Failed to send mkdir request\n");
		exit(10);
	}
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_success);
ATF_TC_HEAD(nfs3_mkdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFS mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_success, tc)
{
	FILE *pipefd = setup(fds, auclass);
	struct rpc_context *rpc;
	struct pollfd pfd;
	struct client client;
	
	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_cb = nfs3_mkdir_cb;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	printf("RPC done\n");	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		printf("RPC\n");
		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed\n");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			break;
		}

		printf("RPC %d \n", client.is_finished);
		if (client.is_finished) {
			break;
		}

	}
	printf("RPC DONE now destroy\n");
	nfs_destroy(rpc);
	ATF_CHECK_EQ(RPC_STATUS_SUCCESS, client.au_rpc_status);

	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_success, tc)
{
	cleanup();
}
/*
ATF_TC_WITH_CLEANUP(nfs3_mkdir_failure);
ATF_TC_HEAD(nfs3_mkdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a unsuccessful "
					"NFS mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_failure, tc)
{
	FILE *pipefd = setup(fds, auclass);
	struct rpc_context *rpc;
	struct pollfd pfd;
	struct client client;
	
	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_cb = nfs3_mkdir_cb;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	printf("RPC done\n");	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		printf("RPC\n");
		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed\n");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			break;
		}

		printf("RPC %d \n", client.is_finished);
		if (client.is_finished) {
			break;
		}

	}
	printf("RPC DONE now destroy\n");
	nfs_destroy(rpc);
	
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	printf("RPC done\n");	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		printf("RPC\n");
		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed\n");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			break;
		}

		printf("RPC %d \n", client.is_finished);
		if (client.is_finished) {
			break;
		}

	}
	printf("RPC DONE now destroy\n");
	nfs_destroy(rpc);

	ATF_CHECK_EQ(RPC_STATUS_ERROR,client.au_rpc_status);

	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_failure, tc)
{
	cleanup();
}
*/
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);

	return atf_no_error();
}
