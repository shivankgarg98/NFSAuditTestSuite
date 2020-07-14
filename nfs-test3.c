#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <atf-c.h>

#include "utils.h"

#define SERVER "192.168.56.105"
#define EXPORT "/mnt/NFS_audit_test"

static struct pollfd fds[1];
static const char *auclass = "nfs";
static char *path = "fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";

static void
nfs3_res_mkdir_cb(__unused struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	MKDIR3res *res;
	
	res = data;
	client->au_rpc_result = res->status;
	client->au_rpc_status = status;
	client->is_finished = 1;
	printf("complete\n");
}

static void
nfs3_call_mkdir_cb(struct rpc_context *rpc, int status, __unused void *data, void *private_data)
{
	struct client *client = private_data;
	MKDIR3args args;

	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to RPC.MOUNTD on server %s failed\n", client->server);
		exit(10);
	}

	memset(&args, 0, sizeof(MKDIR3args));
	args.where.dir = client->rootfh;
	args.where.name = path;
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 777;

	printf("Connected to RPC.NFSD on %s:%d\n", client->server, client->mount_port);
	if (rpc_nfs3_mkdir_async(rpc, nfs3_res_mkdir_cb, &args, client) != 0) {
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
	client.au_rpc_cb = nfs3_call_mkdir_cb;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	nfs_destroy(rpc);
	
	ATF_REQUIRE_EQ(NFS3_OK, client.au_rpc_result);

	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_success, tc)
{
	cleanup();
	remove("/mnt/NFS_audit_test/fileforaudit");
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_failure);
ATF_TC_HEAD(nfs3_mkdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a unsuccessful "
					"NFS mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_failure, tc)
{
	FILE *pipefd;
	struct rpc_context *rpc;
	struct pollfd pfd;
	struct client client;

	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_cb = nfs3_call_mkdir_cb;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	printf("res->status: %d", client.au_rpc_result);
	ATF_REQUIRE_EQ(NFS3_OK, client.au_rpc_result);
	nfs_destroy(rpc);
	memset(&client, 0, sizeof(struct client));
	
	/* mkdir rpc return error as the directory already exists. */
	pipefd = setup(fds, auclass);
	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_cb = nfs3_call_mkdir_cb;

	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	nfs_destroy(rpc);
	printf("res->status: %d", client.au_rpc_result);
	ATF_REQUIRE(NFS3_OK != client.au_rpc_result);

	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_failure, tc)
{
	cleanup();
	remove("/mnt/NFS_audit_test/fileforaudit");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_mkdir_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);

	return (atf_no_error());
}
