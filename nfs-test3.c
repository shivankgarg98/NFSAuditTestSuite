#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

static char *SERVER = "192.168.56.105";
static char *EXPORT = "/mnt/NFS_audit_test";

static struct pollfd fds[1];
static mode_t mode = 0777;
static const char *auclass = "nfs";
static char *client_path = "fileforaudit";
static char *server_path = "/mnt/NFS_audit_test/fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";


ATF_TC_WITH_CLEANUP(nfs3_create_success);
ATF_TC_HEAD(nfs3_create_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_success, tc)
{
	FILE *pipefd = setup(fds, auclass);
	struct rpc_context *rpc;
	struct client client;

	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_event = AUE_NFS3RPC_CREATE;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);

	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	nfs_destroy(rpc);

	ATF_REQUIRE_EQ(NFS3_OK, client.au_rpc_result);

	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_create_success, tc)
{
	cleanup();
	remove(server_path);
}

ATF_TC_WITH_CLEANUP(nfs3_create_failure);
ATF_TC_HEAD(nfs3_create_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_failure, tc)
{
	FILE *pipefd = setup(fds, auclass);
	struct rpc_context *rpc;
	struct client client;
	char buf[111];
	getcwd(buf,111);
	printf("********************%s\n",buf);

	ATF_REQUIRE(open(server_path, O_CREAT, mode) != -1);	
	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_event = AUE_NFS3RPC_CREATE;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);

	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	nfs_destroy(rpc);

	ATF_REQUIRE(NFS3_OK != client.au_rpc_result);

	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_create_failure, tc)
{
	cleanup();
	remove(server_path);
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_success);
ATF_TC_HEAD(nfs3_mkdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_success, tc)
{
	FILE *pipefd = setup(fds, auclass);
	struct rpc_context *rpc;
	struct client client;

	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_event = AUE_NFS3RPC_MKDIR;
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
	remove(server_path);
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_failure);
ATF_TC_HEAD(nfs3_mkdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a unsuccessful "
					"NFSv3 mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_failure, tc)
{
	FILE *pipefd;
	struct rpc_context *rpc;
	struct client client;

/*	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_event = AUE_NFS3RPC_MKDIR;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	printf("res->status: %d", client.au_rpc_result);
	ATF_REQUIRE_EQ(NFS3_OK, client.au_rpc_result);
	nfs_destroy(rpc);
	memset(&client, 0, sizeof(struct client));
*/
	ATF_REQUIRE_EQ(0, mkdir(server_path, mode));
	/* mkdir rpc return error as the directory already exists. */
	pipefd = setup(fds, auclass);
	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	client.au_rpc_event = AUE_NFS3RPC_MKDIR;

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
	remove(server_path);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_create_success);
	ATF_TP_ADD_TC(tp, nfs3_create_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);

	return (atf_no_error());
}
