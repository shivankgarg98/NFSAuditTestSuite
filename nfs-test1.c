#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

static char *path = "fileforaudit";
static char *successreg = "fileforaudit.*return,success";
static char *failurereg = "fileforaudit.*return,failure";

ATF_TC_WITH_CLEANUP(nfs3_getattr_success);
ATF_TC_HEAD(nfs3_getattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 getattr RPC");
}

ATF_TC_BODY(nfs3_getattr_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	GETATTR3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);
	const char *regex = "nfsrvd_getattr.*return,success";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	pipefd = setup(fds, auclass);

	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_getattr_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs,&au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_getattr_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_getattr_failure);
ATF_TC_HEAD(nfs3_getattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 getattr RPC");
}

ATF_TC_BODY(nfs3_getattr_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	GETATTR3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);
	const char *regex = "nfsrvd_getattr.*return,failure";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	ATF_REQUIRE(remove(path) == 0);
	pipefd = setup(fds, auclass);

	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_getattr_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs,&au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}
ATF_TC_CLEANUP(nfs3_getattr_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_setattr_success);
ATF_TC_HEAD(nfs3_setattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 setattr RPC");
}
ATF_TC_BODY(nfs3_setattr_success, tc)
{
}
ATF_TC_CLEANUP(nfs3_setattr_success, tc)
{
}

ATF_TC_WITH_CLEANUP(nfs3_setattr_failure);
ATF_TC_HEAD(nfs3_setattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 setattr RPC");
}
ATF_TC_BODY(nfs3_setattr_failure, tc)
{
}
ATF_TC_CLEANUP(nfs3_setattr_failure, tc)
{
}

ATF_TC_WITH_CLEANUP(nfs3_lookup_success);
ATF_TC_HEAD(nfs3_lookup_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 lookup RPC");
}
ATF_TC_BODY(nfs3_lookup_success, tc)
{
}
ATF_TC_CLEANUP(nfs3_lookup_success, tc)
{
}

ATF_TC_WITH_CLEANUP(nfs3_lookup_failure);
ATF_TC_HEAD(nfs3_lookup_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 lookup RPC");
}
ATF_TC_BODY(nfs3_lookup_failure, tc)
{
}
ATF_TC_CLEANUP(nfs3_lookup_failure, tc)
{
}


ATF_TC_WITH_CLEANUP(nfs3_create_success);
ATF_TC_HEAD(nfs3_create_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_success, tc)
{
//	tc_body_helper(AUE_NFS3RPC_CREATE, SUCCESS, successreg);
}

ATF_TC_CLEANUP(nfs3_create_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_create_failure);
ATF_TC_HEAD(nfs3_create_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_failure, tc)
{

//	ATF_REQUIRE(open(path, O_CREAT, mode) != -1);	
//	tc_body_helper(AUE_NFS3RPC_CREATE, FAILURE, failurereg);
}

ATF_TC_CLEANUP(nfs3_create_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_success);
ATF_TC_HEAD(nfs3_mkdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_success, tc)
{
	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_MKDIR, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	MKDIR3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 0755;
	ATF_REQUIRE(rpc_nfs3_mkdir_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs,&au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_failure);
ATF_TC_HEAD(nfs3_mkdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a unsuccessful "
					"NFSv3 mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_failure, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));

	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_MKDIR, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	MKDIR3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 0755;
	ATF_REQUIRE(rpc_nfs3_mkdir_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs,&au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_failure, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_getattr_success);
	ATF_TP_ADD_TC(tp, nfs3_getattr_failure);
//	ATF_TP_ADD_TC(tp, nfs3_create_success);
//	ATF_TP_ADD_TC(tp, nfs3_create_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_failure);

	return (atf_no_error());
}
