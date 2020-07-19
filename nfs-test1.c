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
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

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
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
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

	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE(remove(path) == 0);
	pipefd = setup(fds, auclass);

	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_getattr_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

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
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	SETATTR3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_SETATTR, &au_test_data);
	const char *regex = "nfsrvd_setattr.*return,success";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	pipefd = setup(fds, auclass);

	args.object = *fh3;
	args.new_attributes.mode.set_it = 1;
	args.new_attributes.mode.set_mode3_u.mode = 0222;
	ATF_REQUIRE_EQ(0, rpc_nfs3_setattr_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}
ATF_TC_CLEANUP(nfs3_setattr_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_setattr_failure);
ATF_TC_HEAD(nfs3_setattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 setattr RPC");
}
ATF_TC_BODY(nfs3_setattr_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	SETATTR3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_SETATTR, &au_test_data);
	const char *regex = "nfsrvd_setattr.*return,failure";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE(remove(path) == 0);
	pipefd = setup(fds, auclass);

	args.object = *fh3;
	args.new_attributes.mode.set_it = 1;
	args.new_attributes.mode.set_mode3_u.mode = 0222;
	ATF_REQUIRE_EQ(0, rpc_nfs3_setattr_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_setattr_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_lookup_success);
ATF_TC_HEAD(nfs3_lookup_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 lookup RPC");
}

ATF_TC_BODY(nfs3_lookup_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_LOOKUP, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	LOOKUP3args args;

	args.what.dir.data.data_len = nfs->rootfh.len;
	args.what.dir.data.data_val = nfs->rootfh.val;
	args.what.name = path;
	ATF_REQUIRE(rpc_nfs3_lookup_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_lookup_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_lookup_failure);
ATF_TC_HEAD(nfs3_lookup_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 lookup RPC");
}

ATF_TC_BODY(nfs3_lookup_failure, tc)
{
	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_LOOKUP, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	LOOKUP3args args;
	
	/* There is no file. */
	args.what.dir.data.data_len = nfs->rootfh.len;
	args.what.dir.data.data_val = nfs->rootfh.val;
	args.what.name = path;
	ATF_REQUIRE(rpc_nfs3_lookup_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_lookup_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_access_success);
ATF_TC_HEAD(nfs3_access_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 access RPC");
}

ATF_TC_BODY(nfs3_access_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_ACCESS, &au_test_data);
	FILE *pipefd;	
	ACCESS3args args;
	const char *regex = "nfsrvd_access.*return,success";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	pipefd = setup(fds, auclass);
	args.object  = *fh3;
	args.access = ACCESS3_READ;
	ATF_REQUIRE(rpc_nfs3_access_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_access_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_access_failure);
ATF_TC_HEAD(nfs3_access_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 access RPC");
}

ATF_TC_BODY(nfs3_access_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0222) != -1);
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_ACCESS, &au_test_data);
	FILE *pipefd;	
	ACCESS3args args;
	const char *regex = "nfsrvd_access.*return,failure";

	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE(remove(path) == 0);

	pipefd = setup(fds, auclass);
	args.object  = *fh3;
	args.access = ACCESS3_READ | ACCESS3_EXECUTE;
	ATF_REQUIRE(rpc_nfs3_access_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_access_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_readlink_success);
ATF_TC_HEAD(nfs3_readlink_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 readlink RPC");
}

ATF_TC_BODY(nfs3_readlink_success, tc)
{
	ATF_REQUIRE(symlink("symlink", path) == 0);
	struct nfs_fh3 *fh3;
	struct nfsfh *nfsfh = NULL;
	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_READLINK, &au_test_data);
	FILE *pipefd;	
	READLINK3args args;
	
	ATF_REQUIRE(nfs_open(nfs, path, O_RDWR, &nfsfh) == 0);
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	
	args.symlink = *fh3;
	ATF_REQUIRE(rpc_nfs3_readlink_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_readlink_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_readlink_failure);
ATF_TC_HEAD(nfs3_readlink_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 readlink RPC");
}

ATF_TC_BODY(nfs3_readlink_failure, tc)
{
	ATF_REQUIRE_MSG(1==0, "readlink success is failing too due to nfs_open");
}

ATF_TC_CLEANUP(nfs3_readlink_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_read_success);
ATF_TC_HEAD(nfs3_read_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 read RPC");
}

ATF_TC_BODY(nfs3_read_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	READ3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_READ, &au_test_data);
	const char *regex = "nfsrvd_read.*return,success";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	pipefd = setup(fds, auclass);

	args.file = *fh3;
	args.offset = 0;
	args.count = 1;
	ATF_REQUIRE_EQ(0, rpc_nfs3_read_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_read_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_read_failure);
ATF_TC_HEAD(nfs3_read_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 read RPC");
}

ATF_TC_BODY(nfs3_read_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	READ3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_READ, &au_test_data);
	const char *regex = "nfsrvd_read.*return,failure";

	ATF_REQUIRE(nfs_open(nfs, path, O_RDONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	ATF_REQUIRE(remove(path) == 0);
	pipefd = setup(fds, auclass);

	args.file = *fh3;
	args.offset = 0;
	args.count = 1;
	ATF_REQUIRE_EQ(0, rpc_nfs3_read_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_read_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_write_success);
ATF_TC_HEAD(nfs3_write_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 write RPC");
}

ATF_TC_BODY(nfs3_write_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	WRITE3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_WRITE, &au_test_data);
	const char *regex = "nfsrvd_write.*return,success";
	char *buf = "NFS AUDIT Test Write";

	ATF_REQUIRE(nfs_open(nfs, path, O_WRONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	pipefd = setup(fds, auclass);

	args.file = *fh3;
	args.offset = 0;
	args.count = strlen(buf);
	args.stable = FILE_SYNC;
	args.data.data_len = strlen(buf);
	args.data.data_val = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_write_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_write_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_write_failure);
ATF_TC_HEAD(nfs3_write_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 write RPC");
}

ATF_TC_BODY(nfs3_write_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	WRITE3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_WRITE, &au_test_data);
	const char *regex = "nfsrvd_write.*return,failure";
	char *buf = "NFS AUDIT Test Write";

	ATF_REQUIRE(nfs_open(nfs, path, O_WRONLY, &nfsfh) == 0);
	fh3  = (struct nfs_fh3 *)nfs_get_fh(nfsfh);

	ATF_REQUIRE(remove(path) == 0);
	pipefd = setup(fds, auclass);

	args.file = *fh3;
	args.offset = 0;
	args.count = strlen(buf);
	args.stable = FILE_SYNC;
	args.data.data_len = strlen(buf);
	args.data.data_val = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_write_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_write_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_create_success);
ATF_TC_HEAD(nfs3_create_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_success, tc)
{
	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_CREATE, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	CREATE3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.how.mode = GUARDED; /* Similiar to case if O_EXCL flag is provided with O_CREAT. */
	args.how.createhow3_u.obj_attributes.mode.set_it = 1;
	args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = 0755;

	ATF_REQUIRE(rpc_nfs3_create_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);	
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
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
	/* The RPC result status is an error as file already exits. */
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_CREATE, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	CREATE3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.how.mode = GUARDED; /* Similiar to case if O_EXCL flag is provided with O_CREAT. */
	args.how.createhow3_u.obj_attributes.mode.set_it = 1;
	args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = 0755;

	ATF_REQUIRE(rpc_nfs3_create_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data) == 0);	
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
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
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

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
	/* The RPC result status is an error as file already exits. */
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
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mkdir_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_symlink_success);
ATF_TC_HEAD(nfs3_symlink_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 symlink RPC");
}

ATF_TC_BODY(nfs3_symlink_success, tc)
{
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	SYMLINK3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_SYMLINK, &au_test_data);

	pipefd = setup(fds, auclass);
	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.symlink.symlink_attributes.mode.set_it = 1;
	args.symlink.symlink_attributes.mode.set_mode3_u.mode = S_IRUSR|S_IWUSR|S_IXUSR;
	args.symlink.symlink_data = "symlink";
	ATF_REQUIRE_EQ(0, rpc_nfs3_symlink_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_symlink_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_symlink_failure);
ATF_TC_HEAD(nfs3_symlink_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 symlink RPC");
}

ATF_TC_BODY(nfs3_symlink_failure, tc)
{
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	SYMLINK3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_SYMLINK, &au_test_data);
	
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	pipefd = setup(fds, auclass);
	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.symlink.symlink_attributes.mode.set_it = 1;
	args.symlink.symlink_attributes.mode.set_mode3_u.mode = S_IRUSR|S_IWUSR|S_IXUSR;
	args.symlink.symlink_data = "symlink";
	ATF_REQUIRE_EQ(0, rpc_nfs3_symlink_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_symlink_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_mknod_success);
ATF_TC_HEAD(nfs3_mknod_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 mknod RPC");
}

ATF_TC_BODY(nfs3_mknod_success, tc)
{
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	MKNOD3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_MKNOD, &au_test_data);

	pipefd = setup(fds, auclass);
	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	/* Make a character special device. */
	args.what.type = NF3CHR;
	args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_it = 1;
	args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_mode3_u.mode = S_IRUSR|S_IWUSR|S_IXUSR;
	args.what.mknoddata3_u.chr_device.spec.specdata1 = 1; /* Major Number */
	args.what.mknoddata3_u.chr_device.spec.specdata2 = 1; /* Minor Number */

	ATF_REQUIRE_EQ(0, rpc_nfs3_mknod_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mknod_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_mknod_failure);
ATF_TC_HEAD(nfs3_mknod_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 mknod RPC");
}

ATF_TC_BODY(nfs3_mknod_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	MKNOD3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_MKNOD, &au_test_data);

	pipefd = setup(fds, auclass);
	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	/* Make a character special device. */
	args.what.type = NF3CHR;
	args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_it = 1;
	args.what.mknoddata3_u.chr_device.dev_attributes.mode.set_mode3_u.mode = S_IRUSR|S_IWUSR|S_IXUSR;
	args.what.mknoddata3_u.chr_device.spec.specdata1 = 1; /* Major Number */
	args.what.mknoddata3_u.chr_device.spec.specdata2 = 1; /* Minor Number */

	ATF_REQUIRE_EQ(0, rpc_nfs3_mknod_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_mknod_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_remove_success);
ATF_TC_HEAD(nfs3_remove_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 remove RPC");
}

ATF_TC_BODY(nfs3_remove_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	REMOVE3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_remove_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_remove_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_remove_failure);
ATF_TC_HEAD(nfs3_remove_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 remove RPC");
}

ATF_TC_BODY(nfs3_remove_failure, tc)
{
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	REMOVE3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_remove_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_remove_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_rmdir_success);
ATF_TC_HEAD(nfs3_rmdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 rmdir RPC");
}

ATF_TC_BODY(nfs3_rmdir_success, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	RMDIR3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_RMDIR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_rmdir_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_rmdir_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_rmdir_failure);
ATF_TC_HEAD(nfs3_rmdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 rmdir RPC");
}

ATF_TC_BODY(nfs3_rmdir_failure, tc)
{
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	RMDIR3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_RMDIR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_rmdir_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_rmdir_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_rename_success);
ATF_TC_HEAD(nfs3_rename_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 rename RPC");
}

ATF_TC_BODY(nfs3_rename_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	RENAME3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_RENAME, &au_test_data);

	pipefd = setup(fds, auclass);
	args.from.dir.data.data_len = nfs->rootfh.len;
	args.from.dir.data.data_val = nfs->rootfh.val;
	args.from.name = path;
	args.to.dir.data.data_len = nfs->rootfh.len;
	args.to.dir.data.data_val = nfs->rootfh.val;
	args.to.name = "newnameforfile";
	ATF_REQUIRE_EQ(0, rpc_nfs3_rename_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK == au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_rename_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_rename_failure);
ATF_TC_HEAD(nfs3_rename_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 rename RPC");
}

ATF_TC_BODY(nfs3_rename_failure, tc)
{
	struct au_rpc_data au_test_data;
	FILE *pipefd;
	RENAME3args args;
	struct nfs_context* nfs = tc_body_init(AUE_NFS3RPC_RENAME, &au_test_data);

	pipefd = setup(fds, auclass);
	args.from.dir.data.data_len = nfs->rootfh.len;
	args.from.dir.data.data_val = nfs->rootfh.val;
	args.from.name = path;
	args.to.dir.data.data_len = nfs->rootfh.len;
	args.to.dir.data.data_val = nfs->rootfh.val;
	args.to.name = "newnameforfile";
	ATF_REQUIRE_EQ(0, rpc_nfs3_rename_async(nfs->rpc, (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE(nfs_poll_fd(nfs, &au_test_data) == RPC_STATUS_SUCCESS);

	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_rename_failure, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_getattr_success);//done
	ATF_TP_ADD_TC(tp, nfs3_getattr_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_setattr_success);//done
	ATF_TP_ADD_TC(tp, nfs3_setattr_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_lookup_success);//done
	ATF_TP_ADD_TC(tp, nfs3_lookup_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_access_success);//done
	ATF_TP_ADD_TC(tp, nfs3_access_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_readlink_success);//problem
	ATF_TP_ADD_TC(tp, nfs3_readlink_failure);//problem
	ATF_TP_ADD_TC(tp, nfs3_read_success);//done
	ATF_TP_ADD_TC(tp, nfs3_read_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_write_success);//done
	ATF_TP_ADD_TC(tp, nfs3_write_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_create_success);//done
	ATF_TP_ADD_TC(tp, nfs3_create_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);//done
	ATF_TP_ADD_TC(tp, nfs3_mkdir_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_symlink_success);//done
	ATF_TP_ADD_TC(tp, nfs3_symlink_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_mknod_success);//done
	ATF_TP_ADD_TC(tp, nfs3_mknod_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_remove_success);//done
	ATF_TP_ADD_TC(tp, nfs3_remove_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_rmdir_success);//done
	ATF_TP_ADD_TC(tp, nfs3_rmdir_failure);//done
	ATF_TP_ADD_TC(tp, nfs3_rename_success);//done
	ATF_TP_ADD_TC(tp, nfs3_rename_failure);//done
/*	ATF_TP_ADD_TC(tp, nfs3_link_success);
	ATF_TP_ADD_TC(tp, nfs3_link_failure);
	ATF_TP_ADD_TC(tp, nfs3_readdir_success);
	ATF_TP_ADD_TC(tp, nfs3_readdir_failure);
	ATF_TP_ADD_TC(tp, nfs3_readdirplus_success);
	ATF_TP_ADD_TC(tp, nfs3_readdirplus_failure);
	ATF_TP_ADD_TC(tp, nfs3_fsstat_success);
	ATF_TP_ADD_TC(tp, nfs3_fsstat_failure);
	ATF_TP_ADD_TC(tp, nfs3_fsinfo_success);
	ATF_TP_ADD_TC(tp, nfs3_fsinfo_failure);
	ATF_TP_ADD_TC(tp, nfs3_pathconf_success);
	ATF_TP_ADD_TC(tp, nfs3_pathconf_failure);
	ATF_TP_ADD_TC(tp, nfs3_commit_success);
	ATF_TP_ADD_TC(tp, nfs3_commit_failure);
*/
	return (atf_no_error());
}
