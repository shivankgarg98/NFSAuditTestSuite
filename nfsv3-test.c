/*-
 * Copyright (C) 2010 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
 * Copyright (C) 2020 by Shivank Garg <shivank@FreeBSD.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

static struct pollfd fds[1];
static const char *auclass = "nfs";
static char path[] = "fileforaudit";
static const char *successreg = "fileforaudit.*return,success";
static const char *failurereg = "fileforaudit.*return,failure";

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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);
	const char *regex = "nfsrvd_getattr.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_getattr_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);
	const char *regex = "nfsrvd_getattr.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_getattr_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_SETATTR, &au_test_data);
	const char *regex = "nfsrvd_setattr.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.object = *fh3;
	args.new_attributes.mode.set_it = 1;
	args.new_attributes.mode.set_mode3_u.mode = 0222;
	ATF_REQUIRE_EQ(0, rpc_nfs3_setattr_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_SETATTR, &au_test_data);
	const char *regex = "nfsrvd_setattr.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.object = *fh3;
	args.new_attributes.mode.set_it = 1;
	args.new_attributes.mode.set_mode3_u.mode = 0222;
	ATF_REQUIRE_EQ(0, rpc_nfs3_setattr_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_LOOKUP, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	LOOKUP3args args;

	args.what.dir.data.data_len = nfs->rootfh.len;
	args.what.dir.data.data_val = nfs->rootfh.val;
	args.what.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_lookup_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_LOOKUP, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	LOOKUP3args args;
	
	/* There is no file. */
	args.what.dir.data.data_len = nfs->rootfh.len;
	args.what.dir.data.data_val = nfs->rootfh.val;
	args.what.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_lookup_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_ACCESS, &au_test_data);
	FILE *pipefd;	
	ACCESS3args args;
	const char *regex = "nfsrvd_access.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.object  = *fh3;
	args.access = ACCESS3_READ;
	ATF_REQUIRE_EQ(0, rpc_nfs3_access_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_ACCESS, &au_test_data);
	FILE *pipefd;	
	ACCESS3args args;
	const char *regex = "nfsrvd_access.*return,failure";

	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.object  = *fh3;
	args.access = ACCESS3_READ | ACCESS3_EXECUTE;
	ATF_REQUIRE_EQ(0, rpc_nfs3_access_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	ATF_REQUIRE_EQ(0, symlink(path, "symlink"));

	struct au_rpc_data au_test_data;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READLINK, &au_test_data);
	FILE *pipefd;
	char buf[PATH_MAX];
	const char *regex = "nfsrvd_readlink.*return,success";

	nfs->version = NFS_V3;
	pipefd = setup(fds, auclass);
	ATF_REQUIRE_EQ(0, nfs_readlink(nfs, "symlink", buf, sizeof(buf)));
	ATF_REQUIRE_MATCH(buf, path);
	check_audit(fds, regex, pipefd);
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
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READLINK, &au_test_data);
	FILE *pipefd;
	char buf[PATH_MAX];
	const char *regex = "nfsrvd_readlink.*return,failure";

	/* The path is regular file not symlink, readlink results in error. */
	nfs->version = NFS_V3;
	pipefd = setup(fds, auclass);
	ATF_REQUIRE(nfs_readlink(nfs, path, buf, sizeof(buf)) != 0);
	check_audit(fds, regex, pipefd);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READ, &au_test_data);
	const char *regex = "nfsrvd_read.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.offset = 0;
	args.count = 1;
	ATF_REQUIRE_EQ(0, rpc_nfs3_read_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READ, &au_test_data);
	const char *regex = "nfsrvd_read.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.offset = 0;
	args.count = 1;
	ATF_REQUIRE_EQ(0, rpc_nfs3_read_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_WRITE, &au_test_data);
	const char *regex = "nfsrvd_write.*return,success";
	char buf[] = "NFS AUDIT Test Write";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_WRONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.offset = 0;
	args.count = strlen(buf);
	args.stable = FILE_SYNC;
	args.data.data_len = strlen(buf);
	args.data.data_val = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_write_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_WRITE, &au_test_data);
	const char *regex = "nfsrvd_write.*return,failure";
	char buf[] = "NFS AUDIT Test Write";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_WRONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.offset = 0;
	args.count = strlen(buf);
	args.stable = FILE_SYNC;
	args.data.data_len = strlen(buf);
	args.data.data_val = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_write_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_CREATE, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	CREATE3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.how.mode = GUARDED; /* Similiar to case if O_EXCL flag is provided with O_CREAT. */
	args.how.createhow3_u.obj_attributes.mode.set_it = 1;
	args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = 0755;
	ATF_REQUIRE_EQ(0, rpc_nfs3_create_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_CREATE, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	CREATE3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.how.mode = GUARDED; /* Similiar to case if O_EXCL flag is provided with O_CREAT. */
	args.how.createhow3_u.obj_attributes.mode.set_it = 1;
	args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = 0755;
	ATF_REQUIRE_EQ(0, rpc_nfs3_create_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_MKDIR, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	MKDIR3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 0755;
	ATF_REQUIRE_EQ(0, rpc_nfs3_mkdir_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_MKDIR, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	MKDIR3args args;

	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 0755;
	ATF_REQUIRE_EQ(0, rpc_nfs3_mkdir_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	char buf[] = "symlink";
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_SYMLINK, &au_test_data);

	pipefd = setup(fds, auclass);
	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.symlink.symlink_attributes.mode.set_it = 1;
	args.symlink.symlink_attributes.mode.set_mode3_u.mode = S_IRUSR|S_IWUSR|S_IXUSR;
	args.symlink.symlink_data = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_symlink_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	char buf[] = "symlink";
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_SYMLINK, &au_test_data);
	
	ATF_REQUIRE_EQ(0, symlink("symlink", path));
	pipefd = setup(fds, auclass);
	args.where.dir.data.data_len = nfs->rootfh.len;
	args.where.dir.data.data_val = nfs->rootfh.val;
	args.where.name = path;
	args.symlink.symlink_attributes.mode.set_it = 1;
	args.symlink.symlink_attributes.mode.set_mode3_u.mode = S_IRUSR|S_IWUSR|S_IXUSR;
	args.symlink.symlink_data = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_symlink_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_MKNOD, &au_test_data);

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
	ATF_REQUIRE_EQ(0, rpc_nfs3_mknod_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_MKNOD, &au_test_data);

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
	ATF_REQUIRE_EQ(0, rpc_nfs3_mknod_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_remove_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_GETATTR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_remove_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_RMDIR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_rmdir_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_RMDIR, &au_test_data);

	pipefd = setup(fds, auclass);
	args.object.dir.data.data_len = nfs->rootfh.len;
	args.object.dir.data.data_val = nfs->rootfh.val;
	args.object.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_rmdir_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
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
	char buf[] = "newnameforfile";
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_RENAME, &au_test_data);

	pipefd = setup(fds, auclass);
	args.from.dir.data.data_len = nfs->rootfh.len;
	args.from.dir.data.data_val = nfs->rootfh.val;
	args.from.name = path;
	args.to.dir.data.data_len = nfs->rootfh.len;
	args.to.dir.data.data_val = nfs->rootfh.val;
	args.to.name = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_rename_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
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
	char buf[] = "newnameforfile";
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_RENAME, &au_test_data);

	pipefd = setup(fds, auclass);
	args.from.dir.data.data_len = nfs->rootfh.len;
	args.from.dir.data.data_val = nfs->rootfh.val;
	args.from.name = path;
	args.to.dir.data.data_len = nfs->rootfh.len;
	args.to.dir.data.data_val = nfs->rootfh.val;
	args.to.name = buf;
	ATF_REQUIRE_EQ(0, rpc_nfs3_rename_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_rename_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_link_success);
ATF_TC_HEAD(nfs3_link_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 link RPC");
}

ATF_TC_BODY(nfs3_link_success, tc)
{
	ATF_REQUIRE(open("ATestFile", O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	LINK3args args;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_LINK, &au_test_data);
	
	ATF_REQUIRE_EQ(0, nfs_open(nfs, "ATestFile", O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.link.dir.data.data_len = nfs->rootfh.len;
	args.link.dir.data.data_val = nfs->rootfh.val;
	args.link.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_link_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, successreg, pipefd);
}

ATF_TC_CLEANUP(nfs3_link_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_link_failure);
ATF_TC_HEAD(nfs3_link_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 link RPC");
}

ATF_TC_BODY(nfs3_link_failure, tc)
{
	ATF_REQUIRE(open("ATestFile", O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	LINK3args args;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_LINK, &au_test_data);
	
	ATF_REQUIRE_EQ(0, nfs_open(nfs, "ATestFile", O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	/* Create a file with same name so that link throws an error. */
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.link.dir.data.data_len = nfs->rootfh.len;
	args.link.dir.data.data_val = nfs->rootfh.val;
	args.link.name = path;
	ATF_REQUIRE_EQ(0, rpc_nfs3_link_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, failurereg, pipefd);
}

ATF_TC_CLEANUP(nfs3_link_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_readdir_success);
ATF_TC_HEAD(nfs3_readdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 readdir RPC");
}

ATF_TC_BODY(nfs3_readdir_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READDIR, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	READDIR3args args;
	const char *regex = "nfsrvd_readdir.*return,success";

	args.dir.data.data_len = nfs->rootfh.len;
	args.dir.data.data_val = nfs->rootfh.val;
	args.cookie = 0;
	memset(&args.cookieverf, 0, sizeof(cookieverf3));
	args.count = 8192;
	ATF_REQUIRE_EQ(0, rpc_nfs3_readdir_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_readdir_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_readdir_failure);
ATF_TC_HEAD(nfs3_readdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 readdir RPC");
}

ATF_TC_BODY(nfs3_readdir_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READDIR, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	READDIR3args args;
	const char *regex = "nfsrvd_readdir.*return,failure";

	args.dir.data.data_len = nfs->rootfh.len;
	args.dir.data.data_val = nfs->rootfh.val;
	args.cookie = -1; /* Bad cookie value throws an error. */
	memset(&args.cookieverf, 0, sizeof(cookieverf3));
	args.count = 8192;
	ATF_REQUIRE_EQ(0, rpc_nfs3_readdir_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_readdir_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_readdirplus_success);
ATF_TC_HEAD(nfs3_readdirplus_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 readdirplus RPC");
}

ATF_TC_BODY(nfs3_readdirplus_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READDIRPLUS, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	READDIRPLUS3args args;
	const char *regex = "nfsrvd_readdirplus.*return,success";

	args.dir.data.data_len = nfs->rootfh.len;
	args.dir.data.data_val = nfs->rootfh.val;
	args.cookie = 0;
	memset(&args.cookieverf, 0, sizeof(cookieverf3));
	args.dircount = 8192;
	args.maxcount = 8192;
	ATF_REQUIRE_EQ(0, rpc_nfs3_readdirplus_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_readdirplus_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_readdirplus_failure);
ATF_TC_HEAD(nfs3_readdirplus_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 readdirplus RPC");
}

ATF_TC_BODY(nfs3_readdirplus_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_READDIRPLUS, &au_test_data);
	FILE *pipefd = setup(fds, auclass);	
	READDIRPLUS3args args;
	const char *regex = "nfsrvd_readdirplus.*return,failure";

	args.dir.data.data_len = nfs->rootfh.len;
	args.dir.data.data_val = nfs->rootfh.val;
	args.cookie = -1; /* Bad cookie value throws an error. */
	memset(&args.cookieverf, 0, sizeof(cookieverf3));
	args.dircount = 8192;
	args.maxcount = 8192;
	ATF_REQUIRE_EQ(0, rpc_nfs3_readdirplus_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_readdirplus_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_fsstat_success);
ATF_TC_HEAD(nfs3_fsstat_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 fsstat RPC");
}

ATF_TC_BODY(nfs3_fsstat_success, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	FSSTAT3args args;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_FSSTAT, &au_test_data);
	const char *regex = "nfsrvd_statfs.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.fsroot = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_fsstat_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_fsstat_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_fsstat_failure);
ATF_TC_HEAD(nfs3_fsstat_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 fsstat RPC");
}

ATF_TC_BODY(nfs3_fsstat_failure, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	FSSTAT3args args;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_FSSTAT, &au_test_data);
	const char *regex = "nfsrvd_statfs.*return,failure";

	/* Remove the directory to get a stale file handle error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.fsroot = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_fsstat_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_fsstat_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_fsinfo_success);
ATF_TC_HEAD(nfs3_fsinfo_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 fsinfo RPC");
}

ATF_TC_BODY(nfs3_fsinfo_success, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	FSINFO3args args;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_FSINFO, &au_test_data);
	const char *regex = "nfsrvd_fsinfo.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.fsroot = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_fsinfo_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_fsinfo_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_fsinfo_failure);
ATF_TC_HEAD(nfs3_fsinfo_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 fsinfo RPC");
}

ATF_TC_BODY(nfs3_fsinfo_failure, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(path, 0755));

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	FSINFO3args args;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_FSINFO, &au_test_data);
	const char *regex = "nfsrvd_fsinfo.*return,failure";

	/* Remove the directory to get a stale file handle error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.fsroot = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_fsinfo_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_fsinfo_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_pathconf_success);
ATF_TC_HEAD(nfs3_pathconf_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 pathconf RPC");
}

ATF_TC_BODY(nfs3_pathconf_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	PATHCONF3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_PATHCONF, &au_test_data);
	const char *regex = "nfsrvd_pathconf.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_pathconf_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_pathconf_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_pathconf_failure);
ATF_TC_HEAD(nfs3_pathconf_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 pathconf RPC");
}

ATF_TC_BODY(nfs3_pathconf_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	PATHCONF3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_PATHCONF, &au_test_data);
	const char *regex = "nfsrvd_pathconf.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	/* Remove the file. The resulting error is Stale NFS file handle. */
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.object = *fh3;
	ATF_REQUIRE_EQ(0, rpc_nfs3_pathconf_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_pathconf_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_commit_success);
ATF_TC_HEAD(nfs3_commit_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 commit RPC");
}

ATF_TC_BODY(nfs3_commit_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	COMMIT3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_COMMIT, &au_test_data);
	const char *regex = "nfsrvd_commit.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.offset = 0;
	args.count = 0;
	ATF_REQUIRE_EQ(0, rpc_nfs3_commit_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE_EQ(NFS3_OK, au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_commit_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_commit_failure);
ATF_TC_HEAD(nfs3_commit_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 commit RPC");
}

ATF_TC_BODY(nfs3_commit_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	FILE *pipefd;
	COMMIT3args args;
	struct nfsfh *nfsfh = NULL;
	struct nfs_fh3 *fh3;
	struct nfs_context *nfs = tc_body_init(AUE_NFS3RPC_COMMIT, &au_test_data);
	const char *regex = "nfsrvd_commit.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	fh3 = (struct nfs_fh3 *)nfs_get_fh(nfsfh);
	ATF_REQUIRE_EQ(0, remove(path));
	pipefd = setup(fds, auclass);
	args.file = *fh3;
	args.offset = 0;
	args.count = 0;
	ATF_REQUIRE_EQ(0, rpc_nfs3_commit_async(nfs->rpc,
	    (rpc_cb)nfs_res_close_cb, &args, &au_test_data));
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(nfs, &au_test_data));
	ATF_REQUIRE(NFS3_OK != au_test_data.au_rpc_result);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs3_commit_failure, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_getattr_success);
	ATF_TP_ADD_TC(tp, nfs3_getattr_failure);
	ATF_TP_ADD_TC(tp, nfs3_setattr_success);
	ATF_TP_ADD_TC(tp, nfs3_setattr_failure);
	ATF_TP_ADD_TC(tp, nfs3_lookup_success);
	ATF_TP_ADD_TC(tp, nfs3_lookup_failure);
	ATF_TP_ADD_TC(tp, nfs3_access_success);
	ATF_TP_ADD_TC(tp, nfs3_access_failure);
	ATF_TP_ADD_TC(tp, nfs3_readlink_success);
	ATF_TP_ADD_TC(tp, nfs3_readlink_failure);
	ATF_TP_ADD_TC(tp, nfs3_read_success);
	ATF_TP_ADD_TC(tp, nfs3_read_failure);
	ATF_TP_ADD_TC(tp, nfs3_write_success);
	ATF_TP_ADD_TC(tp, nfs3_write_failure);
	ATF_TP_ADD_TC(tp, nfs3_create_success);
	ATF_TP_ADD_TC(tp, nfs3_create_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_failure);
	ATF_TP_ADD_TC(tp, nfs3_symlink_success);
	ATF_TP_ADD_TC(tp, nfs3_symlink_failure);
	ATF_TP_ADD_TC(tp, nfs3_mknod_success);
	ATF_TP_ADD_TC(tp, nfs3_mknod_failure);
	ATF_TP_ADD_TC(tp, nfs3_remove_success);
	ATF_TP_ADD_TC(tp, nfs3_remove_failure);
	ATF_TP_ADD_TC(tp, nfs3_rmdir_success);
	ATF_TP_ADD_TC(tp, nfs3_rmdir_failure);
	ATF_TP_ADD_TC(tp, nfs3_rename_success);
	ATF_TP_ADD_TC(tp, nfs3_rename_failure);
	ATF_TP_ADD_TC(tp, nfs3_link_success);
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

	return (atf_no_error());
}
