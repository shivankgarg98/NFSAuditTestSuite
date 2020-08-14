#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

static uint32_t standard_attributes[2] = {
	(1 << FATTR4_TYPE |
	1 << FATTR4_SIZE |
	1 << FATTR4_FILEID),
	(1 << (FATTR4_MODE - 32) |
	1 << (FATTR4_NUMLINKS - 32) |
	1 << (FATTR4_OWNER - 32) |
	1 << (FATTR4_OWNER_GROUP - 32) |
	1 << (FATTR4_SPACE_USED - 32) |
	1 << (FATTR4_TIME_ACCESS - 32) |
	1 << (FATTR4_TIME_METADATA - 32) |
	1 << (FATTR4_TIME_MODIFY - 32))
};

static struct pollfd fds[1];
static const char *auclass = "nfs";
static char path[] = "fileforaudit";
//static const char *successreg = "fileforaudit.*return,success";
//static const char *failurereg = "fileforaudit.*return,failure";

#define NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, IsSuccess)	\
do {									\
	FILE *pipefd = setup(fds, auclass);				\
	COMPOUND4args args;						\
	memset(&args, 0, sizeof(args));					\
	args.argarray.argarray_len = (i);				\
	args.argarray.argarray_val = (op);				\
	ATF_REQUIRE_EQ(0, rpc_nfs4_compound_async((nfs)->rpc,		\
	    (rpc_cb)nfsv4_res_close_cb, &args, &(au_test_data)));	\
	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS,				\
	    nfs_poll_fd((nfs), &(au_test_data)));			\
	if (IsSuccess)							\
		ATF_REQUIRE_EQ(NFS3_OK, (au_test_data).au_rpc_result);	\
	else								\
		ATF_REQUIRE(NFS3_OK != (au_test_data).au_rpc_result);	\
	check_audit(fds, (regex), pipefd);				\
} while (0)

static int
nfs4_op_access(__unused struct nfs_context *nfs, nfs_argop4 *op, uint32_t access_mask)
{
	ACCESS4args *aargs;

	op[0].argop = OP_ACCESS;
	aargs = &op[0].nfs_argop4_u.opaccess;
	memset(aargs, 0, sizeof(*aargs));
	aargs->access = access_mask;

	return 1;
}

static int
nfs4_op_commit(__unused struct nfs_context *nfs, nfs_argop4 *op)
{
	COMMIT4args *coargs;

	op[0].argop = OP_COMMIT;
	coargs = &op[0].nfs_argop4_u.opcommit;
	coargs->offset = 0;
	coargs->count = 0;

	return 1;
}

static int
nfs4_op_close(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh)
{
	CLOSE4args *clargs;
	int i = 0;

	if (fh->is_dirty) {
	        i += nfs4_op_commit(nfs, &op[i]);
	}

	op[i].argop = OP_CLOSE;
	clargs = &op[i++].nfs_argop4_u.opclose;
	clargs->seqid = nfs->seqid;
	clargs->open_stateid.seqid = fh->stateid.seqid;
	memcpy(clargs->open_stateid.other, fh->stateid.other, 12);

	return i;
}

static int
nfs4_op_putfh(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *nfsfh)
{
	PUTFH4args *pfargs;

	op[0].argop = OP_PUTFH;
	pfargs = &op[0].nfs_argop4_u.opputfh;
	pfargs->object.nfs_fh4_len = nfsfh->fh.len;
	pfargs->object.nfs_fh4_val = nfsfh->fh.val;

	return 1;
}

static int
nfs4_op_getattr(__unused struct nfs_context *nfs, nfs_argop4 *op,
                uint32_t *attributes, int count)
{
	GETATTR4args *gaargs;

	op[0].argop = OP_GETATTR;
	gaargs = &op[0].nfs_argop4_u.opgetattr;
	memset(gaargs, 0, sizeof(*gaargs));

	gaargs->attr_request.bitmap4_val = attributes;
	gaargs->attr_request.bitmap4_len = count;

	return 1;
}

ATF_TC_WITH_CLEANUP(nfs4_access_success);
ATF_TC_HEAD(nfs4_access_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 Access RPC");
}

ATF_TC_BODY(nfs4_access_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_ACCESS, &au_test_data);
	const char *regex = "nfsrvd_access.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_access(nfs, &op[i], ACCESS4_READ);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_access_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_access_failure);
ATF_TC_HEAD(nfs4_access_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 Access RPC");
}

ATF_TC_BODY(nfs4_access_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_ACCESS, &au_test_data);
	const char *regex = "nfsrvd_access.*return,failure";

	/* NFSv4 ACCESS sub-operation will fail due to invalid use. (no PUTFH subop) */
	i = nfs4_op_access(nfs, &op[0], ACCESS4_DELETE);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_access_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_close_success);
ATF_TC_HEAD(nfs4_close_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 close RPC");
}

ATF_TC_BODY(nfs4_close_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_CLOSE, &au_test_data);
	const char *regex = "nfsrvd_close.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_close(nfs, &op[i], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_close_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_getattr_success);
ATF_TC_HEAD(nfs4_getattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 getattr RPC");
}

ATF_TC_BODY(nfs4_getattr_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_GETATTR, &au_test_data);
	const char *regex = "nfsrvd_getattr.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_getattr(nfs, &op[i], standard_attributes, 2);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_getattr_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_getattr_failure);
ATF_TC_HEAD(nfs4_getattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 getattr RPC");
}

ATF_TC_BODY(nfs4_getattr_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_GETATTR, &au_test_data);
	const char *regex = "nfsrvd_getattr.*return,failure";

	/* NFSv4 GETATTR sub-operation will fail due to invalid use. (no PUTFH subop) */
	i = nfs4_op_getattr(nfs, &op[0], standard_attributes, 2);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_getattr_failure, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs4_access_success);
	ATF_TP_ADD_TC(tp, nfs4_access_failure);
	ATF_TP_ADD_TC(tp, nfs4_close_success);
//	ATF_TP_ADD_TC(tp, nfs4_close_failure);
	ATF_TP_ADD_TC(tp, nfs4_getattr_success);
	ATF_TP_ADD_TC(tp, nfs4_getattr_failure);

	return (atf_no_error());
}
