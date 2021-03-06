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
		ATF_REQUIRE_EQ(NFS4_OK, (au_test_data).au_rpc_result);	\
	else								\
		ATF_REQUIRE(NFS4_OK != (au_test_data).au_rpc_result);	\
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
nfs4_op_create_char(__unused struct nfs_context *nfs, nfs_argop4 *op)
{
	CREATE4args *cargs;
	uint32_t attrmask[2];
	uint32_t attr_vals[1];

	op[0].argop = OP_CREATE;
	cargs = &op[0].nfs_argop4_u.opcreate;
	memset(cargs, 0, sizeof(*cargs));
	cargs->objname.utf8string_len = strlen(path);
	cargs->objname.utf8string_val = path;
	attrmask[0] = 0;
	attrmask[1] = 1 << (FATTR4_MODE - 32);
	cargs->createattrs.attrmask.bitmap4_len = 2;
	cargs->createattrs.attrmask.bitmap4_val = attrmask;
	attr_vals[0] = S_IFMT | S_IFCHR;
	cargs->createattrs.attr_vals.attrlist4_len = 4;
	cargs->createattrs.attr_vals.attrlist4_val = (char *)attr_vals;
	cargs->objtype.type = NF4CHR;
	cargs->objtype.createtype4_u.devdata.specdata1 = 1;
	cargs->objtype.createtype4_u.devdata.specdata2 = 1;

	return 1;
}

static int
nfs4_op_close(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh)
{
	CLOSE4args *clargs;

	op[0].argop = OP_CLOSE;
	clargs = &op[0].nfs_argop4_u.opclose;
	memset(clargs, 0, sizeof(*clargs));
	clargs->seqid = nfs->seqid;
	clargs->open_stateid.seqid = fh->stateid.seqid;
	memcpy(clargs->open_stateid.other, fh->stateid.other, 12);

	return 1;
}
static int
nfs4_op_delepurge(struct nfs_context *nfs, nfs_argop4 *op)
{
	DELEGPURGE4args *dpargs;

	op[0].argop = OP_DELEGPURGE;
	dpargs = &op[0].nfs_argop4_u.opdelegpurge;
	memset(dpargs, 0, sizeof(*dpargs));
	dpargs->clientid = nfs->clientid;

	return 1;
}

static int
nfs4_op_delegreturn(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh)
{
	DELEGRETURN4args *drargs;

	op[0].argop = OP_DELEGRETURN;
	drargs = &op[0].nfs_argop4_u.opdelegreturn;
	memset(drargs, 0, sizeof(*drargs));
	drargs->deleg_stateid.seqid = fh->stateid.seqid;
	memcpy(drargs->deleg_stateid.other, fh->stateid.other, 12);

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

static int
nfs4_op_getfh(__unused struct nfs_context *nfs, nfs_argop4 *op)
{
	op[0].argop = OP_GETFH;

	return 1;
}

static int
nfs4_op_link(__unused struct nfs_context *nfs, nfs_argop4 *op, char *newname)
{
	LINK4args *largs;

	op[0].argop = OP_LINK;
	largs = &op[0].nfs_argop4_u.oplink;
	memset(largs, 0, sizeof(*largs));
	largs->newname.utf8string_len = strlen(newname);
	largs->newname.utf8string_val = newname;

	return 1;
}

static int
nfs4_op_lock(struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh,
    nfs_opnum4 cmd, nfs_lock_type4 locktype,
    int reclaim, uint64_t offset, length4 length)
{
	LOCK4args *largs;

	op[0].argop = cmd;
	largs = &op[0].nfs_argop4_u.oplock;
	memset(largs, 0, sizeof(*largs));
	largs->locktype = locktype;
	largs->reclaim  = reclaim;
	largs->offset   = offset;
	largs->length   = length;

	if (nfs->has_lock_owner) {
		largs->locker.new_lock_owner = 0;
		largs->locker.locker4_u.lock_owner.lock_stateid.seqid =
		    fh->lock_stateid.seqid;
		memcpy(largs->locker.locker4_u.lock_owner.lock_stateid.other,
		    fh->lock_stateid.other, 12);
		largs->locker.locker4_u.lock_owner.lock_seqid =
		    fh->lock_seqid;
	} else {
		largs->locker.new_lock_owner = 1;
		largs->locker.locker4_u.open_owner.open_seqid =
		    nfs->seqid;
		largs->locker.locker4_u.open_owner.open_stateid.seqid =
		    fh->stateid.seqid;
		memcpy(largs->locker.locker4_u.open_owner.open_stateid.other,
		    fh->stateid.other, 12);
		largs->locker.locker4_u.open_owner.lock_owner.clientid =
		    nfs->clientid;
		largs->locker.locker4_u.open_owner.lock_owner.owner.owner_len =
		    strlen(nfs->client_name);
		largs->locker.locker4_u.open_owner.lock_owner.owner.owner_val =
		    nfs->client_name;
		largs->locker.locker4_u.open_owner.lock_seqid =
		    fh->lock_seqid;
	}
	fh->lock_seqid++;

	return 1;
}

static int
nfs4_op_lockt(struct nfs_context *nfs, nfs_argop4 *op, __unused struct nfsfh *fh,
              nfs_lock_type4 locktype, uint64_t offset, length4 length)
{
	LOCKT4args *ltargs;

	op[0].argop = OP_LOCKT;
	ltargs = &op[0].nfs_argop4_u.oplockt;
	memset(ltargs, 0, sizeof(*ltargs));
	ltargs->locktype = locktype;
	ltargs->offset   = offset;
	ltargs->length   = length;
	ltargs->owner.clientid = nfs->clientid;
	ltargs->owner.owner.owner_len = strlen(nfs->client_name);
	ltargs->owner.owner.owner_val = nfs->client_name;

	return 1;
}

static int
nfs4_op_locku(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh,
              nfs_lock_type4 locktype, uint64_t offset, length4 length)
{
	LOCKU4args *luargs;

	op[0].argop = OP_LOCKU;
	luargs = &op[0].nfs_argop4_u.oplocku;
	memset(luargs, 0, sizeof(*luargs));
	luargs->locktype = locktype;
	luargs->offset   = offset;
	luargs->length   = length;
	luargs->seqid = fh->lock_seqid;
	luargs->lock_stateid.seqid = fh->lock_stateid.seqid;
	memcpy(luargs->lock_stateid.other, fh->lock_stateid.other, 12);
	fh->lock_seqid++;

	return 1;
}

static int
nfs4_op_lookup(__unused struct nfs_context *nfs, nfs_argop4 *op, char *lpath)
{
	LOOKUP4args *largs;

	op[0].argop = OP_LOOKUP;
	largs = &op[0].nfs_argop4_u.oplookup;
	memset(largs, 0, sizeof(*largs));
	largs->objname.utf8string_len = strlen(lpath);
	largs->objname.utf8string_val = lpath;

	return 1;
}

static int
nfs4_op_nverify_chmod(__unused struct nfs_context *nfs,
    nfs_argop4 *op, void *nvbuf)
{
	NVERIFY4args *verifyargs;
	static uint32_t mask[2] = {0, 1 << (FATTR4_MODE - 32)};

	op[0].argop = OP_NVERIFY;
	verifyargs = &op[0].nfs_argop4_u.opnverify;
	memset(verifyargs, 0, sizeof(*verifyargs));
	verifyargs->obj_attributes.attrmask.bitmap4_len = 2;
	verifyargs->obj_attributes.attrmask.bitmap4_val = mask;
	verifyargs->obj_attributes.attr_vals.attrlist4_len = 4;
	verifyargs->obj_attributes.attr_vals.attrlist4_val = nvbuf;

	return 1;
}

static int
nfs4_op_open(__unused struct nfs_context *nfs, nfs_argop4 *op, char *opath)
{
	OPEN4args *oargs;

	op[0].argop = OP_OPEN;
	oargs = &op[0].nfs_argop4_u.opopen;
	memset(oargs, 0, sizeof(*oargs));
	oargs->seqid = nfs->seqid;
	oargs->share_access |= OPEN4_SHARE_ACCESS_READ;
	oargs->share_deny = OPEN4_SHARE_DENY_NONE;
	oargs->owner.clientid = nfs->clientid;
	oargs->owner.owner.owner_len = strlen(nfs->client_name);
	oargs->owner.owner.owner_val = nfs->client_name;
	oargs->openhow.opentype = OPEN4_NOCREATE;
	oargs->claim.claim = CLAIM_NULL;
	oargs->claim.open_claim4_u.file.utf8string_len = strlen(opath);
	oargs->claim.open_claim4_u.file.utf8string_val = opath;

	return 1;
}

static int
nfs4_op_open_confirm(struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh)
{
	OPEN_CONFIRM4args *ocargs;

	op[0].argop = OP_OPEN_CONFIRM;
	ocargs = &op[0].nfs_argop4_u.opopen_confirm;
	memset(ocargs, 0, sizeof(*ocargs));
	ocargs->open_stateid.seqid = fh->stateid.seqid;
	memcpy(&ocargs->open_stateid.other, fh->stateid.other, 12);
	ocargs->seqid = nfs->seqid;

	return 1;
}

static int
nfs4_op_open_downgrade(struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh, uint32_t share_access, uint32_t share_deny)
{
	OPEN_DOWNGRADE4args *odargs;

	op[0].argop = OP_OPEN_DOWNGRADE;
	odargs = &op[0].nfs_argop4_u.opopen_downgrade;
	memset(odargs, 0, sizeof(*odargs));
	odargs->open_stateid.seqid = fh->stateid.seqid;
	memcpy(&odargs->open_stateid.other, fh->stateid.other, 12);
	odargs->seqid = nfs->seqid;
	odargs->share_access = share_access;
	odargs->share_deny = share_deny;

	return 1;
}

static int
nfs4_op_putfh(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh)
{
	PUTFH4args *pfargs;

	op[0].argop = OP_PUTFH;
	pfargs = &op[0].nfs_argop4_u.opputfh;
	memset(pfargs, 0, sizeof(*pfargs));
	pfargs->object.nfs_fh4_len = fh->fh.len;
	pfargs->object.nfs_fh4_val = fh->fh.val;

	return 1;
}

static int
nfs4_op_read(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh,
    uint64_t offset, size_t count)
{
	READ4args *rargs;

	op[0].argop = OP_READ;
	rargs = &op[0].nfs_argop4_u.opread;
	rargs->stateid.seqid = fh->stateid.seqid;
	memcpy(&rargs->stateid.other, fh->stateid.other, 12);
	rargs->offset = offset;
	rargs->count = count;

	return 1;
}

static int
nfs4_op_readdir(__unused struct nfs_context *nfs, nfs_argop4 *op, uint64_t cookie)
{
	READDIR4args *rdargs;

	op[0].argop = OP_READDIR;
	rdargs = &op[0].nfs_argop4_u.opreaddir;
	memset(rdargs, 0, sizeof(*rdargs));

	rdargs->cookie = cookie;
	rdargs->dircount = 8192;
	rdargs->maxcount = 8192;
	rdargs->attr_request.bitmap4_len = 2;
	rdargs->attr_request.bitmap4_val = standard_attributes;

	return 1;
}

static int
nfs4_op_remove(__unused struct nfs_context *nfs, nfs_argop4 *op, char *name)
{
	REMOVE4args *rmargs;

	op[0].argop = OP_REMOVE;
	rmargs = &op[0].nfs_argop4_u.opremove;
	memset(rmargs, 0, sizeof(*rmargs));
	rmargs->target.utf8string_len = strlen(name);
	rmargs->target.utf8string_val = name;

	return 1;
}

static int
nfs4_op_rename(__unused struct nfs_context *nfs, nfs_argop4 *op, char *oldname,
    char *newname)
{
	RENAME4args *rargs;

	op[0].argop = OP_RENAME;
	rargs = &op[0].nfs_argop4_u.oprename;
	memset(rargs, 0, sizeof(*rargs));
	rargs->oldname.utf8string_len = strlen(oldname);
	rargs->oldname.utf8string_val = oldname;
	rargs->newname.utf8string_len = strlen(newname);
	rargs->newname.utf8string_val = newname;

	return 1;
}
static int
nfs4_op_release_lock_owner(struct nfs_context *nfs, nfs_argop4 *op, uint64_t clientid)
{
	RELEASE_LOCKOWNER4args *rloargs;

	op[0].argop = OP_RELEASE_LOCKOWNER;
	rloargs = &op[0].nfs_argop4_u.oprelease_lockowner;
	rloargs->lock_owner.clientid = clientid;
	rloargs->lock_owner.owner.owner_len = strlen(nfs->client_name);
	rloargs->lock_owner.owner.owner_val = nfs->client_name;

	return 1;
}
static int
nfs4_op_savefh(__unused struct nfs_context *nfs, nfs_argop4 *op)
{
	op[0].argop = OP_SAVEFH;

	return 1;
}

static int
nfs4_op_setattr_chmod(__unused struct nfs_context *nfs, nfs_argop4 *op,
    struct nfsfh *fh, void *sabuf)
{
	SETATTR4args *saargs;
	uint32_t mask[2] = {0, 1 << (FATTR4_MODE - 32)};

	op[0].argop = OP_SETATTR;
	saargs = &op[0].nfs_argop4_u.opsetattr;
	memset(saargs, 0, sizeof(*saargs));
	if (fh) {
		saargs->stateid.seqid = fh->stateid.seqid;
		memcpy(saargs->stateid.other, fh->stateid.other, 12);
	}	
	saargs->obj_attributes.attrmask.bitmap4_len = 2;
	saargs->obj_attributes.attrmask.bitmap4_val = mask;
	saargs->obj_attributes.attr_vals.attrlist4_len = 4;
	saargs->obj_attributes.attr_vals.attrlist4_val = sabuf;

	return 1;
}

static int
nfs4_op_setclientid(__unused struct nfs_context *nfs, nfs_argop4 *op, verifier4 verifier,
    char *client_name)
{
	SETCLIENTID4args *scidargs;
	char r_netid[] = "tcp";
	char r_addr[] = "0.0.0.0.0.0";

	op[0].argop = OP_SETCLIENTID;
	scidargs = &op[0].nfs_argop4_u.opsetclientid;
	memcpy(scidargs->client.verifier, verifier, sizeof(verifier4));
	scidargs->client.id.id_len = strlen(client_name);
	scidargs->client.id.id_val = client_name;
	scidargs->callback.cb_program = 0; /* NFS4_CALLBACK */
	scidargs->callback.cb_location.r_netid = r_netid;
	scidargs->callback.cb_location.r_addr = r_addr;
	scidargs->callback_ident = 0x00000001;

	return 1;
}

static int
nfs4_op_setclientid_confirm(__unused struct nfs_context *nfs, struct nfs_argop4 *op,
    uint64_t clientid, verifier4 verifier)
{
	SETCLIENTID_CONFIRM4args *scidcargs;

	op[0].argop = OP_SETCLIENTID_CONFIRM;
	scidcargs = &op[0].nfs_argop4_u.opsetclientid_confirm;
	scidcargs->clientid = clientid;
	memcpy(scidcargs->setclientid_confirm, verifier, NFS4_VERIFIER_SIZE);

	return 1;
}

static int
nfs4_op_verify_chmod(__unused struct nfs_context *nfs,
    nfs_argop4 *op, void *nvbuf)
{
	VERIFY4args *verifyargs;
	uint32_t mask[2] = {0, 1 << (FATTR4_MODE - 32)};

	op[0].argop = OP_VERIFY;
	verifyargs = &op[0].nfs_argop4_u.opverify;
	memset(verifyargs, 0, sizeof(*verifyargs));
	verifyargs->obj_attributes.attrmask.bitmap4_len = 2;
	verifyargs->obj_attributes.attrmask.bitmap4_val = mask;
	verifyargs->obj_attributes.attr_vals.attrlist4_len = 4;
	verifyargs->obj_attributes.attr_vals.attrlist4_val = nvbuf;

	return 1;
}

static int
nfs4_op_write(__unused struct nfs_context *nfs, nfs_argop4 *op, struct nfsfh *fh,
              uint64_t offset, size_t count, char *buf)
{
	WRITE4args *wargs;

	op[0].argop = OP_WRITE;
	wargs = &op[0].nfs_argop4_u.opwrite;
	wargs->stateid.seqid = fh->stateid.seqid;
	memcpy(wargs->stateid.other, fh->stateid.other, 12);
	wargs->offset = offset;
	if (fh->is_sync) {
	        wargs->stable = DATA_SYNC4;
	} else {
	        wargs->stable = UNSTABLE4;
	        fh->is_dirty = 1;
	}
	wargs->data.data_len = count;
	wargs->data.data_val = buf;

	return 1;
}

ATF_TC_WITH_CLEANUP(nfs4_compound_rpc);
ATF_TC_HEAD(nfs4_compound_rpc, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of"
					"NFSv4 Compound RPC");
}

ATF_TC_BODY(nfs4_compound_rpc, tc)
{
	struct au_rpc_data au_test_data;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_ACCESS, &au_test_data);
	const char *regex = "nfsrvd_compound.*return,success";

	NFS4_COMMON_PERFORM(0, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_compound_rpc, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_access_success);
ATF_TC_HEAD(nfs4_access_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 Access sub-op");
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
					"NFSv4 Access sub-op");
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
					"NFSv4 close sub-op");
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

ATF_TC_WITH_CLEANUP(nfs4_close_failure);
ATF_TC_HEAD(nfs4_close_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 close sub-op");
}

ATF_TC_BODY(nfs4_close_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_CLOSE, &au_test_data);
	const char *regex = "nfsrvd_close.*return,failure";

	/* File removed before making sub-op call, stale file handle. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	ATF_REQUIRE_EQ(0, remove(path));
	i = nfs4_op_close(nfs, &op[0], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_close_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_commit_success);
ATF_TC_HEAD(nfs4_commit_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 commit sub-op");
}

ATF_TC_BODY(nfs4_commit_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_COMMIT, &au_test_data);
	const char *regex = "nfsrvd_commit.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_commit(nfs, &op[i]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_commit_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_commit_failure);
ATF_TC_HEAD(nfs4_commit_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 commit sub-op");
}

ATF_TC_BODY(nfs4_commit_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_COMMIT, &au_test_data);
	const char *regex = "nfsrvd_commit.*return,failure";

	/* NFSv4 COMMIT sub-operation will fail due to invalid use. (no PUTFH subop) */
	i = nfs4_op_commit(nfs, &op[0]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_commit_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_create_success);
ATF_TC_HEAD(nfs4_create_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 create sub-op");
}

ATF_TC_BODY(nfs4_create_success, tc)
{
	struct au_rpc_data au_test_data;
	nfs_argop4 op[2];
	int i;
	struct nfsfh nfsfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_CREATE, &au_test_data);
	const char *regex = "nfsrvd_mknod.*return,success";

	nfsfh.fh.len = nfs->rootfh.len;
	nfsfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &nfsfh);
	i += nfs4_op_create_char(nfs, &op[i]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_create_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_create_failure);
ATF_TC_HEAD(nfs4_create_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 create sub-op");
}

ATF_TC_BODY(nfs4_create_failure, tc)
{
	struct au_rpc_data au_test_data;
	nfs_argop4 op[2];
	int i;
	struct nfsfh nfsfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_CREATE, &au_test_data);
	const char *regex = "nfsrvd_mknod.*return,failure";

	/* Results in error: File exists. */
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);
	nfsfh.fh.len = nfs->rootfh.len;
	nfsfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &nfsfh);
	i += nfs4_op_create_char(nfs, &op[i]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_create_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_delegpurge_success);
ATF_TC_HEAD(nfs4_delegpurge_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 delegpurge sub-op");
}

ATF_TC_BODY(nfs4_delegpurge_success, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_DELEGPURGE, &au_test_data);
	const char *regex = "nfsrvd_delegpurge.*return,success";

	i = nfs4_op_delepurge(nfs, &op[0]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_delegpurge_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_delegpurge_failure);
ATF_TC_HEAD(nfs4_delegpurge_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 delegpurge sub-op");
}

ATF_TC_BODY(nfs4_delegpurge_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_DELEGPURGE, &au_test_data);
	const char *regex = "nfsrvd_delegpurge.*return,failure";

	/* Invalid argument set for NFSv4 Client Id, resulting in failure. */ 
	nfs->clientid = 0;
	i = nfs4_op_delepurge(nfs, &op[0]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_delegpurge_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_delegreturn_success);
ATF_TC_HEAD(nfs4_delegreturn_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 delegreturn sub-op");
}

ATF_TC_BODY(nfs4_delegreturn_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_DELEGRETURN, &au_test_data);
	const char *regex = "nfsrvd_delegreturn.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_delegreturn(nfs, &op[i], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_delegreturn_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_delegreturn_failure);
ATF_TC_HEAD(nfs4_delegreturn_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 delegreturn sub-op");
}

ATF_TC_BODY(nfs4_delegreturn_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_DELEGRETURN, &au_test_data);
	const char *regex = "nfsrvd_delegreturn.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_delegreturn(nfs, &op[0], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_delegreturn_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_getattr_success);
ATF_TC_HEAD(nfs4_getattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 getattr sub-op");
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
					"NFSv4 getattr sub-op");
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

ATF_TC_WITH_CLEANUP(nfs4_getfh_success);
ATF_TC_HEAD(nfs4_getfh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 getfh sub-op");
}

ATF_TC_BODY(nfs4_getfh_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_GETFH, &au_test_data);
	const char *regex = "nfsrvd_getfh.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_getfh(nfs, &op[i]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_getfh_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_getfh_failure);
ATF_TC_HEAD(nfs4_getfh_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 getfh sub-op");
}

ATF_TC_BODY(nfs4_getfh_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_GETFH, &au_test_data);
	const char *regex = "nfsrvd_getfh.*return,failure";

	/* NFSv4 GETFH sub-operation will fail due to invalid use. (no PUTFH subop) */
	i = nfs4_op_getfh(nfs, &op[0]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_getfh_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_link_success);
ATF_TC_HEAD(nfs4_link_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 link sub-op");
}

ATF_TC_BODY(nfs4_link_success, tc)
{
	ATF_REQUIRE(open("ATestFile", O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[4];
	struct nfsfh dirfh;
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LINK, &au_test_data);
	const char *regex = "nfsrvd_link.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, "ATestFile", O_RDONLY, &nfsfh));

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_savefh(nfs, &op[i]);
	i += nfs4_op_putfh(nfs, &op[i], &dirfh);
	i += nfs4_op_link(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_link_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_link_failure);
ATF_TC_HEAD(nfs4_link_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 link sub-op");
}

ATF_TC_BODY(nfs4_link_failure, tc)
{
	ATF_REQUIRE(open("ATestFile", O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[4];
	struct nfsfh dirfh;
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LINK, &au_test_data);
	const char *regex = "nfsrvd_link.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, "ATestFile", O_RDONLY, &nfsfh));
	/* To result in error: File exists. */
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_savefh(nfs, &op[i]);
	i += nfs4_op_putfh(nfs, &op[i], &dirfh);
	i += nfs4_op_link(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_link_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lock_success);
ATF_TC_HEAD(nfs4_lock_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 lock sub-op");
}

ATF_TC_BODY(nfs4_lock_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOCK, &au_test_data);
	const char *regex = "nfsrvd_lock.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_lock(nfs, &op[i], nfsfh, OP_LOCK, WRITEW_LT, 0, 0, 1);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_lock_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lock_failure);
ATF_TC_HEAD(nfs4_lock_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 lock sub-op");
}

ATF_TC_BODY(nfs4_lock_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOCK, &au_test_data);
	const char *regex = "nfsrvd_lock.*return,failure";

	/* Invalid argument: length == 0 in lock args result in error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_lock(nfs, &op[i], nfsfh, OP_LOCK, WRITEW_LT, 0, 0, 0);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_lock_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lockt_success);
ATF_TC_HEAD(nfs4_lockt_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 lockt sub-op");
}

ATF_TC_BODY(nfs4_lockt_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOCKT, &au_test_data);
	const char *regex = "nfsrvd_lockt.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_lockt(nfs, &op[i], nfsfh, WRITEW_LT, 0, 1);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_lockt_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lockt_failure);
ATF_TC_HEAD(nfs4_lockt_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 lockt sub-op");
}

ATF_TC_BODY(nfs4_lockt_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[3];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOCKT, &au_test_data);
	const char *regex = "nfsrvd_lockt.*return,failure";

	/* Invalid argument: length == 0 in lockt args result in error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_lockt(nfs, &op[i], nfsfh, WRITEW_LT, 0, 0);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_lockt_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_locku_success);
ATF_TC_HEAD(nfs4_locku_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 locku sub-op");
}

ATF_TC_BODY(nfs4_locku_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOCKU, &au_test_data);
	const char *regex = "nfsrvd_locku.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	ATF_REQUIRE_EQ(0, nfs_lockf(nfs, nfsfh, NFS4_F_LOCK, 1));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_locku(nfs, &op[i], nfsfh, READW_LT, 0, 1);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_locku_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_locku_failure);
ATF_TC_HEAD(nfs4_locku_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 locku sub-op");
}

ATF_TC_BODY(nfs4_locku_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOCKU, &au_test_data);
	const char *regex = "nfsrvd_locku.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_locku(nfs, &op[i], nfsfh, READW_LT, 0, 1);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_locku_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lookup_success);
ATF_TC_HEAD(nfs4_lookup_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 lookup sub-op");
}

ATF_TC_BODY(nfs4_lookup_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOOKUP, &au_test_data);
	const char *regex = "nfsrvd_lookup.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_lookup(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_lookup_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lookup_failure);
ATF_TC_HEAD(nfs4_lookup_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 lookup sub-op");
}

ATF_TC_BODY(nfs4_lookup_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOOKUP, &au_test_data);
	const char *regex = "nfsrvd_lookup.*return,failure";

	/* No such file or directory with name fileforaudit. */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_lookup(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_lookup_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lookupp_success);
ATF_TC_HEAD(nfs4_lookupp_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 lookupp sub-op");
}

ATF_TC_BODY(nfs4_lookupp_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[3];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOOKUPP, &au_test_data);
	const char *regex = "nfsrvd_lookup.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	op[i++].argop = OP_LOOKUPP;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_lookupp_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_lookupp_failure);
ATF_TC_HEAD(nfs4_lookupp_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 lookupp sub-op");
}

ATF_TC_BODY(nfs4_lookupp_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_LOOKUPP, &au_test_data);
	const char *regex = "nfsrvd_lookup.*return,failure";

	/* It fails since no file handle given (PUTFH OP). */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	op[i++].argop = OP_LOOKUPP;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_lookupp_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_nverify_success);
ATF_TC_HEAD(nfs4_nverify_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 nverify sub-op");
}

ATF_TC_BODY(nfs4_nverify_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	uint32_t m = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_NVERIFY, &au_test_data);
	const char *regex = "nfsrvd_verify.*return,success";

	m = htonl(m);
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_nverify_chmod(nfs, &op[i], &m);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_nverify_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_nverify_failure);
ATF_TC_HEAD(nfs4_nverify_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 nverify sub-op");
}

ATF_TC_BODY(nfs4_nverify_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	uint32_t m = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_NVERIFY, &au_test_data);
	const char *regex = "nfsrvd_verify.*return,failure";

	/* NFSv4 NVERIFY sub-operation will fail due to invalid use. (no PUTFH subop) */
	m = htonl(m);
	i = nfs4_op_nverify_chmod(nfs, &op[0], &m);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_nverify_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_open_success);
ATF_TC_HEAD(nfs4_open_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 open sub-op");
}

ATF_TC_BODY(nfs4_open_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPEN, &au_test_data);
	const char *regex = "nfsrvd_open.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_open(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_open_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_open_failure);
ATF_TC_HEAD(nfs4_open_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 open sub-op");
}

ATF_TC_BODY(nfs4_open_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPEN, &au_test_data);
	const char *regex = "nfsrvd_open.*return,failure";

	/* Open type is OPEN4_NOCREATE and no file exists with name path. */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_open(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_open_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_openattr_failure);
ATF_TC_HEAD(nfs4_openattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 openattr sub-op");
}

ATF_TC_BODY(nfs4_openattr_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPENATTR, &au_test_data);
	const char *regex = "nfsrvd_openattr.*text,NFSv4 service not supported";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	OPENATTR4args *oaargs;
	oaargs = &op[i].nfs_argop4_u.opopenattr;
	memset(oaargs, 0, sizeof(*oaargs));
	op[i++].argop = OP_OPENATTR;
	oaargs->createdir = true;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_openattr_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_openconfirm_success);
ATF_TC_HEAD(nfs4_openconfirm_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 openconfirm sub-op");
}

ATF_TC_BODY(nfs4_openconfirm_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPENCONFIRM, &au_test_data);
	const char *regex = "nfsrvd_openconfirm.*return,success";
	FILE *pipefd = setup(fds, auclass);

	/* openconfirm subop is made just after open subop in nfs_open. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	check_audit(fds, (regex), pipefd);
}

ATF_TC_CLEANUP(nfs4_openconfirm_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_openconfirm_failure);
ATF_TC_HEAD(nfs4_openconfirm_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 openconfirm sub-op");
}

ATF_TC_BODY(nfs4_openconfirm_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPENCONFIRM, &au_test_data);
	const char *regex = "nfsrvd_openconfirm.*return,failure";

	/* Invalid use of open_confirm operation. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_open_confirm(nfs, &op[0], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_openconfirm_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_opendowngrade_success);
ATF_TC_HEAD(nfs4_opendowngrade_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 opendowngrade sub-op");
}

ATF_TC_BODY(nfs4_opendowngrade_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPENDOWNGRADE, &au_test_data);
	const char *regex = "nfsrvd_opendowngrade.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_open_downgrade(nfs, &op[i], nfsfh,
	    OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_opendowngrade_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_opendowngrade_failure);
ATF_TC_HEAD(nfs4_opendowngrade_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 opendowngrade sub-op");
}

ATF_TC_BODY(nfs4_opendowngrade_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_OPENDOWNGRADE, &au_test_data);
	const char *regex = "nfsrvd_opendowngrade.*return,failure";

	/* Due to lock being held, the operation fails with NFS4ERR_LOCKS_HELD error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	ATF_REQUIRE_EQ(0, nfs_lockf(nfs, nfsfh, NFS4_F_LOCK, 1));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_open_downgrade(nfs, &op[i], nfsfh,
	    OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_opendowngrade_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_putfh_success);
ATF_TC_HEAD(nfs4_putfh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 putfh sub-op");
}

ATF_TC_BODY(nfs4_putfh_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_PUTFH, &au_test_data);
	const char *regex = "NFSV4OP_PUTFH.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_putfh_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_putfh_failure);
ATF_TC_HEAD(nfs4_putfh_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 putfh sub-op");
}

ATF_TC_BODY(nfs4_putfh_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_PUTFH, &au_test_data);
	const char *regex = "NFSV4OP_PUTFH.*return,failure";

	/* PUTH OP fails due to Stale NFS file handle error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	ATF_REQUIRE_EQ(0, remove(path));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_putfh_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_putpubfh_success);
ATF_TC_HEAD(nfs4_putpubfh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 putpubfh sub-op");
}

ATF_TC_BODY(nfs4_putpubfh_success, tc)
{
	/*
	 * XXX: https://tools.ietf.org/html/rfc5661#section-18.20
	 * but How to use this operation correctly??
	 */
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_PUTPUBFH, &au_test_data);
	const char *regex = "NFSV4OP_PUTPUBFH.*return,success";

	op[i++].argop = OP_PUTPUBFH;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_putpubfh_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_putpubfh_failure);
ATF_TC_HEAD(nfs4_putpubfh_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 putpubfh sub-op");
}

ATF_TC_BODY(nfs4_putpubfh_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_PUTPUBFH, &au_test_data);
	const char *regex = "NFSV4OP_PUTPUBFH.*return,failure";

	op[i++].argop = OP_PUTPUBFH;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_putpubfh_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_putrootfh_success);
ATF_TC_HEAD(nfs4_putrootfh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 putrootfh sub-op");
}

ATF_TC_BODY(nfs4_putrootfh_success, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_PUTROOTFH, &au_test_data);
	const char *regex = "NFSV4OP_PUTROOTFH.*return,success";

	op[i++].argop = OP_PUTROOTFH;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_putrootfh_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_read_success);
ATF_TC_HEAD(nfs4_read_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 read sub-op");
}

ATF_TC_BODY(nfs4_read_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_READ, &au_test_data);
	const char *regex = "nfsrvd_read.*return,success";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_read(nfs, &op[i], nfsfh, 0, 0);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_read_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_read_failure);
ATF_TC_HEAD(nfs4_read_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 read sub-op");
}

ATF_TC_BODY(nfs4_read_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_READ, &au_test_data);
	const char *regex = "nfsrvd_read.*return,failure";

	/* Invalid FH for READ op, since it is directory. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	op[i++].argop = OP_PUTROOTFH;
	i += nfs4_op_read(nfs, &op[i], nfsfh, 0, 0);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_read_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_readdir_success);
ATF_TC_HEAD(nfs4_readdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
	       			"NFSv4 readdir sub-op");
}

ATF_TC_BODY(nfs4_readdir_success, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_READDIR, &au_test_data);
	const char *regex = "nfsrvd_readdirplus.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_readdir(nfs, &op[i], 0);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_readdir_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_readdir_failure);
ATF_TC_HEAD(nfs4_readdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 readdir sub-op");
}

ATF_TC_BODY(nfs4_readdir_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_READDIR, &au_test_data);
	const char *regex = "nfsrvd_readdirplus.*return,failure";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_CREAT, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_readdir(nfs, &op[i], 0);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_readdir_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_readlink_success);
ATF_TC_HEAD(nfs4_readlink_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 readlink sub-op");
}

ATF_TC_BODY(nfs4_readlink_success, tc)
{
	ATF_REQUIRE_EQ(0, symlink(path, "symlink"));

	struct au_rpc_data au_test_data;
	char buf[PATH_MAX];
	FILE* pipefd;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_READLINK, &au_test_data);
	const char *regex = "nfsrvd_readlink.*return,success";

	/* XXX: used high-level API here to avoid the code complications. */ 
	pipefd = setup(fds, auclass);
	ATF_REQUIRE_EQ(0, nfs_readlink(nfs, "symlink", buf, sizeof(buf)));
	ATF_REQUIRE_MATCH(buf, path);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs4_readlink_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_readlink_failure);
ATF_TC_HEAD(nfs4_readlink_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 readlink sub-op");
}

ATF_TC_BODY(nfs4_readlink_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	char buf[PATH_MAX];
	FILE* pipefd;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_READLINK, &au_test_data);
	const char *regex = "nfsrvd_readlink.*return,failure";

	/* XXX: used high-level API here to avoid the code complications. */
	/* path is a regular file and not symlink. */
	pipefd = setup(fds, auclass);
	ATF_REQUIRE(nfs_readlink(nfs, path, buf, sizeof(buf)) != 0);
	check_audit(fds, regex, pipefd);
}

ATF_TC_CLEANUP(nfs4_readlink_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_remove_success);
ATF_TC_HEAD(nfs4_remove_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 remove sub-op");
}

ATF_TC_BODY(nfs4_remove_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_REMOVE, &au_test_data);
	const char *regex = "nfsrvd_remove.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);	
	i += nfs4_op_remove(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_remove_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_remove_failure);
ATF_TC_HEAD(nfs4_remove_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 remove sub-op");
}

ATF_TC_BODY(nfs4_remove_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_REMOVE, &au_test_data);
	const char *regex = "nfsrvd_remove.*return,failure";

	/* No file or directory exists with name path. */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_remove(nfs, &op[i], path);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_remove_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_rename_success);
ATF_TC_HEAD(nfs4_rename_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 rename sub-op");
}

ATF_TC_BODY(nfs4_rename_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[4];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RENAME, &au_test_data);
	const char *regex = "nfsrvd_rename.*return,success";
	char newpath[] = "new_fileforaudit";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_savefh(nfs, &op[i]);
	i += nfs4_op_putfh(nfs, &op[i], &dirfh);	
	i += nfs4_op_rename(nfs, &op[i], path, newpath);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_rename_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_rename_failure);
ATF_TC_HEAD(nfs4_rename_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 rename sub-op");
}

ATF_TC_BODY(nfs4_rename_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[4];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RENAME, &au_test_data);
	const char *regex = "nfsrvd_rename.*return,failure";
	char newpath[] = "new_fileforaudit";

	/* No such file or directory with name path. */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_savefh(nfs, &op[i]);
	i += nfs4_op_putfh(nfs, &op[i], &dirfh);	
	i += nfs4_op_rename(nfs, &op[i], path, newpath);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_rename_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_renew_success);
ATF_TC_HEAD(nfs4_renew_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 renew sub-op");
}

ATF_TC_BODY(nfs4_renew_success, tc)
{
	struct au_rpc_data au_test_data;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RENEW, &au_test_data);
	const char *regex = "nfsrvd_renew.*return,success";

	op[0].argop = OP_RENEW;
	op[0].nfs_argop4_u.oprenew.clientid = nfs->clientid;
	NFS4_COMMON_PERFORM(1, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_renew_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_renew_failure);
ATF_TC_HEAD(nfs4_renew_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 renew sub-op");
}

ATF_TC_BODY(nfs4_renew_failure, tc)
{
	struct au_rpc_data au_test_data;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RENEW, &au_test_data);
	const char *regex = "nfsrvd_renew.*return,failure";

	/* put a random client id (invalid). */
	op[0].argop = OP_RENEW;
	op[0].nfs_argop4_u.oprenew.clientid = 12345;
	NFS4_COMMON_PERFORM(1, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_renew_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_restorefh_success);
ATF_TC_HEAD(nfs4_restorefh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 restorefh sub-op");
}

ATF_TC_BODY(nfs4_restorefh_success, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[3];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RESTOREFH, &au_test_data);
	const char *regex = "NFSV4OP_RESTOREFH.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_savefh(nfs, &op[i]);
	op[i++].argop = OP_RESTOREFH;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_restorefh_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_restorefh_failure);
ATF_TC_HEAD(nfs4_restorefh_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 restorefh sub-op");
}

ATF_TC_BODY(nfs4_restorefh_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RESTOREFH, &au_test_data);
	const char *regex = "NFSV4OP_RESTOREFH.*return,failure";

	/* No saved filehandle, OP would result in NFS4ERR_NOFILEHANDLE. */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	op[i++].argop = OP_RESTOREFH;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_restorefh_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_savefh_success);
ATF_TC_HEAD(nfs4_savefh_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 savefh sub-op");
}

ATF_TC_BODY(nfs4_savefh_success, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SAVEFH, &au_test_data);
	const char *regex = "NFSV4OP_SAVEFH.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	i += nfs4_op_savefh(nfs, &op[i]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_savefh_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_savefh_failure);
ATF_TC_HEAD(nfs4_savefh_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 savefh sub-op");
}

ATF_TC_BODY(nfs4_savefh_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SAVEFH, &au_test_data);
	const char *regex = "NFSV4OP_SAVEFH.*return,failure";

	/* No filehandle to save, OP would result in error. */
	i = nfs4_op_savefh(nfs, &op[0]);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_savefh_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_secinfo_success);
ATF_TC_HEAD(nfs4_secinfo_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 secinfo sub-op");
}

ATF_TC_BODY(nfs4_secinfo_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SECINFO, &au_test_data);
	const char *regex = "nfsrvd_secinfo.*return,success";

	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	op[i].argop = OP_SECINFO;
	op[i].nfs_argop4_u.opsecinfo.name.utf8string_len = strlen(path);
	op[i++].nfs_argop4_u.opsecinfo.name.utf8string_val = path;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_secinfo_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_secinfo_failure);
ATF_TC_HEAD(nfs4_secinfo_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 secinfo sub-op");
}

ATF_TC_BODY(nfs4_secinfo_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh dirfh;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SECINFO, &au_test_data);
	const char *regex = "nfsrvd_secinfo.*return,failure";

	/* No such file or directory with name path. */
	dirfh.fh.len = nfs->rootfh.len;
	dirfh.fh.val = nfs->rootfh.val;
	i = nfs4_op_putfh(nfs, &op[0], &dirfh);
	op[i].argop = OP_SECINFO;
	op[i].nfs_argop4_u.opsecinfo.name.utf8string_len = strlen(path);
	op[i++].nfs_argop4_u.opsecinfo.name.utf8string_val = path;
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_secinfo_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_setattr_success);
ATF_TC_HEAD(nfs4_setattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 setattr sub-op");
}

ATF_TC_BODY(nfs4_setattr_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	uint32_t m = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SETATTR, &au_test_data);
	const char *regex = "nfsrvd_setattr.*return,success";

	m = htonl(m);
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_setattr_chmod(nfs, &op[i], nfsfh, &m);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_setattr_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_setattr_failure);
ATF_TC_HEAD(nfs4_setattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 setattr sub-op");
}

ATF_TC_BODY(nfs4_setattr_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	uint32_t m = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SETATTR, &au_test_data);
	const char *regex = "nfsrvd_setattr.*return,failure";

	/* No PUTFH sub-operation. setattr will fail. */
	m = htonl(m);
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_setattr_chmod(nfs, &op[0], nfsfh, &m);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_setattr_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_setclientid_success);
ATF_TC_HEAD(nfs4_setclientid_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 setclientid sub-op");
}

ATF_TC_BODY(nfs4_setclientid_success, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SETCLIENTID, &au_test_data);
	const char *regex = "nfsrvd_setclientid.*return,success";

	i = nfs4_op_setclientid(nfs, &op[i], nfs->verifier, nfs->client_name);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_setclientid_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_setclientidcfrm_success);
ATF_TC_HEAD(nfs4_setclientidcfrm_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 setclientid confirm sub-op");
}

ATF_TC_BODY(nfs4_setclientidcfrm_success, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SETCLIENTIDCFRM, &au_test_data);
	const char *regex = "nfsrvd_setclientidcfrm.*return,success";

	i = nfs4_op_setclientid_confirm(nfs, &op[i], nfs->clientid, nfs->setclientid_confirm);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_setclientidcfrm_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_setclientidcfrm_failure);
ATF_TC_HEAD(nfs4_setclientidcfrm_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 setclientid confirm sub-op");
}

ATF_TC_BODY(nfs4_setclientidcfrm_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i = 0;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_SETCLIENTIDCFRM, &au_test_data);
	const char *regex = "nfsrvd_setclientidcfrm.*return,failure";

	/* pass wrogn clientid as argument so that operation results in failure. */
	i = nfs4_op_setclientid_confirm(nfs, &op[i], nfs->clientid + 0xff, nfs->setclientid_confirm);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_setclientidcfrm_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_verify_success);
ATF_TC_HEAD(nfs4_verify_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 verify sub-op");
}

ATF_TC_BODY(nfs4_verify_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	uint32_t m = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_VERIFY, &au_test_data);
	const char *regex = "nfsrvd_verify.*return,success";

	m = htonl(m);
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_verify_chmod(nfs, &op[i], &m);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_verify_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_verify_failure);
ATF_TC_HEAD(nfs4_verify_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 verify sub-op");
}

ATF_TC_BODY(nfs4_verify_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	uint32_t m = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_VERIFY, &au_test_data);
	const char *regex = "nfsrvd_verify.*return,failure";

	/* NFSv4 VERIFY sub-operation will fail due to invalid use. (no PUTFH subop) */
	m = htonl(m);
	i = nfs4_op_verify_chmod(nfs, &op[0], &m);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_verify_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_write_success);
ATF_TC_HEAD(nfs4_write_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 write sub-op");
}

ATF_TC_BODY(nfs4_write_success, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_WRITE, &au_test_data);
	const char *regex = "nfsrvd_write.*return,success";
	char wbuf[] = "buffer";

	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDWR, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_write(nfs, &op[i], nfsfh, 0, strlen(wbuf), wbuf);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_write_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_write_failure);
ATF_TC_HEAD(nfs4_write_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 write sub-op");
}

ATF_TC_BODY(nfs4_write_failure, tc)
{
	ATF_REQUIRE(open(path, O_CREAT, 0777) != -1);

	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[2];
	struct nfsfh *nfsfh = NULL;
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_WRITE, &au_test_data);
	const char *regex = "nfsrvd_write.*return,failure";
	char wbuf[] = "buffer";

	/* The file is opened as Read only. Write will return error. */
	ATF_REQUIRE_EQ(0, nfs_open(nfs, path, O_RDONLY, &nfsfh));
	i = nfs4_op_putfh(nfs, &op[0], nfsfh);
	i += nfs4_op_write(nfs, &op[i], nfsfh, 0, strlen(wbuf), wbuf);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_write_failure, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_releaselckown_success);
ATF_TC_HEAD(nfs4_releaselckown_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 releaselckown sub-op");
}

ATF_TC_BODY(nfs4_releaselckown_success, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RELEASELCKOWN, &au_test_data);
	const char *regex = "nfsrvd_releaselckown.*return,success";

	i = nfs4_op_release_lock_owner(nfs, &op[0], nfs->clientid);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, true);
}

ATF_TC_CLEANUP(nfs4_releaselckown_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs4_releaselckown_failure);
ATF_TC_HEAD(nfs4_releaselckown_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv4 releaselckown sub-op");
}

ATF_TC_BODY(nfs4_releaselckown_failure, tc)
{
	struct au_rpc_data au_test_data;
	int i;
	nfs_argop4 op[1];
	struct nfs_context *nfs = tc_body_init(AUE_NFSV4OP_RELEASELCKOWN, &au_test_data);
	const char *regex = "nfsrvd_releaselckown.*return,failure";

	/* It fails due to invalid clientid. */
	i = nfs4_op_release_lock_owner(nfs, &op[0], nfs->clientid + 0xffff);
	NFS4_COMMON_PERFORM(i, op, regex, nfs, au_test_data, false);
}

ATF_TC_CLEANUP(nfs4_releaselckown_failure, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs4_compound_rpc);
	ATF_TP_ADD_TC(tp, nfs4_access_success);
	ATF_TP_ADD_TC(tp, nfs4_access_failure);
	ATF_TP_ADD_TC(tp, nfs4_close_success);
	ATF_TP_ADD_TC(tp, nfs4_close_failure);
	ATF_TP_ADD_TC(tp, nfs4_commit_success);
	ATF_TP_ADD_TC(tp, nfs4_commit_failure);
	ATF_TP_ADD_TC(tp, nfs4_create_success);
	ATF_TP_ADD_TC(tp, nfs4_create_failure);
	ATF_TP_ADD_TC(tp, nfs4_delegpurge_success);
	ATF_TP_ADD_TC(tp, nfs4_delegpurge_failure);
	ATF_TP_ADD_TC(tp, nfs4_delegreturn_success);
	ATF_TP_ADD_TC(tp, nfs4_delegreturn_failure);
	ATF_TP_ADD_TC(tp, nfs4_getattr_success);
	ATF_TP_ADD_TC(tp, nfs4_getattr_failure);
	ATF_TP_ADD_TC(tp, nfs4_getfh_success);
	ATF_TP_ADD_TC(tp, nfs4_getfh_failure);
	ATF_TP_ADD_TC(tp, nfs4_link_success);
	ATF_TP_ADD_TC(tp, nfs4_link_failure);
	ATF_TP_ADD_TC(tp, nfs4_lock_success);
	ATF_TP_ADD_TC(tp, nfs4_lock_failure);
	ATF_TP_ADD_TC(tp, nfs4_lockt_success);
	ATF_TP_ADD_TC(tp, nfs4_lockt_failure);
	ATF_TP_ADD_TC(tp, nfs4_locku_success);
	ATF_TP_ADD_TC(tp, nfs4_locku_failure);
	ATF_TP_ADD_TC(tp, nfs4_lookup_success);
	ATF_TP_ADD_TC(tp, nfs4_lookup_failure);
	ATF_TP_ADD_TC(tp, nfs4_lookupp_success);
	ATF_TP_ADD_TC(tp, nfs4_lookupp_failure);
	ATF_TP_ADD_TC(tp, nfs4_nverify_success);
	ATF_TP_ADD_TC(tp, nfs4_nverify_failure);
    	ATF_TP_ADD_TC(tp, nfs4_open_success);
	ATF_TP_ADD_TC(tp, nfs4_open_failure);
	ATF_TP_ADD_TC(tp, nfs4_openattr_failure); /* NFSv4 service not supported by FreeBSD */
	ATF_TP_ADD_TC(tp, nfs4_openconfirm_success);
	ATF_TP_ADD_TC(tp, nfs4_openconfirm_failure);
	ATF_TP_ADD_TC(tp, nfs4_opendowngrade_success);
	ATF_TP_ADD_TC(tp, nfs4_opendowngrade_failure);
	ATF_TP_ADD_TC(tp, nfs4_putfh_success);
	ATF_TP_ADD_TC(tp, nfs4_putfh_failure);
	ATF_TP_ADD_TC(tp, nfs4_putpubfh_success); /* How to use? */
	ATF_TP_ADD_TC(tp, nfs4_putpubfh_failure); /* How to use? */
	ATF_TP_ADD_TC(tp, nfs4_putrootfh_success);
//	ATF_TP_ADD_TC(tp, nfs4_putrootfh_failure); //How and when it can fail?
	ATF_TP_ADD_TC(tp, nfs4_read_success);
	ATF_TP_ADD_TC(tp, nfs4_read_failure);
	ATF_TP_ADD_TC(tp, nfs4_readdir_success);
	ATF_TP_ADD_TC(tp, nfs4_readdir_failure);
	ATF_TP_ADD_TC(tp, nfs4_readlink_success);
	ATF_TP_ADD_TC(tp, nfs4_readlink_failure);
	ATF_TP_ADD_TC(tp, nfs4_remove_success);
	ATF_TP_ADD_TC(tp, nfs4_remove_failure);
	ATF_TP_ADD_TC(tp, nfs4_rename_success);
	ATF_TP_ADD_TC(tp, nfs4_rename_failure);
	ATF_TP_ADD_TC(tp, nfs4_renew_success);
	ATF_TP_ADD_TC(tp, nfs4_renew_failure);
	ATF_TP_ADD_TC(tp, nfs4_restorefh_success);
	ATF_TP_ADD_TC(tp, nfs4_restorefh_failure);
	ATF_TP_ADD_TC(tp, nfs4_savefh_success);
	ATF_TP_ADD_TC(tp, nfs4_savefh_failure);
	ATF_TP_ADD_TC(tp, nfs4_secinfo_success); /* Why it's not working :( */
	ATF_TP_ADD_TC(tp, nfs4_secinfo_failure);
	ATF_TP_ADD_TC(tp, nfs4_setattr_success);
	ATF_TP_ADD_TC(tp, nfs4_setattr_failure);
	ATF_TP_ADD_TC(tp, nfs4_setclientid_success);
//	ATF_TP_ADD_TC(tp, nfs4_setclientid_failure); // How and When it can fail?
	ATF_TP_ADD_TC(tp, nfs4_setclientidcfrm_success);
	ATF_TP_ADD_TC(tp, nfs4_setclientidcfrm_failure);
	ATF_TP_ADD_TC(tp, nfs4_verify_success);
	ATF_TP_ADD_TC(tp, nfs4_verify_failure);
	ATF_TP_ADD_TC(tp, nfs4_write_success);
	ATF_TP_ADD_TC(tp, nfs4_write_failure);
	ATF_TP_ADD_TC(tp, nfs4_releaselckown_success);
	ATF_TP_ADD_TC(tp, nfs4_releaselckown_failure);
	/* Additional Ops for NFSv4.1. */
//	ATF_TP_ADD_TC(tp, nfs4_backchannelctl_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_bindconntosess_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_bindconntosess_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_exchangeid_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_exchangeid_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_createsession_success); /* How to populate args for request */
//	ATF_TP_ADD_TC(tp, nfs4_createsession_failure); /* How to populate args for request */
//	ATF_TP_ADD_TC(tp, nfs4_destroysession_success); /* Depends on createsession for sessionid */
//	ATF_TP_ADD_TC(tp, nfs4_destroysession_failure); /* Depends on createsession for sessionid */
//	ATF_TP_ADD_TC(tp, nfs4_freestateid_success);
//	ATF_TP_ADD_TC(tp, nfs4_freestateid_failure);
//	ATF_TP_ADD_TC(tp, nfs4_getdirdeleg_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_getdevinfo_success);
//	ATF_TP_ADD_TC(tp, nfs4_getdevinfo_failure);
//	ATF_TP_ADD_TC(tp, nfs4_getdevlist_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_layoutcommit_success);
//	ATF_TP_ADD_TC(tp, nfs4_layoutcommit_failure);
//	ATF_TP_ADD_TC(tp, nfs4_layoutget_success);
//	ATF_TP_ADD_TC(tp, nfs4_layoutget_failure);
//	ATF_TP_ADD_TC(tp, nfs4_layoutreturn_success);
//	ATF_TP_ADD_TC(tp, nfs4_layoutreturn_failure);
//	ATF_TP_ADD_TC(tp, nfs4_secinfononame_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_sequence_success);
//	ATF_TP_ADD_TC(tp, nfs4_sequence_failure);
//	ATF_TP_ADD_TC(tp, nfs4_setssv_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_teststateid_success);
//	ATF_TP_ADD_TC(tp, nfs4_teststateid_failure);
//	ATF_TP_ADD_TC(tp, nfs4_wantdeleg_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_destroyclientid_success);
//	ATF_TP_ADD_TC(tp, nfs4_destroyclientid_failure);
//	ATF_TP_ADD_TC(tp, nfs4_reclaimcompl_success);
//	ATF_TP_ADD_TC(tp, nfs4_reclaimcompl_failure);
	/* Additional operations for NFSv4.2. */
//	ATF_TP_ADD_TC(tp, nfs4_allocate_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_allocate_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_copy_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_copy_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_copynotify_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_deallocate_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_ioadvise_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_ioadvise_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_layouterror_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_layouterror_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_layoutstats_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_layoutstats_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_offloadcancel_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_offloadstatus_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_readplus_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_seek_success); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_seek_failure); /* Not supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_writesame_failure); /* NFSv4 service not supported by FreeBSD */
//	ATF_TP_ADD_TC(tp, nfs4_clone_failure); /* NFSv4 service not supported */
//	ATF_TP_ADD_TC(tp, nfs4_getxattr_success); /* Not Supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_getxattr_failure); /* Not Supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_setxattr_success); /* Not Supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_setxattr_failure); /* Not Supported by libnfs */
	/* The optional Extended attribute operations (RFC-8276) */
//	ATF_TP_ADD_TC(tp, nfs4_listxattrs_success); /* Not Supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_listxattrs_failure); /* Not Supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_removexattr_success); /* Not Supported by libnfs */
//	ATF_TP_ADD_TC(tp, nfs4_removexattr_failure); /* Not Supported by libnfs */

	return (atf_no_error());
}
