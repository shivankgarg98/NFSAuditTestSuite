#ifndef _UTILS_H_
#define _UTILS_H_

#include <poll.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bsm/audit.h>

#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw.h>
#include <nfsc/libnfs-raw-mount.h>
#include <nfsc/libnfs-raw-nfs.h>
#include <nfsc/libnfs-raw-nfs4.h>
#include <nfsc/libnfs-raw-portmap.h>

struct au_rpc_data {
	int	au_rpc_status;
	int	au_rpc_result; /* RPC result status/error. refer: libnfs-raw-nfs.h */
	int	au_rpc_event;
	int	is_finished;
};

struct nfs_fh {
	int	len;
	char	*val;
};

struct stateid {
        uint32_t seqid;
        char other[12];
};

struct nfsfh {
        struct nfs_fh fh;
        int is_sync;
        int is_append;
        int is_dirty;
        uint64_t offset;

        /* NFSv4 */
        struct stateid stateid;
        /* locking */
        uint32_t lock_seqid;
        struct stateid lock_stateid;
};

struct nfs_context {
	struct	rpc_context *rpc;
	char	*server;
	char	*export;
	struct nfs_fh	rootfh;
	uint64_t	readmax;
	uint64_t	writemax;
	uint16_t	mask;
	char*	cwd;
	int	auto_reconnect;
	int	version;
	int	nfsport;
	int	mountport;
};

struct nfs_context *tc_body_init(int, struct au_rpc_data *);
void nfs_res_close_cb(struct nfs_context *, int, void *, void *);
void nfsv4_res_close_cb(struct nfs_context *, int, void *, void *);
int nfs_poll_fd(struct nfs_context *, struct au_rpc_data*);
void check_audit(struct pollfd [], const char *, FILE *);
FILE *setup(struct pollfd [], const char *);
void cleanup(void);

/*
 * NFSv3 RPC related events
 */
#define AUE_NFS3RPC_GETATTR	43266	
#define AUE_NFS3RPC_SETATTR	43267
#define AUE_NFS3RPC_LOOKUP	43268
#define AUE_NFS3RPC_ACCESS	43269
#define AUE_NFS3RPC_READLINK	43270
#define AUE_NFS3RPC_READ	43271
#define AUE_NFS3RPC_WRITE	43272
#define AUE_NFS3RPC_CREATE	43273
#define AUE_NFS3RPC_MKDIR	43274
#define AUE_NFS3RPC_SYMLINK	43275
#define AUE_NFS3RPC_MKNOD	43276
#define AUE_NFS3RPC_REMOVE	43277
#define	AUE_NFS3RPC_RMDIR	43278
#define AUE_NFS3RPC_RENAME	43279
#define AUE_NFS3RPC_LINK	43280
#define AUE_NFS3RPC_READDIR	43281
#define AUE_NFS3RPC_READDIRPLUS	43282
#define AUE_NFS3RPC_FSSTAT	43283
#define AUE_NFS3RPC_FSINFO	43284
#define AUE_NFS3RPC_PATHCONF	43285
#define AUE_NFS3RPC_COMMIT	43286

#define	AUE_NFSV4RPC_COMPOUND	43288

#define	AUE_NFSV4OP_ACCESS	43290
#define	AUE_NFSV4OP_CLOSE	43291
#define	AUE_NFSV4OP_COMMIT	43292
#define	AUE_NFSV4OP_CREATE	43293
#define	AUE_NFSV4OP_DELEGPURGE	43294
#define	AUE_NFSV4OP_DELEGRETURN	43295
#define	AUE_NFSV4OP_GETATTR	43296
#define	AUE_NFSV4OP_GETFH	43297
#define	AUE_NFSV4OP_LINK	43298
#define	AUE_NFSV4OP_LOCK	43299
#define	AUE_NFSV4OP_LOCKT	43300
#define	AUE_NFSV4OP_LOCKU	43301
#define	AUE_NFSV4OP_LOOKUP	43302
#define	AUE_NFSV4OP_LOOKUPP	43303
#define	AUE_NFSV4OP_NVERIFY	43304
#define	AUE_NFSV4OP_OPEN	43305
#define	AUE_NFSV4OP_OPENATTR	43306
#define	AUE_NFSV4OP_OPENCONFIRM	43307
#define	AUE_NFSV4OP_OPENDOWNGRADE	43308
#define	AUE_NFSV4OP_PUTFH	43309
#define	AUE_NFSV4OP_PUTPUBFH	43310
#define	AUE_NFSV4OP_PUTROOTFH	43311
#define	AUE_NFSV4OP_READ	43312
#define	AUE_NFSV4OP_READDIR	43313
#define	AUE_NFSV4OP_READLINK	43314
#define	AUE_NFSV4OP_REMOVE	43315
#define	AUE_NFSV4OP_RENAME	43316
#define	AUE_NFSV4OP_RENEW	43317
#define	AUE_NFSV4OP_RESTOREFH	43318
#define	AUE_NFSV4OP_SAVEFH	43319
#define	AUE_NFSV4OP_SECINFO	43320
#define	AUE_NFSV4OP_SETATTR	43321
#define	AUE_NFSV4OP_SETCLIENTID	43322
#define	AUE_NFSV4OP_SETCLIENTIDCFRM	43323
#define	AUE_NFSV4OP_VERIFY	43324
#define	AUE_NFSV4OP_WRITE	43325
#define	AUE_NFSV4OP_RELEASELCKOWN	43326
#define	AUE_NFSV4OP_BACKCHANNELCTL	43327
#define	AUE_NFSV4OP_BINDCONNTOSESS	43328
#define	AUE_NFSV4OP_EXCHANGEID	43329
#define	AUE_NFSV4OP_CREATESESSION	43330
#define	AUE_NFSV4OP_DESTROYSESSION	43331
#define	AUE_NFSV4OP_FREESTATEID	43332
#define	AUE_NFSV4OP_GETDIRDELEG	43333
#define	AUE_NFSV4OP_GETDEVINFO	43334
#define	AUE_NFSV4OP_GETDEVLIST	43335
#define	AUE_NFSV4OP_LAYOUTCOMMIT	43336
#define	AUE_NFSV4OP_LAYOUTGET	43337
#define	AUE_NFSV4OP_LAYOUTRETURN	43338
#define	AUE_NFSV4OP_SECINFONONAME	43339
#define	AUE_NFSV4OP_SEQUENCE	43340
#define	AUE_NFSV4OP_SETSSV	43341
#define	AUE_NFSV4OP_TESTSTATEID	43342
#define	AUE_NFSV4OP_WANTDELEG	43343
#define	AUE_NFSV4OP_DESTROYCLIENTID	43344
#define	AUE_NFSV4OP_RECLAIMCOMPL	43345
#define	AUE_NFSV4OP_ALLOCATE	43346
#define	AUE_NFSV4OP_COPY	43347
#define	AUE_NFSV4OP_COPYNOTIFY	43348
#define	AUE_NFSV4OP_DEALLOCATE	43349
#define	AUE_NFSV4OP_IOADVISE	43350
#define	AUE_NFSV4OP_LAYOUTERROR	43351
#define	AUE_NFSV4OP_LAYOUTSTATS	43352
#define	AUE_NFSV4OP_OFFLOADCANCEL	43353
#define	AUE_NFSV4OP_OFFLOADSTATUS	43354
#define	AUE_NFSV4OP_READPLUS	43355
#define	AUE_NFSV4OP_SEEK	43356
#define	AUE_NFSV4OP_WRITESAME	43357
#define	AUE_NFSV4OP_CLONE	43358
#define	AUE_NFSV4OP_GETXATTR	43359
#define	AUE_NFSV4OP_SETXATTR	43360
#define	AUE_NFSV4OP_LISTXATTRS	43361
#define	AUE_NFSV4OP_REMOVEXATTR	43362

#endif	/* _UTILS_H */
