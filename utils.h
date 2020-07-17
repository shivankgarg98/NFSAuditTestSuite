#ifndef _NFS_AUDIT_UTILS_H_
#define _NFS_AUDIT_UTILS_H_

#include <bsm/audit.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw.h>
#include <nfsc/libnfs-raw-mount.h>
#include <nfsc/libnfs-raw-nfs.h>
#include <nfsc/libnfs-raw-portmap.h>

struct au_rpc_data {
//	char*	file_path;
	int	au_rpc_status;
	int	au_rpc_result; /* RPC result status/error. refer: libnfs-raw-nfs.h */
	int	au_rpc_event;
	int	is_finished;
};
struct nfs_fh {
	int len;
	char *val;
};
struct nfs_context {
	struct	rpc_context *rpc;
	char	*server;
	char	*export;
	struct nfs_fh	rootfh;
	uint64_t	readmax;
	uint64_t	writemax;
	char*	cwd;
	int	auto_reconnect;
	uint16_t	mask;

	int	version;
	int	nfsport;
	int	mountport;
};

static char *SERVER = "192.168.56.105";
static struct pollfd fds[1];
static mode_t mode = 0777;
static const char *auclass = "nfs";

struct nfs_context *tc_body_init(int, struct au_rpc_data*);
void nfs_res_close_cb(struct nfs_context*, int, void*, void*);
int nfs_poll_fd(struct nfs_context*, struct au_rpc_data*);
void check_audit(struct pollfd [], const char *, FILE *);
FILE *setup(struct pollfd [], const char *);
void cleanup(void);

/*
 * ATF test case success/failure
 */
#define SUCCESS 0
#define FAILURE 1

/*
 * NFSv3 RPC related events
 */
#define AUE_NFS3RPC_GETATTR	43266	
#define AUE_NFS3RPC_SETATTR	43267
#define AUR_NFS3RPC_LOOKUP	43268
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

#endif
