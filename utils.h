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

struct client {
	char	*server;
	char	*export;
	uint32_t	mount_port;
	rpc_cb	au_rpc_cb;
	int	au_rpc_status;
	int	is_finished;
	struct	nfs_fh3 rootfh;
};

void nfs_setup(struct rpc_context *rpc, void *private_data);
void nfs_destroy(struct rpc_context *rpc);

void check_audit(struct pollfd [], const char *, FILE *);
FILE *setup(struct pollfd [], const char *);
void cleanup(void);

#endif
