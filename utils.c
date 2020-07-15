/*-
 * Copyright 2018 Aniket Pandey
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

static char *client_path = "fileforaudit";
static char *server_path = "/mnt/NFS_audit_test/fileforaudit";

/*
 * Checks the presence of "auditregex" in auditpipe(4) after the
 * corresponding system call has been triggered.
 */
static bool
get_records(const char *auditregex, FILE *pipestream)
{
	uint8_t *buff;
	tokenstr_t token;
	ssize_t size = 1024;
	char membuff[size];
	char del[] = ",";
	int reclen, bytes = 0;
	FILE *memstream;

	/*
	 * Open a stream on 'membuff' (address to memory buffer) for storing
	 * the audit records in the default mode.'reclen' is the length of the
	 * available records from auditpipe which is passed to the functions
	 * au_fetch_tok(3) and au_print_flags_tok(3) for further use.
	 */
	ATF_REQUIRE((memstream = fmemopen(membuff, size, "w")) != NULL);
	ATF_REQUIRE((reclen = au_read_rec(pipestream, &buff)) != -1);

	/*
	 * Iterate through each BSM token, extracting the bits that are
	 * required to start processing the token sequences.
	 */
	while (bytes < reclen) {
		if (au_fetch_tok(&token, buff + bytes, reclen - bytes) == -1) {
			perror("au_read_rec");
			atf_tc_fail("Incomplete Audit Record");
		}

		/* Print the tokens as they are obtained, in the default form */
		au_print_flags_tok(memstream, &token, del, AU_OFLAG_NONE);
		bytes += token.len;
	}

	free(buff);
	ATF_REQUIRE_EQ(0, fclose(memstream));
	return (atf_utils_grep_string("%s", membuff, auditregex));
}

/*
 * Override the system-wide audit mask settings in /etc/security/audit_control
 * and set the auditpipe's maximum allowed queue length limit
 */
static void
set_preselect_mode(int filedesc, au_mask_t *fmask)
{
	int qlimit_max;
	int fmode = AUDITPIPE_PRESELECT_MODE_LOCAL;

	/* Set local preselection mode for auditing */
	if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_MODE, &fmode) < 0)
		atf_tc_fail("Preselection mode: %s", strerror(errno));

	/* Set local preselection flag corresponding to the audit_event */
	if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_FLAGS, fmask) < 0)
		atf_tc_fail("Preselection flag: %s", strerror(errno));

	/* Set local preselection flag for non-attributable audit_events */
	if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_NAFLAGS, fmask) < 0)
		atf_tc_fail("Preselection naflag: %s", strerror(errno));

	/* Query the maximum possible queue length limit for auditpipe */
	if (ioctl(filedesc, AUDITPIPE_GET_QLIMIT_MAX, &qlimit_max) < 0)
		atf_tc_fail("Query max-limit: %s", strerror(errno));

	/* Set the queue length limit as obtained from previous step */
	if (ioctl(filedesc, AUDITPIPE_SET_QLIMIT, &qlimit_max) < 0)
		atf_tc_fail("Set max-qlimit: %s", strerror(errno));

	/* This removes any outstanding record on the auditpipe */
	if (ioctl(filedesc, AUDITPIPE_FLUSH) < 0)
		atf_tc_fail("Auditpipe flush: %s", strerror(errno));
}

/*
 * Get the corresponding audit_mask for class-name "name" then set the
 * success and failure bits for fmask to be used as the ioctl argument
 */
static au_mask_t
get_audit_mask(const char *name)
{
	au_mask_t fmask;
	au_class_ent_t *class;

	ATF_REQUIRE((class = getauclassnam(name)) != NULL);
	fmask.am_success = class->ac_class;
	fmask.am_failure = class->ac_class;
	return (fmask);
}

/*
 * Loop until the auditpipe returns something, check if it is what
 * we want, else repeat the procedure until ppoll(2) times out.
 */
static void
check_auditpipe(struct pollfd fd[], const char *auditregex, FILE *pipestream)
{
	struct timespec currtime, endtime, timeout;

	/* Set the expire time for poll(2) while waiting for syscall audit */
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &endtime));
	endtime.tv_sec += 10;
	timeout.tv_nsec = endtime.tv_nsec;

	for (;;) {
		/* Update the time left for auditpipe to return any event */
		ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &currtime));
		timeout.tv_sec = endtime.tv_sec - currtime.tv_sec;

		switch (ppoll(fd, 1, &timeout, NULL)) {
		/* ppoll(2) returns, check if it's what we want */
		case 1:
			if (fd[0].revents & POLLIN) {
				if (get_records(auditregex, pipestream))
					return;
			} else {
				atf_tc_fail("Auditpipe returned an "
				"unknown event %#x", fd[0].revents);
			}
			break;

		/* poll(2) timed out */
		case 0:
			atf_tc_fail("%s not found in auditpipe within the "
					"time limit", auditregex);
			break;

		/* poll(2) standard error */
		case -1:
			atf_tc_fail("Poll: %s", strerror(errno));
			break;

		default:
			atf_tc_fail("Poll returned too many file descriptors");
		}
	}
}

/*
 * Wrapper functions around static "check_auditpipe"
 */
static void
check_audit_startup(struct pollfd fd[], const char *auditrgx, FILE *pipestream){
	check_auditpipe(fd, auditrgx, pipestream);
}

void
check_audit(struct pollfd fd[], const char *auditrgx, FILE *pipestream) {
	check_auditpipe(fd, auditrgx, pipestream);

	/* Teardown: /dev/auditpipe's instance opened for this test-suite */
	ATF_REQUIRE_EQ(0, fclose(pipestream));
}

FILE
*setup(struct pollfd fd[], const char *name)
{
	au_mask_t fmask, nomask;
	fmask = get_audit_mask(name);
	nomask = get_audit_mask("no");
	FILE *pipestream;

	ATF_REQUIRE((fd[0].fd = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE((pipestream = fdopen(fd[0].fd, "r")) != NULL);
	fd[0].events = POLLIN;

	/*
	 * Disable stream buffering for read operations from /dev/auditpipe.
	 * Otherwise it is possible that fread(3), called via au_read_rec(3),
	 * can store buffered data in user-space unbeknown to ppoll(2), which
	 * as a result, reports that /dev/auditpipe is empty.
	 */
	ATF_REQUIRE_EQ(0, setvbuf(pipestream, NULL, _IONBF, 0));

	/* Set local preselection audit_class as "no" for audit startup */
	set_preselect_mode(fd[0].fd, &nomask);
	ATF_REQUIRE_EQ(0, system("service auditd onestatus || \
	{ service auditd onestart && touch started_auditd ; }"));

	/* If 'started_auditd' exists, that means we started auditd(8) */
	if (atf_utils_file_exists("started_auditd"))
		check_audit_startup(fd, "audit startup", pipestream);

	/* Set local preselection parameters specific to "name" audit_class */
	set_preselect_mode(fd[0].fd, &fmask);
	return (pipestream);
}

void
cleanup(void)
{
	if (atf_utils_file_exists("started_nfsd"))
		system("service nfsd onestop > /dev/null 2>&1");
	if (atf_utils_file_exists("started_auditd"))
		system("service auditd onestop > /dev/null 2>&1");
}

void tc_body_helper(int au_rpc_event, int tc_type, char *regex)
{
	FILE *pipefd = setup(fds, auclass);
	struct rpc_context *rpc;
	struct client client;

	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.au_rpc_result = -1;
	client.is_finished = 0;
	client.au_test_nature = tc_type;
	client.au_rpc_event = au_rpc_event;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);

	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, nfs_poll_fd(rpc, &client));
	nfs_destroy(rpc);

	switch (tc_type) {
	case SUCCESS: 
		ATF_REQUIRE(NFS3_OK == client.au_rpc_result);
		break;
	case FAILURE:
		ATF_REQUIRE(NFS3_OK != client.au_rpc_result);
		break;
	}
	check_audit(fds, regex, pipefd);
}

int
nfs_poll_fd(struct rpc_context *rpc, struct client *client)
{
	struct pollfd pfd;
	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		if (poll(&pfd, 1, -1) < 0) {
			atf_tc_fail("poll failed");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			atf_tc_fail("rpc_service failed");
			break;
		}
		if (client->is_finished) {
			break;
		}
	}
	
	return client->au_rpc_status;

}

static void
nfs_res_close_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	switch (client->au_rpc_event) {
	case AUE_NFS3RPC_GETATTR:
		client->au_rpc_result = ((GETATTR3res *)data)->status;
		break;
	case AUE_NFS3RPC_SETATTR:
		break;
	case AUR_NFS3RPC_LOOKUP:
		break;
	case AUE_NFS3RPC_ACCESS:
		break;
	case AUE_NFS3RPC_READLINK:
		break;
	case AUE_NFS3RPC_READ:
		break;
	case AUE_NFS3RPC_CREATE:
		client->au_rpc_result = ((CREATE3res *)data)->status;
		break;
	case AUE_NFS3RPC_MKDIR:
		client->au_rpc_result = ((MKDIR3res *)data)->status;
		break;
	case AUE_NFS3RPC_WRITE:
		break;
	case AUE_NFS3RPC_SYMLINK:
		break;
	case AUE_NFS3RPC_MKNOD:
		break;
	case AUE_NFS3RPC_REMOVE:
		break;
	case AUE_NFS3RPC_RMDIR:
		break;
	case AUE_NFS3RPC_RENAME:
		break;
	case AUE_NFS3RPC_LINK:
		break;
	case AUE_NFS3RPC_READDIR:
		break;
	case AUE_NFS3RPC_READDIRPLUS:
		break;
	case AUE_NFS3RPC_FSSTAT:
		break;
	case AUE_NFS3RPC_FSINFO:
		break;
	case AUE_NFS3RPC_PATHCONF:
		break;
	case AUE_NFS3RPC_COMMIT:
		break;
	default:
		ATF_REQUIRE_EQ(1,0);
	}
	client->au_rpc_status = status;
	client->is_finished = 1;
	printf("complete\n");
}

static void
nfs_connect_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE_EQ(RPC_STATUS_SUCCESS, status);

	printf("Connected to RPC.NFSD on %s:%d\n", client->server, client->mount_port);
	
	switch (client->au_rpc_event) {
	case AUE_NFS3RPC_GETATTR:
	{
		GETATTR3args args;
		args.object = client->rootfh;
		ATF_REQUIRE_EQ(0, rpc_nfs3_getattr_async(rpc, nfs_res_close_cb, &args, client));
		break;
	}
	case AUE_NFS3RPC_SETATTR:
	{
		break;
	}
	case AUR_NFS3RPC_LOOKUP:
	{
		break;
	}
	case AUE_NFS3RPC_ACCESS:
	{
		break;
	}
	case AUE_NFS3RPC_READLINK:
	{
		break;
	}
	case AUE_NFS3RPC_READ:
	{
		break;
	}
	case AUE_NFS3RPC_WRITE:
	{
		break;
	}
	case AUE_NFS3RPC_CREATE:
	{
		CREATE3args args;
		args.where.dir = client->rootfh;
		args.where.name = client_path;
		args.how.mode = GUARDED; /* Similiar to case if O_EXCL flag is provided with O_CREAT. */
		args.how.createhow3_u.obj_attributes.mode.set_it = 1;
		args.how.createhow3_u.obj_attributes.mode.set_mode3_u.mode = 0777;
		ATF_REQUIRE_EQ(0, rpc_nfs3_create_async(rpc, nfs_res_close_cb, &args, client));
		break;
	}
	case AUE_NFS3RPC_MKDIR:
	{
		MKDIR3args args;
		args.where.dir = client->rootfh;
		args.where.name = client_path;
		args.attributes.mode.set_it = 1;
		args.attributes.mode.set_mode3_u.mode = 0777;
		ATF_REQUIRE_EQ(0, rpc_nfs3_mkdir_async(rpc, nfs_res_close_cb, &args, client));
		break;
	}
	case AUE_NFS3RPC_SYMLINK:
	{
		break;
	}
	case AUE_NFS3RPC_MKNOD:
	{
		break;
	}
	case AUE_NFS3RPC_REMOVE:
	{
		break;
	}
	case AUE_NFS3RPC_RMDIR:
	{
		break;
	}
	case AUE_NFS3RPC_RENAME:
	{
		break;
	}
	case AUE_NFS3RPC_LINK:
	{
		break;
	}
	case AUE_NFS3RPC_READDIR:
	{
		break;
	}
	case AUE_NFS3RPC_READDIRPLUS:
	{
		break;
	}
	case AUE_NFS3RPC_FSSTAT:
	{
		break;
	}
	case AUE_NFS3RPC_FSINFO:
	{
		break;
	}
	case AUE_NFS3RPC_PATHCONF:
	{
		break;
	}
	case AUE_NFS3RPC_COMMIT:
	{
		break;
	}
	default:
		ATF_REQUIRE_EQ(0, 1);
	}
}

static void
mount_mnt_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	mountres3 *mnt = data;

	ATF_REQUIRE_MSG(status != RPC_STATUS_ERROR, "mount/mnt call failed with \"%s\"", (char *)data);
	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "mount/mnt call to server %s failed, status:%d", client->server, status);

	client->rootfh.data.data_len = mnt->mountres3_u.mountinfo.fhandle.fhandle3_len;
        client->rootfh.data.data_val = malloc(client->rootfh.data.data_len);
	memcpy(client->rootfh.data.data_val, mnt->mountres3_u.mountinfo.fhandle.fhandle3_val, client->rootfh.data.data_len);

	ATF_REQUIRE_MSG(rpc_disconnect(rpc, "normal disconnect") == 0, "Failed to disconnect socket to mountd");

	ATF_REQUIRE_MSG(rpc_connect_async(rpc, client->server, 2049, nfs_connect_cb, client) == 0, "Failed to start connection");
}

static void
mount_export_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	exports export = *(exports *)data;

	ATF_REQUIRE_MSG(status != RPC_STATUS_ERROR, "mount null call failed with \"%s\"", (char *)data);
	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "mount null call to server %s failed, status:%d", client->server, status);

	while (export != NULL) {
		printf("Export: %s\n", export->ex_dir);
		export = export->ex_next;
	}
	printf("Send MOUNT/MNT command for %s\n", client->export);
	ATF_REQUIRE_MSG(rpc_mount_mnt_async(rpc, mount_mnt_cb, client->export, client) == 0, "Failed to send mnt request");
}

static void
mount_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE_MSG(status != RPC_STATUS_ERROR, "mount null call failed with \"%s\"", (char *)data);
	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "mount null call to server %s failed, status:%d", client->server, status);

	ATF_REQUIRE_MSG(rpc_mount_export_async(rpc, mount_export_cb, client) == 0, "Failed to send export request");
}

static void
mount_connect_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "connection to RPC.MOUNTD on server %s failed", client->server);

	ATF_REQUIRE_MSG(rpc_mount_null_async(rpc, mount_null_cb, client) == 0, "Failed to send null request");
}

static void
pmap_getport2_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE_MSG(status != RPC_STATUS_ERROR, "portmapper getport call failed with \"%s\"", (char *)data);
       	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "portmapper getport call to server %s failed, status:%d", client->server, status);

	client->mount_port = *(uint32_t *)data;
	ATF_REQUIRE_MSG(client->mount_port != 0, "RPC.MOUNTD is not available on server : %s:%d", client->server, client->mount_port);

	ATF_REQUIRE_MSG(rpc_disconnect(rpc, "normal disconnect") == 0, "Failed to disconnect socket to portmapper");

	ATF_REQUIRE_MSG(rpc_connect_async(rpc, client->server, client->mount_port, mount_connect_cb, client) == 0, "Failed to start connection");
}

static void
pmap_dump_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap2_dump_result *dr = data;
	struct pmap2_mapping_list *list = dr->list;

	ATF_REQUIRE_MSG(status != RPC_STATUS_ERROR, "portmapper null call failed with \"%s\"", (char *)data);
	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "portmapper null call to server %s failed, status:%d\n", client->server, status);

	while (list) {
		printf("Prog:%d Vers:%d Protocol:%d Port:%d\n",
			list->map.prog,
			list->map.vers,
			list->map.prot,
			list->map.port);
		list = list->next;
	}

	ATF_REQUIRE_MSG(rpc_pmap2_getport_async(rpc, MOUNT_PROGRAM, MOUNT_V3, IPPROTO_TCP, pmap_getport2_cb, client) == 0, "Failed to send getport request");
}

static void
pmap_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE_MSG(status != RPC_STATUS_ERROR, "portmapper null call failed with \"%s\"", (char *)data);
	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "portmapper null call to server %s failed, status:%d", client->server, status);

	ATF_REQUIRE_MSG(rpc_pmap2_dump_async(rpc, pmap_dump_cb, client) == 0, "Failed to send getport request");
}

static void
pmap_connect_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE_MSG(status == RPC_STATUS_SUCCESS, "connection to portmapper on server %s failed", client->server);
	ATF_REQUIRE_MSG(rpc_pmap2_null_async(rpc, pmap_null_cb, client) == 0, "Failed to send null request");
}

void
nfs_setup(struct rpc_context *rpc, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE(rpc != NULL);

	ATF_REQUIRE_EQ(0, system("service nfsd onestatus || \
	{ service nfsd onestart && touch started_nfsd ; }"));

	ATF_REQUIRE_MSG(rpc_connect_async(rpc, client->server, 111, pmap_connect_cb, client) == 0, "Failed to start connection");
}

void
nfs_destroy(struct rpc_context *rpc)
{

	rpc_destroy_context(rpc);
	rpc = NULL;
}
