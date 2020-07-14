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

int
nfs_poll_fd(struct rpc_context *rpc, struct client *client)
{
	struct pollfd pfd;
	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed\n");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			return RPC_STATUS_ERROR;
		}

		if (client->is_finished) {
			break;
		}

	}
	
	return client->au_rpc_status;

}

static void
nfs_connect_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to RPC.MOUNTD on server %s failed\n", client->server);
		exit(10);
	}

	printf("Connected to RPC.NFSD on %s:%d\n", client->server, client->mount_port);

	if (rpc_nfs3_null_async(rpc, client->au_rpc_cb, client) != 0) {
		printf("Failed to sent a NULL RPC\n");
		exit(10);
	}
}

static void
mount_mnt_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	mountres3 *mnt = data;

	if (status == RPC_STATUS_ERROR) {
		printf("mount/mnt call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("mount/mnt call to server %s failed, status:%d\n", client->server, status);
		exit(10);
	}

	printf("Got reply from server for MOUNT/MNT procedure.\n");
	client->rootfh.data.data_len = mnt->mountres3_u.mountinfo.fhandle.fhandle3_len;
        client->rootfh.data.data_val = malloc(client->rootfh.data.data_len);
	memcpy(client->rootfh.data.data_val, mnt->mountres3_u.mountinfo.fhandle.fhandle3_val, client->rootfh.data.data_len);

	printf("Disconnect socket from mountd server\n");
	if (rpc_disconnect(rpc, "normal disconnect") != 0) {
		printf("Failed to disconnect socket to mountd\n");
		exit(10);
	}

	printf("Connect to RPC.NFSD on %s:%d\n", client->server, 2049);
	if (rpc_connect_async(rpc, client->server, 2049, nfs_connect_cb, client) != 0) {
		printf("Failed to start connection\n");
		exit(10);
	}
}

static void
mount_export_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	exports export = *(exports *)data;

	if (status == RPC_STATUS_ERROR) {
		printf("mount null call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("mount null call to server %s failed, status:%d\n", client->server, status);
		exit(10);
	}

	printf("Got reply from server for MOUNT/EXPORT procedure.\n");
	while (export != NULL) {
		printf("Export: %s\n", export->ex_dir);
		export = export->ex_next;
	}
	printf("Send MOUNT/MNT command for %s\n", client->export);
	if (rpc_mount_mnt_async(rpc, mount_mnt_cb, client->export, client) != 0) {
		printf("Failed to send mnt request\n");
		exit(10);
	}
}

static void
mount_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_ERROR) {
		printf("mount null call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("mount null call to server %s failed, status:%d\n", client->server, status);
		exit(10);
	}

	printf("Got reply from server for MOUNT/NULL procedure.\n");
	printf("Send MOUNT/EXPORT command\n");
	if (rpc_mount_export_async(rpc, mount_export_cb, client) != 0) {
		printf("Failed to send export request\n");
		exit(10);
	}
}

static void
mount_connect_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to RPC.MOUNTD on server %s failed\n", client->server);
		exit(10);
	}

	printf("Connected to RPC.MOUNTD on %s:%d\n", client->server, client->mount_port);
	printf("Send NULL request to check if RPC.MOUNTD is actually running\n");
	if (rpc_mount_null_async(rpc, mount_null_cb, client) != 0) {
		printf("Failed to send null request\n");
		exit(10);
	}
}

static void
pmap_getport2_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_ERROR) {
		printf("portmapper getport call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
       	if (status != RPC_STATUS_SUCCESS) {
		printf("portmapper getport call to server %s failed, status:%d\n", client->server, status);
		exit(10);
	}

	client->mount_port = *(uint32_t *)data;
	printf("GETPORT returned RPC.MOUNTD is on port:%d\n", client->mount_port);
	if (client->mount_port == 0) {
		printf("RPC.MOUNTD is not available on server : %s:%d\n", client->server, client->mount_port);
		exit(10);
	}		

	printf("Disconnect socket from portmap server\n");
	if (rpc_disconnect(rpc, "normal disconnect") != 0) {
		printf("Failed to disconnect socket to portmapper\n");
		exit(10);
	}

	printf("Connect to RPC.MOUNTD on %s:%d\n", client->server, client->mount_port);
	if (rpc_connect_async(rpc, client->server, client->mount_port, mount_connect_cb, client) != 0) {
		printf("Failed to start connection\n");
		exit(10);
	}
}

static void
pmap_dump_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;
	struct pmap2_dump_result *dr = data;
	struct pmap2_mapping_list *list = dr->list;

	if (status == RPC_STATUS_ERROR) {
		printf("portmapper null call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("portmapper null call to server %s failed, status:%d\n", client->server, status);
		exit(10);
	}

	printf("Got reply from server for PORTMAP/DUMP procedure.\n");
	while (list) {
		printf("Prog:%d Vers:%d Protocol:%d Port:%d\n",
			list->map.prog,
			list->map.vers,
			list->map.prot,
			list->map.port);
		list = list->next;
	}
	printf("Send getport request asking for MOUNT port\n");
	if (rpc_pmap2_getport_async(rpc, MOUNT_PROGRAM, MOUNT_V3, IPPROTO_TCP, pmap_getport2_cb, client) != 0) {
		printf("Failed to send getport request\n");
		exit(10);
	}
}

static void
pmap_null_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_ERROR) {
		printf("portmapper null call failed with \"%s\"\n", (char *)data);
		exit(10);
	}
	if (status != RPC_STATUS_SUCCESS) {
		printf("portmapper null call to server %s failed, status:%d\n", client->server, status);
		exit(10);
	}

	printf("Got reply from server for PORTMAP/NULL procedure.\n");
	printf("Send PMAP/DUMP command\n");
	if (rpc_pmap2_dump_async(rpc, pmap_dump_cb, client) != 0) {
		printf("Failed to send getport request\n");
		exit(10);
	}
}

static void
pmap_connect_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	printf("pmap_connect_cb status:%d.\n", status);
	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to portmapper on server %s failed\n", client->server);
		exit(10);
	}

	printf("Send NULL request to check if portmapper is actually running\n");
	if (rpc_pmap2_null_async(rpc, pmap_null_cb, client) != 0) {
		printf("Failed to send null request\n");
		exit(10);
	}
}

void
nfs_setup(struct rpc_context *rpc, void *private_data)
{
	struct client *client = private_data;

	ATF_REQUIRE(rpc != NULL);

	ATF_REQUIRE_EQ(0, system("service nfsd onestatus || \
	{ service nfsd onestart && touch started_nfsd ; }"));

	ATF_REQUIRE_EQ(0, rpc_connect_async(rpc, client->server, 111,
	    pmap_connect_cb, client));
}

void
nfs_destroy(struct rpc_context *rpc)
{

	rpc_destroy_context(rpc);
	rpc = NULL;
}
