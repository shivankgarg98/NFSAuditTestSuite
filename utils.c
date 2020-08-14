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

#include <sys/ioctl.h>

#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

static char SERVER[] = "127.1";

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

	ATF_REQUIRE_MSG((class = getauclassnam(name)) != NULL,
	    "No audit class %s found", name);
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
	if (atf_utils_file_exists("started_auditd"))
		system("service auditd onestop > /dev/null 2>&1");
	if (atf_utils_file_exists("mountd_running"))
		system("service mountd restart > /dev/null 2>&1");
	else
		system("service mountd onestop > /dev/null 2>&1");
	if (atf_utils_file_exists("started_nfsd"))
		system("service nfsd onestop > /dev/null 2>&1");
}

struct nfs_context
*tc_body_init(int au_rpc_event, struct au_rpc_data* au_test_data)
{
	struct nfs_context *nfs;
	struct nfs_url url;
	char cwd[PATH_MAX];
	int error;

	nfs = nfs_init_context();
	ATF_REQUIRE(nfs != NULL);
	au_test_data->au_rpc_event = au_rpc_event;
	au_test_data->au_rpc_status = -1;
	au_test_data->au_rpc_result = -1;
	au_test_data->is_finished = 0;

	/* XXX TODO: Make the nfsv4_server_enable change temporary. */
	if (au_rpc_event >= AUE_NFSV4RPC_COMPOUND)
		system("sysrc nfsv4_server_enable=YES");

	ATF_REQUIRE_EQ(0, system(" ! { service mountd onestatus ; } || \
	    { service mountd onestop && touch mountd_running ; }"));

	if (au_rpc_event >= AUE_NFSV4RPC_COMPOUND)
		ATF_REQUIRE_EQ(0, system("echo V4: / 127.1 > NFSAuditExports"));
	ATF_REQUIRE_EQ(0, system("echo $PWD -mapall=root 127.1 >> \
	    NFSAuditExports && mountd NFSAuditExports"));

	ATF_REQUIRE_EQ(0, system("service nfsd onestatus || \
	    { service nfsd onestart && touch started_nfsd ; }"));

	ATF_REQUIRE(getcwd(cwd, PATH_MAX) != NULL);
	url.server = SERVER;
	url.path = cwd;
	/* loop waiting for nfsd to be ready to accept connections */
	for(;;) {
		error = nfs_mount(nfs, url.server, url.path);
		/*
		 * for reasons of its own, libnfs returns EFAULT if the mount
		 * fails.
		 */
		if (error != -EFAULT)
			break;
		usleep(10000);
	}
	ATF_REQUIRE_EQ_MSG(error, 0, "nfs_mount: %s", strerror(-error));

	return nfs;
}

int
nfs_poll_fd(struct nfs_context *nfs, struct au_rpc_data *au_test_data)
{
	struct pollfd pfd;
	struct rpc_context *rpc = nfs_get_rpc_context(nfs);	

	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);
		ATF_REQUIRE_MSG(poll(&pfd, 1, -1) >= 0, "poll failed");
		if (rpc_service(rpc, pfd.revents) < 0) {
			atf_tc_fail("rpc_service failed");
			break;
		}
		if (au_test_data->is_finished)
			break;
	}

	nfs_umount(nfs);
	rpc_destroy_context(nfs->rpc);
	nfs->rpc = NULL;
	free(nfs);

	return au_test_data->au_rpc_status;
}

void
nfs_res_close_cb(__unused struct nfs_context *nfs, int status, void *data, void *private_data)
{
	struct au_rpc_data* au_test_data = (struct au_rpc_data *)private_data;

	switch (au_test_data->au_rpc_event) {
	case AUE_NFS3RPC_GETATTR:
		au_test_data->au_rpc_result = ((GETATTR3res *)data)->status;
		break;
	case AUE_NFS3RPC_SETATTR:
		au_test_data->au_rpc_result = ((SETATTR3res *)data)->status;
		break;
	case AUE_NFS3RPC_LOOKUP:
		au_test_data->au_rpc_result = ((LOOKUP3res *)data)->status;
		break;
	case AUE_NFS3RPC_ACCESS:
		au_test_data->au_rpc_result = ((ACCESS3res *)data)->status;
		break;
	case AUE_NFS3RPC_READLINK:
		au_test_data->au_rpc_result = ((READLINK3res *)data)->status;
		break;
	case AUE_NFS3RPC_READ:
		au_test_data->au_rpc_result = ((READ3res *)data)->status;
		break;
	case AUE_NFS3RPC_CREATE:
		au_test_data->au_rpc_result = ((CREATE3res *)data)->status;
		break;
	case AUE_NFS3RPC_MKDIR:
		au_test_data->au_rpc_result = ((MKDIR3res *)data)->status;
		break;
	case AUE_NFS3RPC_WRITE:
		au_test_data->au_rpc_result = ((WRITE3res *)data)->status;
		break;
	case AUE_NFS3RPC_SYMLINK:
		au_test_data->au_rpc_result = ((SYMLINK3res *)data)->status;
		break;
	case AUE_NFS3RPC_MKNOD:
		au_test_data->au_rpc_result = ((MKNOD3res *)data)->status;
		break;
	case AUE_NFS3RPC_REMOVE:
		au_test_data->au_rpc_result = ((REMOVE3res *)data)->status;
		break;
	case AUE_NFS3RPC_RMDIR:
		au_test_data->au_rpc_result = ((RMDIR3res *)data)->status;
		break;
	case AUE_NFS3RPC_RENAME:
		au_test_data->au_rpc_result = ((RENAME3res *)data)->status;
		break;
	case AUE_NFS3RPC_LINK:
		au_test_data->au_rpc_result = ((LINK3res *)data)->status;
		break;
	case AUE_NFS3RPC_READDIR:
		au_test_data->au_rpc_result = ((READDIR3res *)data)->status;
		break;
	case AUE_NFS3RPC_READDIRPLUS:
		au_test_data->au_rpc_result = ((READDIRPLUS3res *)data)->status;
		break;
	case AUE_NFS3RPC_FSSTAT:
		au_test_data->au_rpc_result = ((FSSTAT3res *)data)->status;
		break;
	case AUE_NFS3RPC_FSINFO:
		au_test_data->au_rpc_result = ((FSINFO3res *)data)->status;
		break;
	case AUE_NFS3RPC_PATHCONF:
		au_test_data->au_rpc_result = ((PATHCONF3res *)data)->status;
		break;
	case AUE_NFS3RPC_COMMIT:
		au_test_data->au_rpc_result = ((COMMIT3res *)data)->status;
		break;
	default:
		ATF_REQUIRE_EQ_MSG(0, 1, "unknown RPC event");
	}
	au_test_data->au_rpc_status = status;
	au_test_data->is_finished = 1;
}

void
nfsv4_res_close_cb(__unused struct nfs_context *nfs, int status, void *data, void *private_data)
{
	struct au_rpc_data* au_test_data = (struct au_rpc_data *)private_data;
	COMPOUND4res *res = data;

	au_test_data->au_rpc_result = res->status;
	au_test_data->au_rpc_status = status;
	au_test_data->is_finished = 1;
}
