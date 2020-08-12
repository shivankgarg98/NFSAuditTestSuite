#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

//static struct pollfd fds[1];
//static const char *auclass = "nfs";
//static char path[] = "fileforaudit";
//static const char *successreg = "fileforaudit.*return,success";
//static const char *failurereg = "fileforaudit.*return,failure";

ATF_TC_WITH_CLEANUP(nfs4_getattr_success);
ATF_TC_HEAD(nfs4_getattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv4 getattr RPC");
}

ATF_TC_BODY(nfs4_getattr_success, tc)
{
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
}

ATF_TC_CLEANUP(nfs4_getattr_failure, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs4_getattr_success);
	ATF_TP_ADD_TC(tp, nfs4_getattr_failure);

	return (atf_no_error());
}
