#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

static char *client_path = "fileforaudit";
static char *server_path = "/mnt/NFS_audit_test/fileforaudit";
static char *successreg = "fileforaudit.*return,success";
static char *failurereg = "fileforaudit.*return,failure";


ATF_TC_WITH_CLEANUP(nfs3_getattr_success);
ATF_TC_HEAD(nfs3_getattr_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 getattr RPC");
}
ATF_TC_BODY(nfs3_getattr_success, tc)
{
	tc_body_helper(AUE_NFS3RPC_GETATTR, SUCCESS, "nfsrvd_getattr.*return,success");
}
ATF_TC_CLEANUP(nfs3_getattr_success, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(nfs3_getattr_failure);
ATF_TC_HEAD(nfs3_getattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 getattr RPC");
}
ATF_TC_BODY(nfs3_getattr_failure, tc)
{
/*
 * GETATTR FAILURE WHEN AND HOW????
 *
 */
	ATF_REQUIRE_MSG(1==0, "To find when getattr rpc can fail");
//	tc_body_helper(AUE_NFS3RPC_GETATTR, FAILURE, "nfsrvd_getattr.*return,failure");

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
}
ATF_TC_CLEANUP(nfs3_setattr_success, tc)
{
}

ATF_TC_WITH_CLEANUP(nfs3_setattr_failure);
ATF_TC_HEAD(nfs3_setattr_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 setattr RPC");
}
ATF_TC_BODY(nfs3_setattr_failure, tc)
{
}
ATF_TC_CLEANUP(nfs3_setattr_failure, tc)
{
}

ATF_TC_WITH_CLEANUP(nfs3_lookup_success);
ATF_TC_HEAD(nfs3_lookup_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 lookup RPC");
}
ATF_TC_BODY(nfs3_lookup_success, tc)
{
}
ATF_TC_CLEANUP(nfs3_lookup_success, tc)
{
}

ATF_TC_WITH_CLEANUP(nfs3_lookup_failure);
ATF_TC_HEAD(nfs3_lookup_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 lookup RPC");
}
ATF_TC_BODY(nfs3_lookup_failure, tc)
{
}
ATF_TC_CLEANUP(nfs3_lookup_failure, tc)
{
}


ATF_TC_WITH_CLEANUP(nfs3_create_success);
ATF_TC_HEAD(nfs3_create_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_success, tc)
{
	tc_body_helper(AUE_NFS3RPC_CREATE, SUCCESS, successreg);
}

ATF_TC_CLEANUP(nfs3_create_success, tc)
{
	cleanup();
	remove(server_path);
}

ATF_TC_WITH_CLEANUP(nfs3_create_failure);
ATF_TC_HEAD(nfs3_create_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of an unsuccessful "
					"NFSv3 create RPC");
}

ATF_TC_BODY(nfs3_create_failure, tc)
{

	ATF_REQUIRE(open(server_path, O_CREAT, mode) != -1);	

	tc_body_helper(AUE_NFS3RPC_CREATE, FAILURE, failurereg);
}

ATF_TC_CLEANUP(nfs3_create_failure, tc)
{
	cleanup();
	remove(server_path);
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_success);
ATF_TC_HEAD(nfs3_mkdir_success, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a successful "
					"NFSv3 mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_success, tc)
{
	tc_body_helper(AUE_NFS3RPC_MKDIR, SUCCESS, successreg);
}

ATF_TC_CLEANUP(nfs3_mkdir_success, tc)
{
	cleanup();
	remove(server_path);
}

ATF_TC_WITH_CLEANUP(nfs3_mkdir_failure);
ATF_TC_HEAD(nfs3_mkdir_failure, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the audit of a unsuccessful "
					"NFSv3 mkdir RPC");
}

ATF_TC_BODY(nfs3_mkdir_failure, tc)
{
	ATF_REQUIRE_EQ(0, mkdir(server_path, mode));
	tc_body_helper(AUE_NFS3RPC_MKDIR, FAILURE, failurereg);
}

ATF_TC_CLEANUP(nfs3_mkdir_failure, tc)
{
	cleanup();
	remove(server_path);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, nfs3_getattr_success);
	ATF_TP_ADD_TC(tp, nfs3_getattr_failure);
	ATF_TP_ADD_TC(tp, nfs3_create_success);
	ATF_TP_ADD_TC(tp, nfs3_create_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_failure);
	ATF_TP_ADD_TC(tp, nfs3_mkdir_success);

	return (atf_no_error());
}
