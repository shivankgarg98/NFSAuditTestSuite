# $FreeBSD$

TESTSDIR=	${LOCALBASE}/tests/nfs-audit

ATF_TESTS_C+=	nfs-test3

SRCS.nfs-test3+=	nfs-test3.c
SRCS.nfs-test3+=	utils.c

LDFLAGS+=	-lbsm -lutil

LDADD.nfs-test3+=	${LOCALBASE}/lib/libnfs.a

CFLAGS+=	-I${LOCALBASE}/include

.include <bsd.test.mk>
