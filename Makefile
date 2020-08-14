TESTSDIR=${LOCALBASE}/tests/nfs-audit
BINDIR=${TESTSDIR}	

PROGS+=	nfsv3-test
PROGS+=	nfsv4-test

SRCS.nfsv3-test+=	nfsv3-test.c
SRCS.nfsv4-test+=	nfsv4-test.c

SRCS.nfsv3-test+=	utils.c
SRCS.nfsv4-test+=	utils.c
CFLAGS+=	-I${LOCALBASE}/include

LDFLAGS+=	-lbsm -latf-c -lnfs

WARNS?=	6

LDADD+=	-L${LOCALBASE}/lib

.include <bsd.test.mk>
