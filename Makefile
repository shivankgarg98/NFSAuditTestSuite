TESTSDIR=${LOCALBASE}/tests/nfs-audit
BINDIR=${TESTSDIR}	
PROG=	nfs-test1

SRCS+=	nfs-test1.c
SRCS+=	utils.c

CFLAGS+=	-I${LOCALBASE}/include

LDFLAGS+=	-lbsm -latf-c -lnfs

WARNS?= 6

LDADD+=	-L${LOCALBASE}/lib

.include <bsd.test.mk>
