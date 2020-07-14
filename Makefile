TESTSDIR=	${LOCALBASE}/tests/nfs-audit

PROG=	nfs-test3

SRCS+=	nfs-test3.c
SRCS+=	utils.c

CFLAGS+=	-I${LOCALBASE}/include

LDFLAGS+=	-lbsm -latf-c -lnfs

LDADD+=	-L${LOCALBASE}/lib

.include <bsd.test.mk>
