#include "utils.h"
#include <unistd.h>
#define SERVER "192.168.56.105"
#define EXPORT "/usr/home/shivank/TEST_NFS"

static void
mkdir_status_cb(struct rpc_context *rpc, int status, void * data,  void *private_data)
{
	struct client *client = private_data;

	if (status == RPC_STATUS_SUCCESS)
		printf("success\n");
	if (status == RPC_STATUS_ERROR)
		printf("mkdir error\n");
	if (status == RPC_STATUS_CANCEL)
		printf("mkdir cancel\n");

	client->au_rpc_status = status;
	client->is_finished = 1;
	printf("complete\n");
}

static void
mkdir_cb(struct rpc_context *rpc, int status, void *data, void *private_data)
{
	struct client *client = private_data;

	if (status != RPC_STATUS_SUCCESS) {
		printf("connection to RPC.MOUNTD on server %s failed\n", client->server);
		exit(10);
	}

	MKDIR3args args;
	memset(&args, 0, sizeof(MKDIR3args));
	args.where.dir = client->rootfh;
	args.where.name = "TEST_DIR_AU";
	args.attributes.mode.set_it = 1;
	args.attributes.mode.set_mode3_u.mode = 420;

	printf("Connected to RPC.NFSD on %s:%d\n", client->server, client->mount_port);
	if (rpc_nfs3_mkdir_async(rpc, mkdir_status_cb, &args, client) != 0) {
		printf("Failed to send mkdir request\n");
		exit(10);
	}
}

int
main()
{
	struct rpc_context *rpc;
	struct pollfd pfd;
	struct client client;

	client.server = SERVER;
	client.export = EXPORT;
	client.au_rpc_status = -1;
	client.is_finished = 0;
	/* **** mkdir success **** */
	/*
	client.audit_cb = mkdir_cb;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	printf("RPC done\n");	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		printf("RPC\n");
		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed\n");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			break;
		}

		printf("RPC %d \n", client.is_finished);
		if (client.is_finished) {
			break;
		}

	}
	printf("RPC DONE now destroy\n");
	nfs_destroy(rpc);
	*/
	/* **** mkdir success **** */

	/* **** mkdir failure **** */
	client.au_rpc_cb = mkdir_cb;
	rpc = rpc_init_context();
	nfs_setup(rpc, &client);
	printf("RPC done\n");	
	for (;;) {
		pfd.fd = rpc_get_fd(rpc);
		pfd.events = rpc_which_events(rpc);

		printf("RPC\n");
		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed\n");
			exit(10);
		}

		if (rpc_service(rpc, pfd.revents) < 0) {
			printf("rpc_service failed\n");
			break;
		}

		printf("RPC %d \n", client.is_finished);
		if (client.is_finished) {
			break;
		}

	}

	printf("RPC DONE now destroy\n");
	nfs_destroy(rpc);
}
