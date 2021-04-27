#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <string>
#include <algorithm>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFSZ 1024

struct client_data {
    int csock;
    struct sockaddr_storage storage;
};

void usage(int argc, char **argv) {
	printf("usage: %s <server IP> <server port>\n", argv[0]);
	printf("example: %s 127.0.0.1 51511\n", argv[0]);
	exit(EXIT_FAILURE);
}

void * send_thread(void *data) {
    struct client_data *cdata = (struct client_data *)data;

    char buf[BUFSZ];
    
    while(1) {
   		memset(buf, 0, BUFSZ);
		fgets(buf, BUFSZ-1, stdin);
		std::string msg(buf);
		std::remove(msg.begin(), msg.end(), '\0'); //remove \0            
   		send(cdata->csock, &msg[0], msg.size(), 0);
	}
    
    pthread_exit(EXIT_SUCCESS);
}

void * recv_thread(void *data) {
    struct client_data *cdata = (struct client_data *)data;

    char buf[BUFSZ];
	unsigned total = 0;

    while(1) {
		memset(buf, 0, BUFSZ);
		size_t count = recv(cdata->csock, buf + total, BUFSZ - total, 0);
		
		if (count == 0) {
			// Connection terminated.
			exit(EXIT_SUCCESS);
		}

		puts(buf+total);
		total += count;
	
	}
    
    close(cdata->csock);
    pthread_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
	if (argc < 3) {
		usage(argc, argv);
	}

	struct sockaddr_storage storage;
	
	if (addrparse(argv[1], argv[2], &storage) != 0) {
		usage(argc, argv);
	}

	int sock;
	sock = socket(storage.ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		logexit("socket");
	}

	struct sockaddr *addr = (struct sockaddr *)(&storage);
	if (connect(sock, addr, sizeof(storage)) != 0) {
		logexit("connect");
	}

	char addrstr[BUFSZ];
	addrtostr(addr, addrstr, BUFSZ);

	printf("connected to %s\n", addrstr);

	struct client_data *cdata = new client_data; //cria o client
    if (!cdata) {
	    logexit("malloc");
	}
	
    cdata->csock = sock;
	memcpy(&(cdata->storage), &storage, sizeof(storage));

    pthread_t send_id, recv_id;
    pthread_create(&send_id, NULL, send_thread, cdata); //thread para send
    pthread_create(&recv_id, NULL, recv_thread, cdata); //thread para recv

    /* precisamos desse while para evitar que o programa termine prematuramente, 
    as threads serao responsaveis por terminar o programa */
    while(1) {
    	
    }

	exit(EXIT_SUCCESS);
}