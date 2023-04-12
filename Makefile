all:
	gcc -Wall -w -o sshserv sshserv.c -I/usr/local/ssl/include/ -L/usr/local/ssl/lib -lssl -lcrypto
