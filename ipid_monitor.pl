#!/usr/bin/perl -w
#
# Script to collection IP ID values to enumrate remote host activity for profiling purposes e.g. amount of hosts behind IP address, OS fingerprinting, frequency analysis for denial of service plan simulation - Tom Van de Wiele 2009
#

use strict;
sub usage() {
   print "IP ID monitor using sqlite - Tom Van de Wiele, 2009\n\n./ipid_monitor.pl <host> <tcp port>\n";
}

if ($#ARGV < 1) {
   usage();
   exit(0);
}

my $host = $ARGV[0];
my $port = $ARGV[1];
my $sqlite = "/usr/bin/sqlite3";
my $HPING3 = "/usr/sbin/hping3";
my $outputdb = $host . ".sqlite.db";
my $ipid;
my $TIMEOUT = 1;

while(1) {
   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
   $year += 1900;
   $mon  += 1;
   print "Probing $host on port $port...\n";
   my $rawid = `sudo $HPING3 -S -p $port -c 1 $host 2>&1| grep len`;

   if ($rawid =~ /^.*id=(\d*)\s+.*$/) {
      $ipid = $1;
   }
   else {
      $ipid = "NA";
   }

   if (! -e $outputdb) {
      print "Creating a new database...\n";
      my $return = `$sqlite $outputdb "create table stats (id INTEGER PRIMARY KEY, host TEXT, ipid TEXT, date TEXT);"`;
   }
   print "Adding to database...\n";
   my $sqlinsertout = sprintf ("$sqlite $outputdb \"insert into stats (id,host,ipid,date) values (NULL,\'$host\',\'$ipid\',\\\"%02d/%02d/%04d %02d:%02d:%02d\\\");\"\n", $mday, $mon, $year, $hour, $min, $sec);
   my $sqlinject = `$sqlinsertout`;
   print "Sleeping $TIMEOUT seconds...\n";
   sleep $TIMEOUT;
}