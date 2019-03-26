#!/usr/bin/perl

# создаем нужные файлы из БД rkn
# Внимание!!! IP адреса в базе должны храниться в виде байт, а не целого числа.

use strict;
use warnings;
use utf8;
use Config::Simple;
use DBI;
use File::Basename;
use URI;
use POSIX;
use Digest::MD5 qw (md5);
use Log::Log4perl;
use Net::IP qw(:PROC);
use Encode;
use Net::CIDR::Lite;

binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');

my $dir = File::Basename::dirname($0);

my $Config = {};
Config::Simple->import_from($dir.'/extfilter_maker.conf', $Config) or die "Can't open ".$dir."/extfilter_maker.conf for reading!\n";
Log::Log4perl::init( $dir."/extfilter_maker_log.conf" );

my $logger=Log::Log4perl->get_logger();


my $db_host = $Config->{'DB.host'} || die "DB.host not defined.";
my $db_user = $Config->{'DB.user'} || die "DB.user not defined.";
my $db_pass = $Config->{'DB.password'} || die "DB.password not defined.";
my $db_name = $Config->{'DB.name'} || die "DB.name not defined.";

# пути к генерируемым файлам:
my $domains_file = $Config->{'APP.domains'} || "";
my $urls_file = $Config->{'APP.urls'} || "";
my $ssls_file = $Config->{'APP.ssls'} || "";
my $hosts_file = $Config->{'APP.hosts'} || "";
my $protos_file = $Config->{'APP.protocols'} || "";
my $ssls_ips_file = $Config->{'APP.ssls_ips'} || "";
my $domains_ssl = $Config->{'APP.domains_ssl'} || "false";
$domains_ssl = lc($domains_ssl);
my $only_original_ssl_ip = $Config->{'APP.only_original_ssl_ip'} || "false";
$only_original_ssl_ip = lc($only_original_ssl_ip);
my $make_sp_chars = $Config->{'APP.make_sp_chars'} || "false";
$make_sp_chars = lc($make_sp_chars);
my $ips_to_hosts = lc($Config->{'APP.ips_to_hosts'} || "false");
my $nets_to_hosts = lc($Config->{'APP.nets_to_hosts'} || "false");

my $dbh = DBI->connect("DBI:mysql:database=".$db_name.";host=".$db_host,$db_user,$db_pass,{mysql_enable_utf8 => 1}) or die DBI->errstr;
$dbh->do("set names utf8");


my $domains=0;
my $only_ip=0;
my $urls=0;
my $https=0;
my $total_entry=0;
my %already_out;


my $domains_file_hash_old=get_md5_sum($domains_file);
my $urls_file_hash_old=get_md5_sum($urls_file);
my $ssl_host_file_hash_old=get_md5_sum($ssls_file);
my $hosts_file_hash_old=get_md5_sum($hosts_file);

open (my $DOMAINS_FILE, ">",$domains_file) or die "Could not open DOMAINS '$domains_file' file: $!";
open (my $URLS_FILE, ">",$urls_file) or die "Could not open URLS '$urls_file' file: $!";
open (my $SSL_HOST_FILE, ">",$ssls_file) or die "Could not open SSL hosts '$ssls_file' file: $!";
open (my $SSL_IPS_FILE, ">", $ssls_ips_file) or die "Could not open SSL ips '$ssls_ips_file' file: $!";


open (my $HOSTS_FILE, ">",$hosts_file) or die "Could not open file '$hosts_file' $!";
open (my $PROTOS_FILE, ">", $protos_file) or die "Could not open file '$protos_file' $!";

my $cur_time=strftime "%F %T", localtime $^T;


my %http_add_ports;
my %https_add_ports;

my %ssl_hosts;
my %ssl_ip;
my %hosts;

my %domains;

my $sth = $dbh->prepare("SELECT * FROM zap2_domains WHERE domain like '*.%'");
$sth->execute();
while (my $ips = $sth->fetchrow_hashref())
{
	my $dm = $ips->{domain};
	$dm =~ s/\*\.//g;
	$dm =~ s/\\//g;
	my $uri = new URI("http://".$dm);
	my $domain_canonical = lc($uri->host());
	treeAddDomain(\%domains, "*.".$domain_canonical, 1);
	print $DOMAINS_FILE "*.",$domain_canonical,"\n";
	if($domains_ssl eq "true")
	{
		print $SSL_HOST_FILE "*.",$domain_canonical,"\n";
	}
}
$sth->finish();
$sth = $dbh->prepare("SELECT * FROM zap2_domains WHERE domain not like '*.%'");
$sth->execute;
while (my $ips = $sth->fetchrow_hashref())
{
	my $domain=$ips->{domain};
	$domain =~ s/\\//g;
	my $uri = new URI("http://".$domain);
	my $domain_canonical = lc($uri->host());
	next if(treeFindDomain(\%domains, $domain_canonical));
	treeAddDomain(\%domains, $domain_canonical, 0);
	$logger->debug("Canonical domain: $domain_canonical");
	print $DOMAINS_FILE $domain_canonical."\n";
	if($domains_ssl eq "true")
	{
		next if(defined $ssl_hosts{$domain_canonical});
		$ssl_hosts{$domain_canonical}=1;
		print $SSL_HOST_FILE (length($domain_canonical) > 255 ? (substr($domain_canonical,0,255)."\n"): "$domain_canonical\n");
		my @ssl_ips=get_ips_for_record_id($ips->{record_id});
		foreach my $ip (@ssl_ips)
		{
			next if(defined $ssl_ip{$ip});
			$ssl_ip{$ip}=1;
			if($ip =~ /^(\d{1,3}\.){3}\d{1,3}$/)
			{
				print $SSL_IPS_FILE "$ip","\n";
			} else {
				print $SSL_IPS_FILE "[$ip]","\n";
			}
		}
	}
}
$sth->finish();
$sth = $dbh->prepare("SELECT * FROM zap2_urls");
$sth->execute;
while (my $ips = $sth->fetchrow_hashref())
{
	my $url2=$ips->{url};
	# cut from first &#
	if((my $idx=index($url2,"&#")) != -1)
	{
		$url2 = substr($url2, 0, $idx);
	}
	# delete fragment
	$url2 =~ s/^(.*)\#(.*)$/$1/;

	my $url1=new URI($url2);
	my $scheme=$url1->scheme();
	if($scheme !~ /http/ && $scheme !~ /https/)
	{
		my @ipp=split(/\:/,$url2);
		if(scalar(@ipp) != 3)
		{
			$logger->warn("Bad scheme ($scheme) for: $url2. Skip it.");
		} else {
			my @url_ips=get_ips_for_record_id($ips->{record_id});
			foreach my $ip (@url_ips)
			{
				if($ip =~ /^(\d{1,3}\.){3}\d{1,3}$/)
				{
					print $HOSTS_FILE "$ip:",$ipp[2],"\n";
				} else {
					print $HOSTS_FILE "[$ip]:",$ipp[2],"\n";
				}
			}
		}
		next;
	}
	my $host=lc($url1->host());
	next if(($host !~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ && $scheme ne 'https') && treeFindDomain(\%domains, $host));
	my $path=$url1->path();
	my $query=$url1->query();
	my $port=$url1->port();

	my $do=0;

	if($scheme eq 'https')
	{
		if($host =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ && !defined $hosts{"$host:$port"})
		{
			#print "Host name is an ip address, add to ip:port file\n";
			print $HOSTS_FILE "$host:", $port ,"\n";
			$hosts{"$host:$port"} = 1;
		}
		next if(defined $ssl_hosts{$host});
		$ssl_hosts{$host}=1;
		print $SSL_HOST_FILE (length($host) > 255 ? (substr($host, 0, 255)."\n"): "$host\n");
		if($port ne "443")
		{
			$logger->info("Adding $port to https protocol");
			$https_add_ports{$port}=1;
		}
		my @ssl_ips=get_ips_for_record_id($ips->{record_id});
		foreach my $ip (@ssl_ips)
		{
			next if(defined $ssl_ip{$ip});
			$ssl_ip{$ip}=1;
			if($ip =~ /^(\d{1,3}\.){3}\d{1,3}$/)
			{
				print $SSL_IPS_FILE "$ip","\n";
			} else {
				print $SSL_IPS_FILE "[$ip]","\n";
			}
		}
		next;
	}
	if($port ne "80")
	{
		$logger->info("Adding $port to http protocol");
		$http_add_ports{$port}=1;
	}

	$url1->host($host);
	my $as_str = $url1->as_string();
	$path =~ s/\/+/\//g;
	$path =~ s/http\:\//http\:\/\//g;
	$url1->path($path);

	my $url11 = $url1->canonical();

	$url11 =~ s/^http\:\/\///;
	$url2 =~ s/^http\:\/\///;
	$as_str =~ s/^http\:\/\///;

	$url2 .= "/" if($url2 !~ /\//);

	$url11 =~ s/\?$//g;

	$url11 =~ s/\/\.$//;

	insert_to_url($url11);
	if($url2 ne $url11)
	{
		insert_to_url($url2);
	}
	if($as_str ne $url2 || $as_str ne $url11)
	{
		my $last_char_1 = substr($url11, -1);
		my $last_char_2 = substr($as_str, -1);
		if($last_char_1 eq $last_char_2)
		{
			insert_to_url($as_str);
		}
	}
	make_special_chars($url11, $url1->as_iri(), 0) if($make_sp_chars eq "true");
}
$sth->finish();

my $n=0;
foreach my $port (keys %http_add_ports)
{
	print $PROTOS_FILE ($n == 0 ? "" : ","),"tcp:$port";
	$n++;
}
if($n)
{
	print $PROTOS_FILE "\@HTTP\n";
}

$n=0;
foreach my $port (keys %https_add_ports)
{
	print $PROTOS_FILE ($n == 0 ? "" : ","),"tcp:$port";
	$n++;
}
if($n)
{
	print $PROTOS_FILE "\@SSL\n";
}

ips_to_hosts() if($ips_to_hosts eq "true");
nets_to_hosts() if($nets_to_hosts eq "true");

close $DOMAINS_FILE;
close $URLS_FILE;
close $SSL_HOST_FILE;
close $HOSTS_FILE;
close $PROTOS_FILE;
close $SSL_IPS_FILE;

$dbh->disconnect();

my $domains_file_hash=get_md5_sum($domains_file);
my $urls_file_hash=get_md5_sum($urls_file);
my $ssl_host_file_hash=get_md5_sum($ssls_file);
my $hosts_file_hash=get_md5_sum($hosts_file);

if($domains_file_hash ne $domains_file_hash_old || $urls_file_hash ne $urls_file_hash_old || $ssl_host_file_hash ne $ssl_host_file_hash_old || $hosts_file_hash ne $hosts_file_hash_old)
{
	system("/bin/systemctl", "reload-or-restart", "extfilter");
	if($? != 0)
	{
		$logger->error("Can't reload or restart extfilter!");
		exit 1;
	}
	$logger->info("Extfilter successfully reloaded/restarted!");
}

exit 0;

sub get_md5_sum
{
	my $file=shift;
	open(my $MFILE, $file) or return "";
	binmode($MFILE);
	my $hash=Digest::MD5->new->addfile(*$MFILE)->hexdigest;
	close($MFILE);
	return $hash;
}

sub get_ips_for_record_id
{
	my $record_id=shift;
	my @ips;
	my $sql = "SELECT ip FROM zap2_ips WHERE record_id=$record_id";
	$sql="SELECT ip FROM zap2_ips WHERE record_id=$record_id AND resolved=0" if($only_original_ssl_ip eq "true");
	my $sth = $dbh->prepare($sql);
	$sth->execute;
	while (my $ips = $sth->fetchrow_hashref())
	{
		push(@ips,get_ip($ips->{ip}));
	}
	$sth->finish();
	return @ips;
}

sub get_ip
{
	my $ip_address=shift;
	my $d_size=length($ip_address);
	my $result;
	if($d_size == 4)
	{
		$result=ip_bintoip(unpack("B*",$ip_address),4);
	} else {
		$result=ip_bintoip(unpack("B*",$ip_address),6);
	}
	return $result;
}


sub _encode_sp
{
	my $url=shift;
	$url =~ s/\%7C/\|/g;
	$url =~ s/\%5B/\[/g;
	$url =~ s/\%5D/\]/g;
	$url =~ s/\%3A/\:/g;
	$url =~ s/\%3D/\=/g;
	$url =~ s/\%2B/\+/g;
	$url =~ s/\%2C/\,/g;
	$url =~ s/\%2F/\//g;
	return $url;
}

sub _encode_space
{
	my $url=shift;
	if($url =~ /\+/)
	{
		$url =~ s/\+/\%20/g;
		insert_to_url($url);
	}
	return $url;
}

sub make_special_chars
{
	my $url=shift;
	my $url1=$url;
	my $orig_rkn=shift;
	my $orig_url=$url;
	my $need_add_dot=shift;
	$url = _encode_sp($url);
	if($url ne $orig_url)
	{
		$logger->debug("Write changed url to the file");
		insert_to_url($url);
	}
	_encode_space($url);
	if($url =~ /\%27/)
	{
		$url =~ s/\%27/\'/g;
		$logger->debug("Write changed url (%27) to the file");
		insert_to_url($url);
	}
	_encode_space($url);
	if($url =~ /\%5C/)
	{
		$url =~ s/\%5C/\//g;
		$logger->debug("Write changed url (slashes) to the file");
		$url =~ s/\/\/$/\//;
		insert_to_url($url);
	}
	_encode_space($url);
	if($orig_rkn && $orig_rkn =~ /[\x{0080}-\x{FFFF}]/)
	{
		return if($orig_rkn =~ /^http\:\/\/[а-я]/i || $orig_rkn =~ /^http\:\/\/www\.[а-я]/i);
		$orig_rkn =~ s/^http\:\/\///;
		$orig_rkn =~ s/\//\.\// if($need_add_dot);
		$orig_rkn =~ s/^(.*)\#(.*)$/$1/g;
		$orig_rkn .= "/" if($orig_rkn !~ /\//);
		$orig_rkn =~ s/\/+/\//g;
		$orig_rkn =~ s/\?$//g;
		my $str = encode("utf8", $orig_rkn);
		Encode::from_to($str, 'utf-8','windows-1251');
		if($str ne $orig_rkn)
		{
			$logger->debug("Write url in cp1251 to the file");
			print $URLS_FILE (length($str) > 600 ? (substr($str,0,600)): "$str")."\n";
		}
		if($url ne $orig_rkn)
		{
			$logger->debug("Write changed url to the file");
			insert_to_url($orig_rkn);
		}
	}
}

sub insert_to_url
{
	my $url=shift;
	my $encoded=encode("utf8", $url);
	my $sum = md5($encoded);
	return if(defined $already_out{$sum});
	$already_out{$sum}=1;
	if(length($encoded) > 600)
	{
		$encoded = substr($encoded, 0, 600);
		if(substr($encoded, length($encoded) - 1, 1) eq "%")
		{
			$encoded = substr($encoded, 0, length($encoded) -1);
		} elsif (substr($encoded, length($encoded) - 2, 1) eq "%")
		{
			$encoded = substr($encoded, 0, length($encoded) - 2);
		}
	}
	print $URLS_FILE $encoded."\n";
}

# Код от ixi
sub treeAddDomain
{
	my ($tree, $domain, $masked) = @_;
	$domain .= "d" if(substr($domain, length($domain)-1, 1) eq '.');
	my @d = split /\./, $domain;
	my $cur = $tree;
	my $prev;
	while (defined(my $part = pop @d))
	{
		$prev = $cur;
		$cur = $prev->{$part};
		if ($part eq '*') { # Заблокировано по маске
			last;
		} elsif (!$cur) {
			$cur = $prev->{$part} = {};
		}
	}

	if ($masked)
	{
		my $first = $domain;
		$first =~ s/(\.).+$//;
		$prev->{$first || $domain} = '*';
	} else {
		$cur->{'.'} = 1
	}

}

sub treeFindDomain
{
	my ($tree, $domain) = @_;
	my $r = $tree;
	$domain .= "d" if(substr($domain, length($domain)-1, 1) eq '.');
	my @d = split /\./, $domain;
	while (defined(my $part = pop @d))
	{
		$r = $r->{$part};
		return 0 unless $r;
		return 1 if ($r && exists $r->{'*'});
	}
	return $r->{'.'} || 0;
}

sub ips_to_hosts
{
	my $ip_cidr = new Net::CIDR::Lite;
	my $ip6_cidr = new Net::CIDR::Lite;
	my $sth = $dbh->prepare("SELECT ip FROM zap2_only_ips");
	$sth->execute;
	while (my $ips = $sth->fetchrow_hashref())
	{
		my $ip = get_ip($ips->{ip});
		if($ip =~ /^(\d{1,3}\.){3}\d{1,3}$/)
		{
			$ip_cidr->add_any($ip);
		} else {
			$ip6_cidr->add_any($ip);
		}
	}
	$sth->finish();
	foreach my $ip (@{$ip_cidr->list()})
	{
		print $HOSTS_FILE "$ip", ", 6/0xfe", "\n";
	}
	foreach my $ip6 (@{$ip6_cidr->list()})
	{
		print $HOSTS_FILE "[$ip6]", ", 6/0xfe", "\n";
	}
	
}

sub nets_to_hosts
{
	my $sth = $dbh->prepare("SELECT subnet FROM zap2_subnets");
	$sth->execute;
	while (my $ips = $sth->fetchrow_hashref())
	{
		print $HOSTS_FILE "$ips->{subnet}", ", 6/0xfe", "\n";
	}
	$sth->finish();
}
