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

my $n_masked_domains = 0;
my %masked_domains;
my %domains;
my $sth = $dbh->prepare("SELECT * FROM zap2_domains WHERE domain like '*.%'");
$sth->execute();
while (my $ips = $sth->fetchrow_hashref())
{
	my $dm = $ips->{domain};
	$dm =~ s/\*\.//g;
	my $domain_canonical=new URI("http://".$dm)->canonical();
	$domain_canonical =~ s/^http\:\/\///;
	$domain_canonical =~ s/\/$//;
	$domain_canonical =~ s/\.$//;
	$masked_domains{$domain_canonical} = 1;
	$n_masked_domains++;
	print $DOMAINS_FILE "*.",$domain_canonical,"\n";
	if($domains_ssl eq "true")
	{
		print $SSL_HOST_FILE "*.",$domain_canonical,"\n";
	}
}
$sth->finish();

$sth = $dbh->prepare("SELECT * FROM zap2_domains");
$sth->execute;
while (my $ips = $sth->fetchrow_hashref())
{
	my $domain=$ips->{domain};
	my $domain_canonical=new URI("http://".$domain)->canonical();
	$domain_canonical =~ s/^http\:\/\///;
	$domain_canonical =~ s/\/$//;
	$domain_canonical =~ s/\.$//;
	my $skip = 0;
	foreach my $dm (keys %masked_domains)
	{
		if($domain_canonical =~ /\.$dm$/ || $domain_canonical =~ /^$dm$/)
		{
#			print "found mask $dm for domain $domain\n";
			$skip++;
			last;
		}
	}
	next if($skip);
	if(defined $domains{$domain_canonical})
	{
		$logger->warn("Domain $domain_canonical already present in the domains list");
		next;
	}
	$domains{$domain_canonical}=1;
	$logger->debug("Canonical domain: $domain_canonical");
	print $DOMAINS_FILE $domain_canonical."\n";
	if($domains_ssl eq "true")
	{
		next if(defined $ssl_hosts{$domain_canonical});
		$ssl_hosts{$domain_canonical}=1;
		print $SSL_HOST_FILE (length($domain_canonical) > 47 ? (substr($domain_canonical,0,47)."\n"): "$domain_canonical\n");
		my @ssl_ips=get_ips_for_record_id($ips->{record_id});
		foreach my $ip (@ssl_ips)
		{
			next if(defined $ssl_ip{$ip});
			$ssl_ip{$ip}=1;
			print $SSL_IPS_FILE "$ip","\n";
		}
	}
}
$sth->finish();

$sth = $dbh->prepare("SELECT * FROM zap2_urls");
$sth->execute;
while (my $ips = $sth->fetchrow_hashref())
{
	my $url2=$ips->{url};
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
	my $path=$url1->path();
	my $query=$url1->query();
	my $port=$url1->port();

	$host =~ s/\.$//;

	my $do=0;
	my $skip = 0;
	foreach my $dm (keys %masked_domains)
	{
		if($host =~ /\.\Q$dm\E$/ || $host =~ /^\Q$dm\E$/)
		{
#			print "found mask $dm for domain $host\n";
			$skip++;
			last;
		}
	}
	next if($skip);
	if($host !~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ && $scheme ne 'https' && defined $domains{$host})
	{
#		$logger->warn("Host '$host' from url '$url2' present in the domains");
		next;
	}
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
		print $SSL_HOST_FILE (length($host) > 47 ? (substr($host,0,47)."\n"): "$host\n");
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
	my $url11 = $url1->canonical();

	$url11 =~ s/^http\:\/\///;
	$url2 =~ s/^http\:\/\///;

	my $host_end=index($url2,'/',7);
	my $need_add_dot=0;
	$need_add_dot=1 if(substr($url2, $host_end-1 , 1) eq ".");

	# убираем любое упоминание о фрагменте... оно не нужно
	$url11 =~ s/^(.*)\#(.*)$/$1/g;
	$url2 =~ s/^(.*)\#(.*)$/$1/g;

	if((my $idx=index($url2,"&#")) != -1)
	{
		$url2 = substr($url2,0,$idx);
	}

	$url2 .= "/" if($url2 !~ /\//);

	$url11 =~ s/\/+/\//g;
	$url2 =~ s/\/+/\//g;

	$url11 =~ s/http\:\//http\:\/\//g;
	$url2 =~ s/http\:\//http\:\/\//g;

	$url11 =~ s/\/http\:\/\//\/http\:\//g;
	$url2 =~ s/\/http\:\/\//\/http\:\//g;

	$url11 =~ s/\?$//g;
	$url2 =~ s/\?$//g;

	$url11 =~ s/\/\.$//;
	$url2 =~ s/\/\.$//;
	$url11 =~ s/\//\.\// if($need_add_dot);
	insert_to_url($url11);
	if($url2 ne $url11)
	{
#		print "insert original url $url2\n";
		insert_to_url($url2);
	}
	make_special_chars($url11,$url1->as_iri(),$need_add_dot);
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

if($domains_file_hash ne $domains_file_hash_old || $urls_file_hash ne $urls_file_hash_old || $ssl_host_file_hash ne $ssl_host_file_hash_old)
{
	system("/bin/systemctl", "reload-or-restart","extfilter");
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
	print $URLS_FILE (length($encoded) > 600 ? (substr($encoded,0,600)): "$encoded")."\n";
}
