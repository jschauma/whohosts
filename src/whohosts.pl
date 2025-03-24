#! /usr/local/bin/perl -Tw
#
# This tool attempts to determine who hosts a given
# domain.  It does this by looking up DNS records
# relating to the domain, querying WHOIS, or making HTTP
# requests to the given domain name.
#
# Copyright (c) 2025, Jan Schaumann
# <jschauma@netmeister.org> All rights reserved.
# 
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
# 
# 1. Redistributions of source code must retain the
# above copyright notice, this list of conditions and
# the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the
# above copyright notice, this list of conditions and
# the following disclaimer in the documentation and/or
# other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use 5.008;

use strict;
use File::Basename;
use Getopt::Long;
Getopt::Long::Configure("bundling");

use Net::DNS;
use LWP::UserAgent;

$ENV{'PATH'} = "/usr/bin:/usr/sbin:/bin:/sbin";
delete($ENV{'ENV'});
delete($ENV{'CDPATH'});

###
### Constants
###

use constant TRUE => 1;
use constant FALSE => 0;

use constant EXIT_FAILURE => 1;
use constant EXIT_SUCCESS => 0;

###
### Globals
###

# Based on
# https://raw.githubusercontent.com/cisagov/findcdn/refs/heads/develop/src/findcdn/cdnEngine/detectCDN/cdn_config.py
#
# These patterns are matched case-insensitively with an implicit "(^|\.)<pattern>$".
my %DNS_PATTERNS = (
	"(ax4z|myra(cloud|security))\.com"	=> "Myra",
	"(azureedge|msecnd|trafficmanager)\.net"=> "Microsoft Azure",
	"(b-cdn|bunnyinfra)\.net"		=> "BunnyCDN",
	"(dnse2|qq)\.com"			=> "Tencent",
	"(google|youtube)\.com"			=> "Google",
	".*-msedge\.net"			=> "Microsoft Azure",
	"1e100\.net"				=> "Google",
	"aads(1|-cng?)\.net"			=> "Aryaka",
	"aaplimg\.com"				=> "Apple",
	"afxcdn\.net"				=> "afxcdn\.net",
	"airee\.international"			=> "Airee",
	"aiv-cdn.net"				=> "Amazon AWS",
	"aka(m|dns|mai(zed|edge|hd)?)\.net"	=> "Akamai",
	"akamai(tech(nologies)?)?\.(com|fr|net)"=> "Akamai",
	"amazonaws\.com"			=> "Amazon AWS",
	"anankecdn\.com\.br"			=> "Ananke",
	"att-dsa\.net"				=> "AT&T",
	"azion(cdn)?\.(com|net)"		=> "Azion",
	"azure-dns\.(com|org|info|net)"		=> "Microsoft Azure",
	"belugacdn\.com"			=> "BelugaCDN",
	"bisongrid\.net"			=> "BisonGrid",
	"bitgravity\.com"			=> "BitGravity",
	"bluehatnetwork\.com"			=> "BlueHatNetwork",
	"bo\.lt"				=> "BO\.LT",
	"c3c(dn|ache)\.net"			=> "ChinaCache",
	"cachefly\.net"				=> "Cachefly",
	"cap-mii\.net"				=> "MirrorImage",
	"caspowa\.com"				=> "Caspowa",
	"ccgslb\.(com|net)"			=> "ChinaCache",
	"cdn77\.(net|org)"			=> "DataCamp",
	"cdn\.bitgravity\.com"			=> "Tata communications",
	"cdn\.geeksforgeeks\.org"		=> "GeeksForGeeksCDN",
	"cdn\.gocache\.net"			=> "GoCache",
	"cdn\.sfr\.net"				=> "SFR",
	"cdn\.telefonica\.com"			=> "Telefonica",
	"cdncloud\.net\.au"			=> "MediaCloud",
	"cdngc\.net"				=> "CDNetworks",
	"cdnify\.io"				=> "CDNify",
	"cdninstagram\.com"			=> "Facebook",
	"cdnsun\.net"				=> "CDNsun",
	"cdntel\.net"				=> "Telenor",
	"chinacache\.net"			=> "ChinaCache",
	"clever-cloud\.com"			=> "Clever-cloud",
	"clients\.turbobytes\.net"		=> "Turbo Bytes",
	"cloudflare\.(com|net)"			=> "Cloudflare",
	"cloudfront\.net"			=> "Amazon AWS",
	"cloudscdn\.net"			=> "Cloudflare",
	"cotcdn\.net"				=> "CotendoCDN",
	"cubecdn\.net"				=> "cubeCDN",
	"discordapp\.com"			=> "Discord",
	"edge(suite|key)\.net"			=> "Akamai",
	"facebook\.(com|net)"			=> "Facebook",
	"fastly(lb)?\.net"			=> "Fastly",
	"fbcdn\.net"				=> "Facebook",
	"footprint\.net"			=> "Level3",
	"fpbns\.net"				=> "Level3",
	"garenanow\.com"			=> "Garena Online",
	"gccdn\.(cdn|net)"			=> "CDNetworks",
	"gfx\.ms"				=> "Limelight",
	"google"				=> "Google",
	"google(usercontent|hosted|syndication)\.com" => "Google",
	"gslb\.tbcache\.com"			=> "Alimama",
	"gvt2\.com"				=> "Google",
	"hiberniacdn\.com"			=> "HiberniaCDN",
	"hosting4cdn\.com"			=> "Hosting4CDN",
	"huaweicloud-dns\.(net|org|)"		=> "Huawei Cloud",
	"hwcdn\.net"				=> "Highwinds",
	"incapdns\.net"				=> "Imperva",
	"ins(cname|nw)\.net"			=> "InstartLogic",
	"instacontent\.net"			=> "MirrorImage",
	"internapcdn\.net"			=> "Internap",
	"jsdelivr\.net"				=> "jsDelivr",
	"kinxcdn\.(com|net)"			=> "KINXCDN",
	"ksyun(cdn)?\.com"			=> "Kingsoft Cloud CDN",
	"kxcdn\.com"				=> "KeyCDN",
	"lambdacdn\.net"			=> "LambdaCDN",
	"linodeusercontent\.com"		=> "Akamai (Linode)",
	"ll(dns|nwd)\.net"			=> "Limelight",
	"lswcdn\.(net|eu)"			=> "LeaseWebCDN",
	"lxdns\.com"				=> "ChinaNetCenter",
	"mirror-image\.net"			=> "MirrorImage",
	"mncdn\.(com|net|org)"			=> "Medianova",
	"mwcloudcdn\.com"			=> "QUANTIL/ChinaNetCenter",
	"myracloud\.com"			=> "Myra",
	"netdna(-(cdn|ssl))?\.com"		=> "StackPath",
	"netlify(globalcdn)?\.com"		=> "Netlify",
	"ngenix\.net"				=> "NGENIX",
	"nocookie\.net"				=> "Fastly",
	"nyiftw\.(com|net)"			=> "NYIFTW",
	"optimalcdn\.com"			=> "OptimalCDN",
	"ourwebpic\.com"			=> "ChinaNetCenter",
	"pagerain\.net"				=> "PageRain",
	"panthercdn\.com"			=> "CDNetworks",
	"r\.world(cdn|ssl)\.net"		=> "OnApp",
	"raxcdn\.com"				=> "Rackspace",
	"resrc\.it"				=> "ReSRC.it",
	"rev[cd]n\.net"				=> "RevSoftware",
	"rlcdn\.com"				=> "Reapleaf",
	"rncdn1\.com"				=> "ReflectedNetworks",
	"simplecdn\.net"			=> "SimpleCDN",
	"speedcdns\.com"			=> "QUANTIL/ChinaNetCenter",
	"squixa\.net"				=> "section.io",
	"srip\.net"				=> "Akamai",
	"stackpathdns\.com"			=> "StackPath",
	"swift(cdn1|serve)\.com"		=> "SwiftServe",
	"taobao(cdn)?\.com"			=> "Taobao",
	"tbcdn\.cn"				=> "Taobao",
	"tl88\.net"				=> "AkamaiChinaCDN",
	"turbobytes-cdn\.com"			=> "Turbo Bytes",
	"twimg\.com"				=> "Twitter",
	"unicorncdn\.net"			=> "UnicornCDN",
	"voxcdn\.net"				=> "VoxCDN",
	"wp\.com"				=> "WordPress",
	"wsc(dns|loudcdn)\.com"			=> "ChinaNetCenter",
	"x\.incapdns\.net"			=> "Incapsula",
	"y(ahoo|img)\.com"			=> "Yahoo",
	"yahooapis\.com"			=> "Yahoo",
	"yandex\.(net|cloud|ru)"		=> "Yandex Cloud",
	"yottaa\.net"				=> "Yottaa",
	"your-server\.de"			=> "Hetzner",
	"ytimg\.com"				=> "Google",
	"zenedge\.net"				=> "Zenedge",
	"z(scaler(two|three)?|(dx|s)cloud)\.net"=> "Zscaler",
);

# This pattern is matched un-anchored, case-insensitively.
my %WHOIS_PATTERNS = (
	'ADVANCEDHOSTERS-AS'		=> "Advanced Hosting / DataWeb",
	'AKAMAI-LINODE'			=> "Akamai (Linode)",
	'AKAMAI-AS'			=> "Akamai",
	'APPLE-'			=> "Apple",
	'AS-APPNEX'			=> "AppNexus",
	'AS-VULTR,'			=> "Vultr",
	'CACHENETWORKS'			=> "CacheFly",
	'CLOUDFLARE(NET|SPECTRUM)'	=> "Cloudflare",
	'China Mobile'			=> 'China Mobile',
	'China Telecom'			=> 'China Telecom',
	'China Unicom'			=> 'China Unicom',
	'DIGITALOCEAN'			=> "DigitalOcean",
	'FLOKINET'			=> "FlokiNET",
	'GOOGLE,'			=> "Google",
	'GOOGLE-CLOUD-PLATFORM'		=> "Google (GCP)",
	'HETZNER-'			=> "Hetzner",
	'HLL-AS'			=> "High Load Lab (Qrator)",
	'HWCLOUDS-'			=> "Huawei Cloud",
	'INCAPSULA'			=> "Imperva",
	'IONOS-AS'			=> "Ionos",
	'JCOLO,'			=> "Sunbreak Electronics",
	'Kingsoft Cloud '		=> "Kingsoft Cloud",
	'MICROSOFT-AZURE-'		=> "Microsoft Azure",
	'MICROSOFT-CORP-'		=> "Microsoft",
	'ORACLE-BMC-'			=> "Oracle Cloud Infrastructure",
	'OVH'				=> "OVHcloud",
	'SCZN-AS'			=> "T-Systems (DTAG)",
	'SECURITYSERVICES,'		=> "Vercara",
	'SERVERCENTRAL'			=> "Deft",
	'SERVERSTACK'			=> "DigitalOcean",
	'(INTERNAP|SINGLEHOP)'		=> "INAP/HorizonIQ",
	'SNC, US'			=> "ServiceNow",
	'SNIC,'				=> "Sonic",
	'SOPRADO'			=> "Myra",
	'SQUARESPACE'			=> "Squarespace",
	'STARK-INDUSTRIES'		=> "PQ Hosting",
	'THEROCKETSCIENCEGROUP'		=> "MailChimp",
	'VELIANET-'			=> "velia.net",
	'VK(ONTAKTE)?-'			=> "VK",
	'WIX_COM'			=> "Wix",
	'WOODYNET-'			=> "PCH",
	'WORKDAY-'			=> "Workday",
	'YANDEXCLOUD'			=> "Yandex Cloud",
	'ZEN-ECN'			=> "Zenlayer",
	'^ACE-'				=> "Tencent",
	'^AS-ITGLOBALCOM-'		=> "ITGLOBAL",
	'^AVANTEL-'			=> "Avantel Ltd.",
	'^ATW-AS'			=> "ATW Internet",
	'^Alibaba-'			=> "Alibaba",
	'^AMAZON-AES'			=> "Amazon",
	'^BAIDU '			=> "Baidu",
	'^BIZNET-'			=> "Biznet",
	'^CENTURYLINK-'			=> 'Level3',
	'^CHINATELECOM-'		=> 'China Telecom',
	'^DNIC-'			=> "DoD NIC",
	'(^GODADDY[-,]|-GO-DADDY-COM)'	=> "GoDaddy",
	'^HKBN(-|ES)'			=> "HKBN Ltd.",
	'^LEASEWEB-'			=> "Leaseweb",
	'^RACKSPACE[-,]'		=> "Rackspace",
	'^TENCENT-'			=> "Tencent",
	'^VODAFONE'			=> "Vodafone",
);

my %KNOWN_AS = (
		"13335"  => "Cloudflare",
		"13360"	 => "Triton Digital",
		"14061"  => "DigitalOcean",
		"16276"  => "OVHcloud",
		"16509"  => "Amazon AWS",
		"16625"  => "Akamai",
		"19551"  => "Imperva",
		"20473"  => "Vultr",
		"20940"  => "Akamai",
		"24429"  => "Alibaba",
		"24941"  => "Hetzner",
		"29066"  => "velia.net",
		"30081"  => "CacheFly",
		"31898"  => "Oracle Cloud Infrastructure",
		"37153"	 => "xneelo",
		"41075"  => "ATW Internet",
		"44477"  => "PQ Hosting",
		"50340"  => "Selectel",
		"53831"  => "Squarespace",
		"54113"  => "Fastly",
		"54994"  => "Meteverse",
		"60068"  => "CDN77",
		"8075"	 => "Microsoft",
		"133165" => "DigitOcean",
		"135340" => "DigitOcean",
		"200350" => "Yandex Cloud",
		"200651" => "FlokiNET",
		"212317" => "Hetzner",
		"213230" => "Hetzner",
		"215859" => "Hetzner",
		"393406" => "DigitOcean",
		"394362" => "DigitOcean",
		"395502" => "Sunbreak Electronics",
);

# These are matched case-insensitively with an implicit "^".
my %HTTP_PATTERNS = (
	"(X-)?Akamai-"			=> "Akamai",
	"(x-roblox-|roblox-machine-id)"	=> "Roblox",
	"Set-Cookie: ak_bmsc-"		=> "Akamai",
	"cf-(cache|ray)"		=> "Cloudflare",
	"server: BunnyCDNE"		=> "Bunny CDN",
	"server: Squarespace"		=> "Squarespace",
	"server: cloudflare"		=> "Cloudflare",
	"server: gws"			=> "Google",
	"via: 1.1.*cloudfront.net"	=> "Amazon AWS",
	"x-(azure|ms-(client|msedge))-"	=> "Microsoft Azure",
	"x-amz-"			=> "Amazon AWS",
	"x-aws-region"			=> "Amazon AWS",
	"x-netflix"			=> "Netflix",
	"xappgw-trace-id"		=> "Microsoft Azure",
);

my @INVALID_IPBLOCKS = (
	"^(127|0|10|255)\\\.",
	"^169\\\.254\\\.",
	"^172.(1[6-9]|2[0-9]|3[01])\\\.",
	"^192\\\.0\\\.0\\\.",
	"^192\\\.168\\\.",
	"^2(4[0-9]|5[0-5])\\\.",
	"^::1",
);

###
### You shouldn't have to change anything below this line.
###

my @IPS;
my %IP_CACHE;

my $WHOIS = "whois -h whois.cymru.com";

my $RESOLVER = Net::DNS::Resolver->new();

my %OPTS;
my $PROGNAME = basename($0);
my $RETVAL = 0;
my @VALID_CHECKS = ( "dns", "whois", "http" );
my $VERSION = 0.1;

###
### Subroutines
###

sub checkDns($) {
	my ($domain) = @_;
	if (grep(/dns/, @{$OPTS{'skip'}})) {
		verbose("Skipping DNS check for $domain.", 2);
		return;
	}
	verbose("Checking DNS of $domain...", 2);

	if (checkCnameChain($domain)) {
		return TRUE;
	}

	@IPS = getIPs($domain);
	# Ok, this is fugly.  We ran a 'matchDNS' within getIPs on the
	# domain name (iff it didn't have any A/AAAA/CNAME records);
	# if that matched, we returned "matched" instead of a list of IPs.
	# If the name didn't match, then we looked up NS records for the
	# domain, which we can then handle in 'checkPtr' below.
	if ((scalar(@IPS) == 1) && ($IPS[0] eq "matched")) {
		return TRUE;
	}
	return checkPtr($domain);
}

sub checkHandler($$) {
	my ($opt, $val) = @_;

	foreach my $v (split(",", $val)) {
		if (!grep(/^$v$/i, @VALID_CHECKS)) {
			error("Invalid check. Use one of \"" . join("\", \"", @VALID_CHECKS) . "\".", EXIT_FAILURE);
		}
		push(@{$OPTS{$opt}}, $v);
	}
}

sub checkHTTP($;$) {
	my ($domain, $ip) = @_;
	if (grep(/http/, @{$OPTS{'skip'}})) {
		verbose("Skipping HTTP check for $domain.", 2);
		return;
	}
	if (!scalar(@IPS)) {
		verbose("Skipping HTTP check for $domain (no IPs found).", 2);
		return;
	}
	verbose("Checking HTTP headers of $domain...", 2);

	my $ua = LWP::UserAgent->new(timeout => 3);
	$ua->agent("Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1");

	my $response = $ua->get("https://$domain");

	if (!$response->is_success) {
		return "";
	}

	my $headers = $response->headers();
	my @hnames = $headers->header_field_names();

	foreach my $key (@hnames) {
		my $value = $headers->header($key);
		my $result = matchHTTP($domain, $key, $value);
		if ($result) {
			print "$domain: $result\n";
			if ($ip) {
				$IP_CACHE{$ip} = $result;
			}
			return $result;
		}
	}

	return "";
}


sub checkPtr($) {
	my ($domain) = @_;
	verbose("Checking PTR for IP addresses of $domain...", 3);

	if (!scalar(@IPS)) {
		verbose("$domain has no IPs.", 4);
		return FALSE;
	}

	foreach my $ip (@IPS) {
		my $query = $RESOLVER->search($ip, 'PTR');
		if (!$query) {
			next;
		}
		foreach my $rr ($query->answer) {
			if ($rr->type eq 'PTR') {
				verbose("$ip reverses to " . $rr->ptrdname, 4);
				if (matchDNSname($domain, $rr->ptrdname)) {
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

# Perform a whois lookup against whois.cymru.com and match the
# result against known patterns.  If a match is found, report
# and remember in our cache, but if no known pattern is found,
# try an HTTP lookup.
sub checkWhois($) {
	my ($domain) = @_;
	if (grep(/whois/, @{$OPTS{'skip'}})) {
		verbose("Skipping WHOIS check for $domain.", 2);
		return;
	}
	if (!scalar(@IPS)) {
		verbose("Skipping WHOIS check for $domain (no IPs found).", 2);
		return;
	}
	verbose("Checking WHOIS of $domain...", 2);

	foreach my $ip (@IPS) {
		verbose("Checking WHOIS of $ip...", 3);

		if ($IP_CACHE{$ip}) {
			verbose("Found $ip in cache.", 4);
			print "$domain: " . $IP_CACHE{$ip} . "\n";
			return TRUE;
		}

		my @cmd = split(/\s+/, $WHOIS);
		push(@cmd, $ip);
		verbose("Running '" . join(" ", @cmd) . "'...", 4);
		open(my $pipe, "-|", @cmd) || error("Unable to open pipe from '" .
						join(" ", @cmd) . "': $!\n", EXIT_FAILURE);
		foreach my $line (<$pipe>) {
			if ($line =~ m/^([0-9]+)\s*\|.*\| (.*)/) {
				my $as = $1;
				my $asname = $2;
				my $result = matchAS($domain, $as);
				if (!$result) {
					$result = matchWhois($domain, $asname);
				}
				if (!$result) {
					if (checkHTTP($domain, $ip)) {
						return TRUE;
					}
					$result = $asname;
				}
				print "$domain: $result\n";
				$IP_CACHE{$ip} = $result;
				return TRUE;
			}
		}
		close($pipe);
	}

	return FALSE;
}

sub error($;$) {
	my ($msg, $err) = @_;

	$RETVAL++;

	print STDERR "$msg\n";
	if ($err) {
		exit($err);
		# NOTREACHED
	}
}

sub checkCnameChain($) {
	my ($domain) = @_;
	verbose("Getting CNAME chain for $domain...", 3);

	my @chain;
	my $name = $domain;

outer:
	while(1) {
		my $query = $RESOLVER->search($name);
		if (!$query) {
			last;
		}

		foreach my $rr ($query->answer) {
			if ($rr->type eq 'CNAME') {
				push(@chain, $rr->name);
				$name = $rr->cname;
				last;
			} elsif ($rr->type eq 'A' || $rr->type eq 'AAAA') {
				push(@chain, $rr->name);
				last outer;
			} else {
				last outer;
			}
		}
	}
	if (!scalar(@chain)) {
		verbose("No CNAME chain / DNS result.", 2);
		return FALSE;
	}

	verbose(join(" -> ", @chain), 2);
	foreach my $c (reverse(@chain)) {
		if (matchDNSname($domain, $c)) {
			return TRUE;
		}
	}
	return FALSE;
}

sub getIPs($;$);

sub getIPs($;$) {
	my ($domain, $dontRecurse) = @_;
	verbose("Getting IP addresses for $domain...", 3);

	my @ips;

	if ($domain =~ m/:|(^\d+\.\d+\.\d+\.\d+$)/) {
		push(@ips, $domain);
		return @ips;
	}

	foreach my $type ('A', 'AAAA') {
		my $query = $RESOLVER->search($domain, $type);
		if (!$query) {
			next;
		}
answer:
		foreach my $rr ($query->answer) {
			next unless $rr->type eq $type;

			my $ip = $rr->address;
			foreach my $r (@INVALID_IPBLOCKS) {
				if ($ip =~ m/$r/) {
					verbose("Ignoring invalid IP address '$ip' ($r).", 4);
					next answer;
				}
			}
			push(@ips, $ip);
		}
	}

	if (!scalar(@ips)) {
		if ($dontRecurse) {
			verbose("Not recursing into NS records.", 4);
			return @ips;
		}
		verbose("No IPs found, trying to simply match $domain...", 4);
		if (matchDNSname($domain, $domain)) {
			return "matched";
		}
		verbose("Trying NS records for $domain...", 4);
		my $query = $RESOLVER->search($domain, 'NS');
		if (!$query) {
			return @ips;
		}
		foreach my $rr ($query->answer) {
	            next unless $rr->type eq 'NS';
		    return getIPs($rr->nsdname, TRUE);
		}
	}
	return @ips;
}

sub init() {
	my ($ok);

	my (@only, @skip);

	$ok = GetOptions(
			 "help|h" 	=> \$OPTS{'help'},
			 "skip|s=s" 	=> \&checkHandler,
			 "verbose|v+" 	=> sub { $OPTS{'verbose'}++; },
			 "version|V"	=> sub {
			 			print "$PROGNAME: $VERSION\n";
						exit(EXIT_SUCCESS);
			 		}
			 );

	if ($OPTS{'help'} || !$ok) {
		usage($ok);
		exit(!$ok);
		# NOTREACHED
	}
}

sub matchAS($$) {
	my ($domain, $as) = @_;
	verbose("Checking if AS$as is known...", 4);

	return $KNOWN_AS{$as};
}

sub matchDNSname($$) {
	my ($domain, $name) = @_;
	verbose("Checking if $name matches a known pattern...", 4);

	foreach my $regex (keys(%DNS_PATTERNS)) {
		if ($name =~ m/(^|\.)$regex$/i) {
			print "$domain: " . $DNS_PATTERNS{$regex} . "\n";
			return TRUE;
		}
	}
	return FALSE;
}

sub matchHTTP($$$) {
	my ($domain, $key, $value) = @_;
	verbose("Checking if HTTP header '$key' matches a known pattern...", 4);

	foreach my $regex (keys(%HTTP_PATTERNS)) {
		my ($kr, $vr) = split(/: /, $regex);
		if ($key =~ m/^$kr/i) {
			if (!$vr || $value =~ m/$vr/i) {
				return $HTTP_PATTERNS{$regex};
			}
		}
	}

	return "";
}


sub matchWhois($$) {
	my ($domain, $info) = @_;
	verbose("Checking if '$info' matches a known pattern...", 4);

	foreach my $regex (keys(%WHOIS_PATTERNS)) {
		if ($info =~ m/$regex/i) {
			return $WHOIS_PATTERNS{$regex};
		}
	}
	return;
}

sub usage($) {
	my ($err) = @_;
	my $FH = $err ? \*STDERR : \*STDOUT;
	my $checks = join("\", \"", sort(@VALID_CHECKS));

	print $FH <<EOH
Usage: $PROGNAME [-Vhv] [-s check] [domain [...]]
        -V        print version number and exit
	-h        print this help and exit
	-s check  skip this check (must be one of "$checks")
	-v        increase verbosity
EOH
	;
}

sub whohosts($) {
	my ($domain) = @_;
	verbose("Checking $domain...");
	if (checkDns($domain)) {
		return;
	}

	if (grep(/dns/, @{$OPTS{'skip'}})) {
		@IPS = getIPs($domain);
	}
	if (checkWhois($domain)) {
		return;
	}
	if (checkHTTP($domain)) {
		return;
	}
	print "$domain: unknown\n";
}

sub verbose($;$) {
	my ($msg, $level) = @_;
	my $char = "=";

	return unless $OPTS{'verbose'};

	$char .= "=" x ($level ? ($level - 1) : 0 );

	if (!$level || ($level <= $OPTS{'verbose'})) {
		print STDERR "$char> $msg\n";
	}
}


###
### Main
###

init();

foreach my $domain (scalar(@ARGV) ? @ARGV : <STDIN>) {
	chomp($domain);
	whohosts($domain);
}

exit($RETVAL);
