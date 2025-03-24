whohosts - try to determine who hosts a given domain
====================================================

The `whohosts(1)` tool attempts to determine who hosts
a given domain.	It does this by looking up DNS records
relating to the domain and matching them against a
list of known patterns, querying WHOIS for the AS
information, or making HTTP requests to the given
domain name and matching the returned headers.

Requirements
============

`whohosts(1)` is written in Perl, and you will need
the following modules installed:

* Net::DNS
* LWP::UserAgent

Installation
============

To install the command and manual page somewhere
convenient, run `make install`; the Makefile defaults
to '/usr/local' but you can change the PREFIX:

```
$ make PREFIX=~ install
```

Accuracy
========

`whohosts(1)` should give you a reasonable guess as to
who hosts the given domain.  However, there are many
reasons why a guess might be wrong or not succeed at
all.

For example, a domain may be multi-homed, where
different IPs are hosted by different service
providers.  `whohosts(1)` will only pick one IP
address and make its guess based on that.

A domain may be hosted by different services in
different regions, so that if you run `whohosts(1)`
from one location you might get a different result
from running it in another.

A domain may be hosted on IP space that is mapped via
WHOIS to one party, but the service may still be
hosted by another (for example, `www.yahoo.com` (as of
2025-03-12) is hosted on AWS on IP space owned by
Yahoo via AWS's
[BYOIP](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-byoip.html)).

When attempting to connect to a domain using HTTPS,
`whohosts(1)` may be caught in bot defenses and not be
served a response it can analyze.

If a domain does not resolve to any IP addresses, then
`whohosts(1)` will attempt to use the IP address of
one of the domain's NS records, but of course a
domain's NS records and where its HTTP is hosted may
be completely different.


Documentation
=============

Please see the manual page for all details:

```
NAME
     whohosts - try to determine who hosts a given domain

SYNOPSIS
     whohosts [-Vhv] [-s check] [domain [...]]

DESCRIPTION
     The whohosts tool attempts to determine who hosts a given domain.	It does
     this by looking up DNS records relating to the domain, querying WHOIS, or
     making HTTP requests to the given domain name.

     If whohosts cannot make a reasonable guess based on that information, then
     it will print the AS name matched to the domain, either by its IP address,
     or by the IP address of one of its NS records.

OPTIONS
     The following options are supported by whohosts:

     -V		Print version number and exit.

     -h		Display help and exit.

     -s check	Skip the given check(s).  Multiple checks can be given as a
		comma-separated list or a repeated options.  check must be one
		of "DNS", "WHOIS", or "HTTP".

     -v		Be verbose.  Can be specified multiple times.

DETAILS
     If no domain names are given on the command-line, then whohosts will read
     names from stdin.

     In order to try to guess which organization is hosting a given domain,
     whohosts performs the following checks:

     DNS     Perform a forward DNS lookup of the given domain name.  If a CNAME
	     chain is found, each canonical name is matched against a list of
	     known patterns.  Otherwise, any A or AAAA records are used for a
	     reverse (i.e., PTR) lookup, and the resulting name, if any, is
	     matched against those patterns.

	     If no CNAME nor A / AAAA records are found, then whohosts will look
	     up the NS record for the domain and resolve that name to an IP
	     address.

     WHOIS   Perform a WHOIS lookup against the IP address(es) of the given
	     domain name using Team Cymru's whois(1) interface.	 Any
	     organization names are matched against a list of known patterns or
	     reported verbatim if not matched.

     HTTP    Perform an HTTP "GET" request to the domain and attempt to match
	     the HTTP headers returned by the server against a list of known
	     patterns.

     These checks are performed in order, unless the -s flags are given.  The
     first successful match will terminate the lookup unless the -a flag is
     given.

     Note: whohosts will only perform checks and matches against one result.
     This can have the side-effect that the user sees different results for the
     same domain when run repeatedly, for example if the domain is multi-homed.

EXAMPLES
     To report who is hosting the given domains:

	   $ whohosts www.microsoft.com www.office.com www.netflix.com
	   www.microsoft.com: Akamai
	   www.office.com: Microsoft Azure
	   www.netflix.com: Netflix

     To very verbosely check a larger set of domains:

	   $ head -1000 input | whohosts -v -v -v -v
	   => Checking www.apple.com...
	   ==> Checking DNS of www.apple.com...
	   ===> Getting CNAME chain for www.apple.com...
	   ==> www.apple.com -> www-apple-com.v.aaplimg.com -> www.apple.com.edgekey.net -> e6858.dsce9.akamaiedge.net
	   ====> Checking if e6858.dsce9.akamaiedge.net matches a known pattern...
	   www.apple.com: Akamai
	   [...]

SEE ALSO
     host(1), whois(1)

HISTORY
     whohosts was originally written by Jan Schaumann <jschauma@netmeister.org>
     in February 2025.

BUGS
     Please file bugs and feature requests by emailing the author or via GitHub
     issues or pull requests.
```
