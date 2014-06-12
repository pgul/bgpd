
use POSIX;

# Blackhole announces with these as-pathes are legitimate even without aggregated announce
sub correct_path { return [
    "13249 42655"
]; }

sub initmap
# Called after perl start (on start bgpd or reconfig)
{
	$pfxs = $need_recheck = 0;
	%pfxs = %pfxs_bh = %need_recheck = %need_recheck_bh = %aggr_pfx = %update_alarm = %aspath = %aspath_bh = ();
	%correct_path = map { $_ => 1 } @{correct_path()};
	$first_run = 1;		# Send trap about all "good" peers after start or reconfig
	Log("initmap");
}

sub bgpup
# Called when first update received
{
	$pfxs = $need_recheck = 0;
	%pfxs = %pfxs_bh = %need_recheck = %need_recheck_bh = %aggr_pfx = %update_alarm = %aspath = %aspath_bh = ();
	$time_start = time();
	zabbix_send("bgp.route.num", "unknown");
	Log("bgp up");
}

sub bgpdown
{
	zabbix_send("bgp.route.num", "unknown");
	$pfxs = $need_recheck = 0;
	%pfxs = %pfxs_bh = %need_recheck = %need_recheck_bh = %aggr_pfx = %update_alarm = %aspath = %aspath_bh = ();
	Log("bgp down");
}

sub update
# available variables:
# $community, $aspath, $prefix, $next_hop, $new
# $remote, $remote_as
# Return 0 to deny update, 1 to accept
# if $aspath == "" then it's withdraw
{
	if ($new) {
		$pfxs++;
		Log("New prefix $prefix nh=$next_hop as-path \"$aspath\" community \"$community\"");
	} else {
		Log("Update prefix $prefix nh=$next_hop as-path \"$aspath\" community \"$community\"");
	}
	if ($prefix =~ m@/32$@) {
		$pfxs_bh{$`} = $next_hop;
		$aspath_bh{$`} = $aspath;
		$need_recheck_bh{$`} = 1 unless $need_recheck;
	} else {
		if ($new) {
			$need_recheck = 1;
		} else {
			$need_recheck{$prefix} = 1;
		}
		$pfxs{$prefix} = $next_hop;
		$aspath{$prefix} = $aspath;
	}
}

sub withdraw
{
	$pfxs--;
	$pfxs = 0 if $pfxs < 0;
	Log("Withdraw prefix $prefix");
	if ($prefix =~ m@/32$@) {
		my $ip = $`;
		if ($alarmed{$ip}) {
			bh_ok($ip);
		}
		delete($pfxs_bh{$ip});
		delete($aggr_pfx{$ip});
		delete($aspath_bh{$ip});
	} else {
		delete($pfxs{$prefix});
		delete($aspath{$prefix});
		$need_recheck{$prefix} = 1;
	}
}

sub filter
{
# available variables:
# $community, $aspath, $prefix, $nexthop
# Return 0 to deny update, 1 to accept
	return 1;
}

sub keepalive
{
	#if (time() - $time_start > 5*60) {
		zabbix_send("bgp.route.num", $pfxs);
	#}
}

sub update_done
{
	keepalive();

	#if (time() - $time_start < 5*60) {
	#	return;	# Do not send traps first 5 minutes, wait for stability
	#}

	if ($need_recheck) {
		foreach (keys %pfxs_bh) {
			check_bh($_);
		}
	} else {
		foreach (keys %need_recheck_bh) {
			check_bh($_);
		}
		foreach (keys %pfxs_bh) {
			check_bh($_) if !$need_recheck_bh{$_} && $need_recheck{$aggr_pfx{$_}};
		}
	}
	# Log("Need to send updated alarm to " . join(",", keys %update_alarm));
	foreach (keys %update_alarm) {
		send_alarm($_);
	}
	$need_recheck = 0;
	%need_recheck = %need_recheck_bh = %update_alarm = ();
	$first_run = 0;
}

sub rs
{
	return ($remote eq "195.35.65.1" ? "rs1" : "rs2");
}

sub find_pfx
{
	my ($ip) = @_;

	return undef unless $ip =~ /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/;
	my $intip = ($1<<24) | ($2<<16) | ($3<<8) | $4;
	for (my $preflen = 31; $preflen >= 0; $preflen--) {
		my $intpfx = $intip & (0xffffffff << (32 - $preflen));
		my $pfx = ($intpfx >> 24) . "." . (($intpfx >> 16) & 0xff) . "." . (($intpfx >> 8) & 0xff) . "." . ($intpfx & 0xff) . "/" . $preflen;
		return $pfx if $pfxs{$pfx};
	}
	return undef;
}

sub check_bh
{
	my ($ip) = @_;

	my $pfx = find_pfx($ip);
	#Log("Check correctness of blackhole announce $ip from $pfxs_bh{$ip}, aggregated prefix $pfx from $pfxs{$pfx}");
	$aggr_pfx{$ip} = $pfx;
	if ($pfx && $pfxs{$pfx} eq $pfxs_bh{$ip}) {
		return unless $alarmed{$ip} || $first_run;
		Log("Blackhole announce $ip from $pfxs_bh{$ip} is ok now, aggregated prefix $pfx");
		bh_ok($ip);
	} else {
		if ($pfx) {
			# Does aspath for bh announce includes aspath for aggregated announce?
			my ($as_bh, $as_pfx);
			$as_bh = (split(/\s+/, $aspath_bh{$ip}))[0];
			$as_pfx = (split(/\s+/, $aspath{$pfx}))[0];
			if ($aspath_bh{$ip} eq $aspath{$pfx}) {
				return unless $alarmed{$ip} || $first_run;
				Log("Blackhole announce $ip from $pfxs_bh{$ip}, aggregated prefix $pfx from $pfxs{$pfx}, same aspath \"$aspath{$pfx}\"");
				bh_ok($ip);
			} elsif ($as_bh eq $as_pfx) {
				return unless $alarmed{$ip} || $first_run;
				Log("Blackhole announce $ip from $pfxs_bh{$ip}, aggregated prefix $pfx from $pfxs{$pfx}, same AS $as_bh");
				bh_ok($ip);
			} elsif (substr($aspath_bh{$ip}, -length($aspath{$pfx}) - 1) eq " " . $aspath{$pfx}) {
				return unless $alarmed{$ip} || $first_run;
				Log("Blackhole announce $ip from $pfxs_bh{$ip} uplink of $pfxs{$pfx}, aggregated prefix $pfx");
				bh_ok($ip);
			} elsif ($aspath_bh{$ip} =~ / $as_pfx\b/) {
				return unless $alarmed{$ip} || $first_run;
				Log("Blackhole announce $ip from $pfxs_bh{$ip} contains AS $as_pfx, aggregated prefix $pfx from $pfxs{$pfx}");
				bh_ok($ip);
			} elsif ($correct_path{$aspath_bh{$ip}}) {
				return unless $alarmed{$ip} || $first_run;
				Log("Blackhole announce $ip from $pfxs_bh{$ip} good aspath '$aspath_bh{$ip}', aggregated prefix $pfx from $pfxs{$pfx}");
				bh_ok($ip);
			} else {
				return if exists($alarmed{$ip}) && $alarmed{$ip} eq $pfxs_bh{$ip};
				Log("Bad blackhole announce $ip from $pfxs_bh{$ip} aspath '$aspath_bh{$ip}', aggregated prefix $pfx from $pfxs{$pfx}");
				bh_alarm($ip);
			}
		} else {
			return if exists($alarmed{$ip}) && $alarmed{$ip} eq $pfxs_bh{$ip};
			Log("Bad blackhole announce $ip from $pfxs_bh{$ip} aspath '$aspath_bh{$ip}', no aggregated prefix");
			bh_alarm($ip);
		}
	}
}

sub bh_ok
{
	my ($ip) = @_;

	$update_alarm{$alarmed{$ip} || $pfxs_bh{$ip}} = 1;
	delete($alarmed{$ip});
}

sub bh_alarm
{
	my ($ip) = @_;

	$update_alarm{$pfxs_bh{$ip}} = 1;
	$update_alarm{$alarmed{$ip}} = 1 if $alarmed{$ip};
	$alarmed{$ip} = $pfxs_bh{$ip};
}

sub send_alarm
{
	my ($peer) = @_;

	my (@alarm_ip) = sort grep { $alarmed{$_} eq $peer } keys %alarmed;
	#Log("Send blackhole alarm for peer $peer, announces " . join(",", @alarm_ip));
	zabbix_send("bad_blackhole[$peer]", join("", map { "\n$_ $aspath_bh{$_}" } @alarm_ip));
}

sub zabbix_send
{
	my ($key, $val) = @_;

	system("echo /usr/local/bin/zabbix_sender -c /usr/local/etc/zabbix/zabbix_agentd.conf -s " . rs() . " -k '$key' -o '$val' >/dev/null");
}

sub Log
{
	print strftime("%b %e %T ", localtime()) . rs() . " " . $_[0] . "\n";
}

1;

