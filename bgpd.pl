
# variables $remote and $remote_as available for all functions

sub initmap
# Called when shared memory segment created or before bgpup if used old segment
{
	initclass("0.0.0.0/0", 1);	# Means all is Ukraine when bgp down
}

sub bgpup
# Called when first update received
{
	initclass("0.0.0.0/0", 0);	# switch default to world
	initclass("10.0.0.0/8", 1);
	initclass("127.0.0.0/8", 1);
}

sub setclass
{
# available variables:
# $community, $aspath, $prefix
	if ($community =~ /^(.* )?15497:(10|16545|3254)|16545:16545( .*)?$/)
	{	return 1;
	}
	return 0;
}

sub update
{
# available variables:
# $community, $aspath, $prefix
}

sub update_done
{
# called when all updates from packet processed
}

sub keepalive
{
# available variable:
# $sent - true if it's outbound keepalive, false if inbound
}

sub filter
{
# available variables:
# $community, $aspath, $prefix, $nexthop
# $community and $aspath undefined for withdrawed announces
# Return 0 to deny update, 1 to accept

# You cannot reject withdraw, it just inhibit warning "withdraw unexisting announce"
# if original announce was rejected.
# This function does not call on withdraw if soft-reconfiguration enabled.

	return 0 if $prefix =~ /^(10|127)\./;
	return 1;	# accept
}

