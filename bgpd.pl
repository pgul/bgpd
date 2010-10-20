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
# Return 0 to deny update, 1 to accept
{
	return 0 if $prefix =~ /(10|127)\./;
	return 1;
}

