sub initmap
{
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
