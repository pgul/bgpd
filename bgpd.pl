
sub setclass
{
	if ($community =~ /^(.* )?15497:(10|16545|3254)|16545:16545( .*)$/)
	{	return 1;
	}
	return 0;
}
