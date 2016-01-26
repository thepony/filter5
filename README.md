# filter5
Scans through Apache and SSH logs with the intention of identifying potential full out attempts at compromising a webserver/system
I came up with this after a few frustrating hours of bouncing between logs trying to match up IPs seeing who was screwing
with what on a honeypot server I use to analyze and learn with. Old but new, I put down I.T. and Coding years back and just
getting a chance to get back into it again... and feel just as clueless as before :-)


Filter5 	User Manual Version 0.3.2 


You may use this source only when giving credit as follows:
  You must give appropriate credit, provide a link to the source, and indicate if changes 
were made. You may do so in any reasonable manner, but not in any way that suggests the 
creator endorses you or your use. you may not distribute this source without contacting 
the creator (I just wanna know where its going if it goes anywhere :] thank you!)


NAME
	Filter5 - Log compiler and filtration

SYNOPSIS
	Filter5 -option (only accepts one option flag per run)

DESCRIPTION
	Filter5 - The intention of Filter5 is to eliminate some of the attempts to compromise 
	servers. This is intended to assit in locating multi-dimensional attacks on a system 
	using logs from several services and matching any attempts. Attempts are placed into 
	a Banlog file at current but will soon create additional tactics to handle the attacks.
	Filters SSH, and APACHE2 logs for potential threats by failed login, 40X requests, and 
	other excessive resource requests by compiling and searching the Auth.log, error.log, and 
	access.log files. Designed on ubuntu system but should work with any compatible system.

	Latest source should be available on github @ https://github.com/thepony/filter5

OPTIONS


	-b	Displays any duplicate cross matched IPs, does not add ban or execute a system 
		request to activate firewall settings.

	-l	Disables logging of all matched IPs in banlist.log

	-n	Displays total find numbers in each log file scanned

	-v	Display version and exit (Does no processing!)

	-L	Creates temp files from matches and exits without cleaning up 
		(In any other mode the temp files are created but removed before program 
		exits). Does not process any further info or bans. This is essentially
		a dirty exit after gathering data.

FILES
	Reads from /var/log/apache2/error.log, /var/log/apache2/access.log, and /var/log/auth.log files and 
	creates three temp files with matched finds. The three temp files (tmper.log, tmpac.log, and tmpau.log)
	are cleaned up in the local director Filter5 is running in before exit. These files are not removed
	when using the -L flag.
BUGS
	Please report bugs to thepony on github https://github.com/thepony/filter5

AUTHOR
	Greg Colburn
	
Support my coding by bitcoin if you like this
(my consumption of caffine and chips while coding sucks)

1K6hdkYQthme7o1eTp9bjKhY1jQikrS7VQ
