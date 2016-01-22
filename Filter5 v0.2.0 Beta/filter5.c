// Filter5 version 0.1.0 Beta -- G Colburn 2016

/* Filter5 is written by G Colburn 2016 -- You may use this source only when giving credit as follows:
** You must give appropriate credit, provide a link to the source, and indicate if changes were made. You may
** do so in any reasonable manner, but not in any way that suggests the creator endorses you or your use. you
** may not distribute this source without contacting the creator (I just wanna know where its going if
** it goes anywhere :] thank you!)
**
** Donations welcome via bitcoin: 1K6hdkYQthme7o1eTp9bjKhY1jQikrS7VQ
** (Just helps me find chips and caffine while coding!)
*/

/* Filter5 is a simple method of pulling and examining Apache's error and access logs and cross referencing
** the logs with ssh logs. I hope to also include other log filtering into this algorithm. The intended use
** is to find attempts to compromise a system in multiple methods. While a single attempt or two at ssh or
** a web server access point may indicate a potential threat, a system attempting access through mutliple
** services tends to show initiative of a malicious attempt. This program was written to deal more with
** that circumstance.
*/

#include <stdio.h>
#include <string.h>
#include <time.h>

// -- File Pointers
FILE *fr;
FILE *loggs;
FILE *ban;

int matchMax = 3;
int killitwithFire = 1; // 0 false, 1 true
//char action[200] = "IPSET -A BLACKLIST ";

int banfind = 0;
int unixtime;

// -- Swap pointers/chars for searching through logs
char line[256];
char line2[256];
char *s;

// -- File paths for log files and names for temp files and ban file
char *temperror = "tmper.log";
char *tempaccess = "tmpac.log";
char *tempauth = "tmpau.log";
char *banlog = "banlist.log";
char *apacheAccess = "/var/log/apache2/access.log";
char *apacheError = "/var/log/apache2/error.log";
char *sshAuth = "/var/log/auth.log";

// -- Search Keys, these are used to trip a bad request in auth.log, error.log and access.log
char *errorKey = ":error]"; // -- Consider using core:error]
char *accessKey1 = " 400 ";
char *accessKey2 = " 401 ";
char *accessKey3 = " 403 ";
char *accessKey4 = " 404 ";
char *authKey = " Failed password ";


// -- Search error.log for errors
void errorlog() {
	loggs = fopen(temperror, "w");
	fr = fopen(apacheError, "r");
	while (fgets(line, 256, fr) != NULL) {
		if (strcasestr(line, errorKey)) {
			s = strstr(line, "client"); // locates IP
			s = strstr(s, " ");
			s = strtok(s, " ");
		        s = strtok(s, ":");
		        fprintf(loggs, "%s\n", s);
		}
	}
	fclose(fr);
	fclose(loggs);
  }

// -- Search access.log for 4XX's
void accesslog() {
	loggs = fopen(tempaccess, "w");
	fr = fopen(apacheAccess, "r");
        while (fgets(line, 256, fr) != NULL) {
        	if (strstr(line, accessKey1) || strstr(line, accessKey2) || strstr(line, accessKey3) || strstr(line, accessKey4)) {
                	s = strtok(line, "-");
                        fprintf(loggs, "%s\n", s);
                }
        }
        fclose(fr);
        fclose(loggs);
  }

// -- Seach auth.log for failed logins
void authlog() {
	loggs = fopen(tempauth, "w");
	fr = fopen(sshAuth, "r");
        while (fgets(line, 256, fr) != NULL) {
        	if (strcasestr(line, authKey)) {
        		s = strstr(line, "from");
        		s = strstr(s, " ");
        		s = strtok(s, " ");
        		fprintf(loggs, "%s\n", s);
        	}
        }
        fclose(fr);
        fclose(loggs);
  }

// -- Tests a file for a matching IP from filename filename (used inside creatban())
// -- Appends ban list with count total of any ip cross-matched
void test(char line3[50], char *filename) {
	loggs = fopen(filename, "r");
	ban = fopen(banlog, "a+");
	int len = strlen(line3);
	line3[len - 2] = '\0';
	while (fgets(line2, 256, loggs) != NULL) {
		int len2 = strlen(line2);
		line2[len - 2] = '\0';
		if (strstr(line2, line3)) {
			banfind++;
		}
	}
	if (banfind > 0) {
		printf("Match: %s\t%d times\n", line3, banfind);
		fprintf(ban, "%s\t%d\n", line3, banfind);
		if (killitwithFire == 1 && banfind >= matchMax) {
			printf("Processing Ban for %s per config!\n", line3);
			char processed[256] = "ipset -A BLACKLIST ";
			strcat(processed, line3);
			sleep(1);
			system(processed); printf(".\n");
		}
	}
	fclose(loggs);
	fclose(ban);
	banfind = 0;
  }


// Rolls through the IPs pulled in auth.log and error.log and compared to 4XXs ips from access.log
void creatban() {
	int counter = 0;
	fr = fopen(tempauth, "r");
	while(fgets(line, 256, fr) != NULL) {
		test(line, tempaccess);
		counter++;
	}
	fclose(fr);

	fr = fopen(temperror, "r");
	while (fgets(line, 256, fr) != NULL) {
		test(line, tempaccess);
		counter++;
	}
	fclose(fr);
  }


// -- Runs the above mentioned things to find the cross referenced IPs
// -- Not always but most likely a match is an attempt to compromise
// -- the system or find a weakened state of entry.
int main() {
	errorlog();
	accesslog();
	authlog();

	ban = fopen(banlog, "a+");
	fprintf(ban, "\n[Filter Started @ %d]\n", (int)time(NULL));
	fclose(ban);
	creatban();

	// -- Since the temp files are just that, I clean them out after each run!
	printf("\n\nSweeping the floor of debris......");
	system("rm tmpau.log tmpac.log tmper.log");
	printf("  done");
	return 0;
}
