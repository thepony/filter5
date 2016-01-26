// Filter5 Beta -- G Colburn 2016

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

char *version = "Version 0.3.2";

int matchMax = 3;
int banfindTest = 0;

int iFind = 0; //-- general counter
int killitwithFire = 1; // 0 false, 1 true -- set the ban action
int gimmieNumbers = 0; // Print total finds from logs
int banlogON = 1; // option to turn off logging
char processed[256] = "ipset -quiet -A BLACKLIST ";

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
		        if (gimmieNumbers == 1) ++iFind;
		}
	}
	fclose(fr);
	fclose(loggs);
	if (gimmieNumbers == 1) {
		printf("Error Log Total: %d\n", iFind);
		iFind = 0;
	}
  }

// -- Search access.log for 4XX's
void accesslog() {
	loggs = fopen(tempaccess, "w");
	fr = fopen(apacheAccess, "r");
        while (fgets(line, 256, fr) != NULL) {
        	if (strstr(line, accessKey1) || strstr(line, accessKey2) || strstr(line, accessKey3) || strstr(line, accessKey4)) {
                	s = strtok(line, "-");
                        fprintf(loggs, "%s\n", s);
                        if (gimmieNumbers == 1) ++iFind;
                }
        }
        fclose(fr);
        fclose(loggs);
        if (gimmieNumbers == 1) {
        	printf("Access Log Total: %d\n", iFind);
        	iFind = 0;
        }
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
        		if (gimmieNumbers == 1) ++iFind;
        	}
        }
        fclose(fr);
        fclose(loggs);
        if (gimmieNumbers == 1) {
        	printf("Auth Log Total: %d\n\n", iFind);
        	iFind = 0;
        }
  }

// -- Tests a file for a matching IP from filename filename (used inside creatban())
// -- Appends ban list with count total of any ip cross-matched
void test(char line3[50], char *filename) {
	loggs = fopen(filename, "r");
	if (banlogON == 1) ban = fopen(banlog, "a+");
	int len = strlen(line3);
	line3[len - 2] = '\0';
	while (fgets(line2, 256, loggs) != NULL) {
		int len2 = strlen(line2);
		line2[len - 2] = '\0';
		if (strstr(line2, line3)) {
			banfind++;
		}
	}
	if (banfind > banfindTest) {
		printf("\nMatch: %s\t%d times", line3, banfind);
		if (killitwithFire == 0 || banfind < matchMax) { fprintf(ban, "%s\t%d\n", line3, banfind); }

		if (killitwithFire == 1 && banfind >= matchMax) {
			if (banlogON == 1) fprintf(ban, "%s\t%d <<--->> BAN BY CONFIG!\n", line3, banfind);
			printf(" <<--->> Processing Ban for %s per config!", line3);
			strcat(processed, line3);
			system(processed);
		}
	}
	fclose(loggs);
	if (banlogON == 1) fclose(ban);
	banfind = 0;
  }

void dupeTest() {
	int savekillitFire = killitwithFire;
	killitwithFire = 0; // disable the banning before running this!!
	banfindTest = 2; // Tighten the filter matches in test()
	char *cdupe;
	char *checkfile;
	int i;
	printf("Single log duplicate check...");
	for (i = 0; i < 3; i++) {
		if (i == 0) checkfile = tempauth;
		if (i == 1) checkfile = tempaccess;
		if (i == 2) checkfile = temperror;
		printf("\nChecking %s...", checkfile);
		fr = fopen(checkfile, "r");
		while(fgets(line, 256, fr) != NULL) {
			test(line, checkfile);
		}
		fclose(fr);
	}
	killitwithFire = savekillitFire; // restore killitwithfire before leaving scope
	banfindTest = 0; // put the filter limits back to 0 for test()
}



// Rolls through the IPs pulled in auth.log and error.log and compared to 4XXs ips from access.log
void creatban() {
	int counter = 0;
	printf("\n\nCross log duplicate checks...");
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


void openLog(char *arg1) {
	ban = fopen(banlog, "a+");
	fprintf(ban, "\n[Filter5 Start Flag: %s  at  UT: %d ]\n", arg1, (int)time(NULL));
	fclose(ban);
  }

void removeTmp() {
	printf("\n\nSweeping the floor of debris......");
	system("rm tmpau.log tmpac.log tmper.log");
	printf("  done");
  }

// -- Runs the above mentioned things to find the cross referenced IPs
// -- Not always but most likely a match is an attempt to compromise
// -- the system or find a weakened state of entry.
int main(int argc, char* argv[]) {
	openLog(argv[1]);
	if (argv[1] == NULL) { // -- No args first otherwise crashes!!
		errorlog();
		accesslog();
		authlog();
		//dupeTest();
		creatban();
		removeTmp();
		return 0;
	}

	//-- ARG Value Section --//
	//-- ARG Value Section --//
	if (strstr(argv[1], "-L")) { //-- create tmp logs and exit dirty
		printf("Starting with -L (create tmp logs and exit dirty!) flag!\n");
		errorlog();
		accesslog();
		authlog();
		return 0;
	}
	else if (strstr(argv[1], "-v")) { //-- Version and Exit
		printf("Filter5 %s", version);
		return 0;
	}
	else if (strstr(argv[1], "-l")) { //-- Do not log finds in the banlist.log
		printf("Starting with -l (disabled banlist.log logging!!!) flag!\n");
		banlogON = 0;
	}
	else if (strstr(argv[1], "-b")) { //-- No Ban (just find matches, build banlist.log and exit)
		printf("Starting with -b (no ban) flag!\n");
		killitwithFire = 0;
	}
	else if (strstr(argv[1], "-n")) {
		printf("Starting with -n (Gimmie the numbers!) flag!\n");
		gimmieNumbers = 1;
	}
	errorlog();
	accesslog();
	authlog();
	if (strstr(argv[1], "-d")) dupeTest();
	creatban();
	removeTmp();
	return 0;

}