/*
  chpasswd.c

  Changes local user password

  Developed by
  Pedro L Orso - orso@onda.com.br
  Changed by
  Thiago Melo de Paula - thiago@fafibe.br
  Paul Lesneiwski - pdontthink@angrynerds.com

  Released under GNU GPL - see http://www.gnu.org/copyleft/gpl.html

  How to compile:
    gcc -lcrypt -O -o chpasswd chpasswd.c; chmod 4750 chpasswd; chown root:apache chpasswd
    gcc -Wall -lcrypt -O -o chpasswd chpasswd.c; chmod 4750 chpasswd; chown root:apache chpasswd

*/

#define TMPFILE "/tmp/chpasswdXXXXXX"

#define PASSWD "/etc/passwd"
#define SHADOW "/etc/shadow"

#define STR_MAX 100
#define MAXLEN 1024
#define hhex(x) (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))

#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <crypt.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
//#include <errno.h>
#include <sys/stat.h>


void eperror(register char *);
void getword(char *, char *, char);
void to64(register char *, register long, register int);
void putline(FILE *,char *);
void *xmalloc(size_t);
static void fixpwd(unsigned char *);
static int htoi(unsigned char *s);

int main(int argc, char *argv[]){
	int ok, fdes, test = 0;
	char User[STR_MAX];
	char buf[MAXLEN];
	char PUser[50];
	char New_pw[50];
	char Old_pw[50];
	char WOld_pw[50];
	char Wrest[MAXLEN];
	char pwdfile[255] = PASSWD;
	//char command[255];
	char WUser[50];
	char *cpw, salt[9];
	char *tn, *cypher;
	FILE *fpw, *tmp;

	tn = NULL;

	if((setuid(0)) < 0) eperror("setuid");
	// unecessary:  if((setgid(3)) < 0) eperror("setgid");

	//sprintf(User,"%s",argv[1]);
        snprintf(User, sizeof(User)-1, "%s", argv[1]);
        User[sizeof(User)-1] = '\0';

	//sprintf(Old_pw,"%s",argv[2]);
        snprintf(Old_pw, sizeof(Old_pw)-1, "%s", argv[2]);
        Old_pw[sizeof(Old_pw)-1] = '\0';

	//sprintf(New_pw,"%s",argv[3]);
        snprintf(New_pw, sizeof(New_pw)-1, "%s", argv[3]);
        New_pw[sizeof(New_pw)-1] = '\0';

	if(!strcmp("(null)",User)){
		printf("Missing username\n");
		return 12;
	}

	if(!strcmp("(null)",New_pw)){
		printf("Missing new password\n");
		return 2;
	}

	if(!strcmp("(null)",Old_pw)){
		printf("Missing current password\n");
		return 3;
	}

	if(!strcmp(User,"root")){
		printf("The password for this user cannot be changed due to security constraints: %s\n",User);
		return 4; //the root user cannot be edited for security reasons
	}

	fixpwd(New_pw);
	fixpwd(Old_pw);
	fixpwd(User);

	if(!strcmp(Old_pw,New_pw)){
		printf("The new password is equal to the current password. Choose another password.\n");
		return 5;
	}

	if (access(SHADOW, R_OK) == 0){
		sprintf(pwdfile, SHADOW);
		test = 1;
	}

	//strcpy(PUser,User);
	strncpy(PUser, User, sizeof(PUser)-1);
        PUser[sizeof(PUser)-1] = '\0';

	//strcat(PUser,":");
	strncat(PUser, ":", sizeof(PUser)-1);
        PUser[sizeof(PUser)-1] = '\0';

	if((fpw=fopen(pwdfile,"r"))==NULL){
		printf("Could not read password file: %s\n",pwdfile);
		if(!test)
			return 6; // means we are not using shadow pwd file
		return 7; // means we are using shadow pwd file
	}

	tn = (char *)xmalloc(strlen(TMPFILE) + 1);
	strcpy(tn, TMPFILE);
/* 
   mode_t oldUmask; 
   oldUmask = umask(0177);
   ...mkstemp()...
   umask (oldUmask); 
*/
	umask(0177);
	if ((tmp = fdopen((fdes = mkstemp(tn)), "w+")) == NULL) {
		printf("Temporary file could not be opened: %s\n", tn);
		return 8;
	}

	ok = 0;
	while(fgets(buf,MAXLEN,fpw)!=NULL){
		if(!ok){
			if(strncmp(buf,PUser,strlen(PUser)) == 0){
				getword(WUser,buf,':');
				getword(WOld_pw,buf,':');
				strcpy(Wrest,buf);

				if(strcmp(WOld_pw, (char *)crypt(Old_pw, WOld_pw)) != 0){
					if(fpw)
						fclose(fpw);
					if(tmp){
						fclose(tmp);
						close(fdes);
						unlink(tn);
					}
					printf("Current password is incorrect\n");
					return 9;
				}

				(void)srand((int)time((time_t *)NULL));
				//cpw = (char *)crypt(New_pw,salt);
				cypher = (char *)xmalloc(12); //MD5
				strcpy(cypher, "$1$"); //MD5
				strcat(cypher, salt); //MD5
				cpw = (char *)crypt(New_pw, cypher); //MD5
				sprintf(buf,"%s:%s:%s\n",User,cpw,Wrest);
				buf[strlen(buf)-1]='\0';
				ok++;
			}
		} 
		putline(tmp,buf);
	}

	fclose(fpw);
//	fclose(tmp);

	if(ok) {
		//por nm@g only, en reemplazo del system cp, más rápido y menos recursos
		rewind(tmp);
		if((fpw=fopen(pwdfile,"w"))==NULL){
			printf("Could not read password file: %s\n",pwdfile);
			if(!test)
				return 6; // means we are not using shadow pwd file
			return 7; // means we are using shadow pwd file
		}
		while( fgets(buf, MAXLEN, tmp) != NULL ) {
			putline(fpw,buf);
		}
		fclose(fpw);
		fclose(tmp);
		close(fdes);
		unlink(tn);
		printf("The password was modified successfully\n");
		return 0;
	} else {
		printf("User does not exist: %s\n", User);
		fclose(tmp);
		close(fdes);
		unlink(tn);
		return 10;
	}

}

void eperror(s)
register char *s;
{
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	Changed by
	Thiago Melo de Paula - thiago@fafibe.br
	*/
   char str[50];

   snprintf(str, sizeof(str)-1, "chpasswd - %s", s);
   str[sizeof(str)-1] = '\0';
   perror(str);
   exit(1);
}

void getword(char *word, char *line, char stop) 
{
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	*/
   int x = 0,y;

   for(x=0;((line[x]) && (line[x] != stop));x++)
      word[x] = line[x];

   word[x] = '\0';
   if(line[x]) ++x;
   y=0;

   while((line[y++] = line[x++]));
}

static void
fixpwd(str)
   unsigned char   *str;
{
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	*/	 
   unsigned char   *dest = str;

   while (str[0]) {
      if (str[0] == '+')
         dest[0] = ' ';
      else if (str[0] == '%' && hhex(str[1]) && hhex(str[2])) {
         dest[0] = (unsigned char) htoi(str + 1);
         str += 2;
      } else dest[0] = str[0];

      str++;
      dest++;
   }

   dest[0] = '\0';
   return;
}

static int
htoi(s)
   unsigned char   *s;
{
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	*/
   int     value;
   char    c;

   c = s[0];
   if (isupper(c))
      c = tolower(c);
   value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

   c = s[1];
   if (isupper(c))
      c = tolower(c);
   value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

   return (value);
}

static unsigned char itoa64[] =         /* 0 ... 63 => ascii - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	*/

void to64(s, v, n)
   register char *s;
   register long v;
   register int n;
{
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	Improved (md5) by nmag only <nmag@softhome.net>
	*/
   while (--n >= 0) {
      *s++ = itoa64[v&0x3f];
      v >>= 3;
      v = ~v;
   }
}

void putline(FILE *f,char *l) {
	/*
	Developed by
	Pedro L Orso - orso@onda.com.br
	*/
   int x;

   for(x=0;l[x];x++) fputc(l[x],f);
   return;
}

// Developed by nmag only <nmag@softhome.net>
void *xmalloc (size_t size) {
	register void *value = malloc(size);
	if ( value == 0 ) {
		printf("Virtual memory exhausted\n");
		exit(11);
//		exit(EXIT_FAILURE);
	}
	return value;
}
