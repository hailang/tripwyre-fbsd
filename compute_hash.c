#include <unistd.h>
#include <stdio.h>
#include <termios.h>

struct termios tty;

#include "controller_options.h"

enum states {FAIL = 0, SUCCESS = 1};

int get_passphrase(char *, char *);

int get_passphrase(char *try1, char *try2)
{
  
  tty.c_lflag &= ~ECHO;
  (void)tcsetattr(0, TCSADRAIN|TCSASOFT, &tty);

  fprintf(stderr,"Enter the passphrase: ");
  if(fgets(try1,PASS_CHAR,stdin) == NULL)
    exit(0);

  fprintf(stderr,"\nEnter the passphrase (again): ");
  if(fgets(try2,PASS_CHAR,stdin) == NULL)
    exit(0);

  if(strncmp(try1, try2, PASS_CHAR) != 0) {
    fprintf(stderr, "don't match, try again\n");
    return FAIL;
  }
  
  else
    return SUCCESS;

}

int main(int argc, char *argv[])
{
  
  tcgetattr(0, &tty);
  char *try1, *try2;
  try1 = malloc( PASS_CHAR * sizeof(char));
  try2 = malloc( PASS_CHAR * sizeof(char));
  char *hash;
  int c = 0;

  while((c = get_passphrase(try1, try2)) == FAIL)
    ;

  hash = crypt(try1, SALT);
  fprintf(stdout,"\n#ifdef HASH\n#undef HASH\n#define HASH \"%s\"\n#else\n#define HASH \"%s\"\n#endif\n", hash,hash);
}
