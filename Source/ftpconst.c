/*
 * ftpconst.c
 *
 *  Created  : May 15, 2020
 *  Modified : May 15, 2020
 *  Author   : lightftp
 */

const char shortmonths[12][4] = {
		"Jan\0", "Feb\0", "Mar\0", "Apr\0", "May\0", "Jun\0",
		"Jul\0", "Aug\0", "Sep\0", "Oct\0", "Nov\0", "Dec\0"};

const char success211[] =
		"211-Extensions supported:\r\n PASV\r\n UTF8\r\n TVFS\r\n REST STREAM\r\n "
		"SIZE\r\n MLSD\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n EPSV\r\n"
		"211 End.\r\n";

const char success214[] =
		"214-The following commands are recognized.\r\n"
		" ABOR APPE AUTH CDUP CWD  DELE EPSV FEAT HELP LIST MKD MLSD NOOP OPTS\r\n"
		" PASS PASV PBSZ PORT PROT PWD  QUIT REST RETR RMD RNFR RNTO SITE SIZE\r\n"
		" STOR SYST TYPE USER NLST\r\n"
		"214 Help OK.\r\n";
