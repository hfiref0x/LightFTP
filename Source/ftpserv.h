/*
* ftpserv.h
*
*  Created on: Aug 20, 2016
*
*  Modified on: Jun 28, 2018
*
*      Author: lightftp
*/

#ifndef FTPSERV_H_
#define FTPSERV_H_

#define __USE_GNU
#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>

typedef struct _FTP_CONFIG {
	char			*ConfigFile;
	unsigned int	MaxUsers;
	in_port_t		Port;
	in_port_t		PasvPortBase;
	in_port_t		PasvPortMax;
	in_addr_t		BindToInterface;
	in_addr_t		ExternalInterface;
	in_addr_t		LocalIPMask;
} FTP_CONFIG, *PFTP_CONFIG;

#define	CONFIG_FILE_NAME		"fftp.conf"
#define	CONFIG_SECTION_NAME		"ftpconfig"
#define	DEFAULT_FTP_PORT		21

#define INVALID_SOCKET -1
#define SOCKET	int

#define MODE_NORMAL			0
#define MODE_PASSIVE		1

/*
 * NOT_LOGGED_IN = "banned" in config. Not logged in or banned.
 * READONLY = "readonly" in config. Browse and download.
 * CREATENEW = "upload" in config. Creating new directories, store new files. Append, rename and delete disabled.
 * FULL = "admin" in config. All access features enabled.
 */

#define FTP_ACCESS_NOT_LOGGED_IN	0
#define FTP_ACCESS_READONLY			1
#define FTP_ACCESS_CREATENEW		2
#define FTP_ACCESS_FULL				3

#define TRANSMIT_BUFFER_SIZE	65536

static const unsigned long int	FTP_PATH_MAX = PATH_MAX;

#define	SIZE_OF_GPBUFFER		4*FTP_PATH_MAX

typedef struct	_FTPCONTEXT {
	pthread_mutex_t		MTLock;
	SOCKET				ControlSocket;
	SOCKET				DataSocket;
	pthread_t			WorkerThreadId;
	/*
	 * WorkerThreadValid is output of pthread_create
	 * therefore zero is VALID indicator and -1 is invalid.
	 */
	int					WorkerThreadValid;
	int					WorkerThreadAbort;
	in_addr_t			ServerIPv4;
	in_addr_t			ClientIPv4;
	in_addr_t			DataIPv4;
	in_port_t			DataPort;
	int					File;
	int					Mode;
	int					Access;
	int					CreateMode;
	int					SessionID;
	int					DataProtectionLevel;
	off_t				RestPoint;
	unsigned long int	BlockSize;
	char				CurrentDir[PATH_MAX];
	char				RootDir[PATH_MAX];
	char				*GPBuffer;
	gnutls_session_t	TLS_session;
} FTPCONTEXT, *PFTPCONTEXT;

typedef int (*FTPROUTINE) (PFTPCONTEXT context, const char *params);
typedef void *(__thread_start_routine)(void *), *__ptr_thread_start_routine;

extern FTP_CONFIG	g_cfg;
extern int			g_log;
extern void *ftpmain(void *p);

extern gnutls_certificate_credentials_t		x509_cred;
extern gnutls_priority_t					priority_cache;

#define	MAX_CMDS 32

int ftpUSER	(PFTPCONTEXT context, const char *params);
int ftpQUIT	(PFTPCONTEXT context, const char *params);
int ftpNOOP	(PFTPCONTEXT context, const char *params);
int ftpPWD	(PFTPCONTEXT context, const char *params);
int ftpTYPE	(PFTPCONTEXT context, const char *params);
int ftpPORT	(PFTPCONTEXT context, const char *params);
int ftpLIST	(PFTPCONTEXT context, const char *params);
int ftpAPPE	(PFTPCONTEXT context, const char *params);
int ftpCDUP	(PFTPCONTEXT context, const char *params);
int ftpCWD	(PFTPCONTEXT context, const char *params);
int ftpRETR	(PFTPCONTEXT context, const char *params);
int ftpABOR	(PFTPCONTEXT context, const char *params);
int ftpDELE	(PFTPCONTEXT context, const char *params);
int ftpPASV	(PFTPCONTEXT context, const char *params);
int ftpPASS	(PFTPCONTEXT context, const char *params);
int ftpREST	(PFTPCONTEXT context, const char *params);
int ftpSIZE	(PFTPCONTEXT context, const char *params);
int ftpMKD	(PFTPCONTEXT context, const char *params);
int ftpRMD	(PFTPCONTEXT context, const char *params);
int ftpSTOR	(PFTPCONTEXT context, const char *params);
int ftpSYST	(PFTPCONTEXT context, const char *params);
int ftpFEAT	(PFTPCONTEXT context, const char *params);
int ftpRNFR	(PFTPCONTEXT context, const char *params);
int ftpRNTO	(PFTPCONTEXT context, const char *params);
int ftpOPTS	(PFTPCONTEXT context, const char *params);
int ftpMLSD	(PFTPCONTEXT context, const char *params);
int ftpAUTH (PFTPCONTEXT context, const char *params);
int ftpPBSZ (PFTPCONTEXT context, const char *params);
int ftpPROT (PFTPCONTEXT context, const char *params);
int ftpEPSV (PFTPCONTEXT context, const char *params);
int ftpHELP (PFTPCONTEXT context, const char *params);
int ftpSITE (PFTPCONTEXT context, const char *params);

static const char success200[]		= "200 Command okay.\r\n";
static const char success200_1[]	= "200 Type set to A.\r\n";
static const char success200_2[]	= "200 Type set to I.\r\n";
static const char success211[]		=
		"211-Extensions supported:\r\n PASV\r\n UTF8\r\n TVFS\r\n REST STREAM\r\n "
		"SIZE\r\n MLSD\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n EPSV\r\n"
		"211 End.\r\n";

static const char success214[]		=
		"214-The following commands are recognized.\r\n"
		" ABOR APPE AUTH CDUP CWD  DELE EPSV FEAT HELP LIST MKD MLSD NOOP OPTS\r\n"
		" PASS PASV PBSZ PORT PROT PWD  QUIT REST RETR RMD RNFR RNTO SITE SIZE\r\n"
		" STOR SYST TYPE USER\r\n"
		"214 Help OK.\r\n";

static const char success215[]		= "215 UNIX Type: L8\r\n";
static const char success220[]		= "220 LightFTP server v2.0a ready\r\n";
static const char success221[]		= "221 Goodbye!\r\n";
static const char success226[]		= "226 Transfer complete. Closing data connection.\r\n";
static const char success227[]		= "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u).\r\n";
static const char success229[]		= "229 Entering Extended Passive Mode (|||%u|)\r\n";
static const char success230[]		= "230 User logged in, proceed.\r\n";
static const char success234[]		= "234 AUTH command OK. Initializing TLS connection.\r\n";
static const char success250[]		= "250 Requested file action okay, completed.\r\n";
static const char success257[]		= "257 Directory created.\r\n";
static const char error425[]		= "425 Can not open data connection.\r\n";
static const char error426[]		= "426 Connection closed; transfer aborted.\r\n";
static const char error451[]		= "451 Requested action aborted. Local error in processing.\r\n";
static const char error500[]		= "500 Syntax error, command unrecognized.\r\n";
static const char error500_auth[]	= "500 AUTH unsuccessful.\r\n";
static const char error501[]		= "501 Syntax error in parameters or arguments.\r\n";
static const char error503[]		= "503 Invalid sequence of commands (AUTH TLS required prior to authentication).\r\n";
static const char error504[]		= "504 Command not implemented for that parameter.\r\n";
static const char error530[]		= "530 Please login with USER and PASS.\r\n";
static const char error530_b[]		= "530 This account is disabled.\r\n";
static const char error530_r[]		= "530 Invalid user name or password.\r\n";
static const char error550[]		= "550 File or directory unavailable.\r\n";
static const char error550_r[]		= "550 Permission denied.\r\n";
static const char error550_a[]		= "550 Data channel was closed by ABOR command from client.\r\n";
static const char error550_t[]		= "550 Another action is in progress, use ABOR command first.\r\n";
static const char error550_m[]		= "550 Insufficient resources.\r\n";
static const char interm125[]		= "125 Data connection already open; Transfer starting.\r\n";
static const char interm150[]		= "150 File status okay; about to open data connection.\r\n";
static const char interm350[]		= "350 REST supported. Ready to resume at byte offset ";
static const char interm350_ren[]	= "350 File exists. Ready to rename.\r\n";
static const char interm331[]		= "331 User ";
static const char interm331_tail[]  = " OK. Password required\r\n";
static const char NOSLOTS[]			= "MAXIMUM ALLOWED USERS CONNECTED\r\n";

static const char shortmonths[12][4] = {
		"Jan\0", "Feb\0", "Mar\0", "Apr\0", "May\0", "Jun\0",
		"Jul\0", "Aug\0", "Sep\0", "Oct\0", "Nov\0", "Dec\0"};

#endif /* FTPSERV_H_ */
