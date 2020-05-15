/*
* ftpserv.h
*
*  Created on: Aug 20, 2016
*
*  Modified on: May 15, 2020
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
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>

#ifdef __CYGWIN__
#define TCP_KEEPCNT 8
#define TCP_KEEPINTVL 150
#define TCP_KEEPIDLE 14400
#endif

typedef struct _FTP_CONFIG {
	char			*ConfigFile;
	unsigned int	MaxUsers;
	unsigned int	EnableKeepalive;
	in_port_t		Port;
	in_port_t		PasvPortBase;
	in_port_t		PasvPortMax;
	in_addr_t		BindToInterface;
	in_addr_t		ExternalInterface;
	in_addr_t		LocalIPMask;
} FTP_CONFIG, *PFTP_CONFIG;

#define	CONFIG_FILE_NAME     "fftp.conf"
#define	CONFIG_SECTION_NAME  "ftpconfig"
#define	DEFAULT_FTP_PORT     21

#define INVALID_SOCKET       -1
#define SOCKET               int

#define MODE_NORMAL          0
#define MODE_PASSIVE         1

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

#define	SIZE_OF_RCVBUFFER       2*PATH_MAX
#define	SIZE_OF_GPBUFFER        4*PATH_MAX

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

extern const char shortmonths[12][4];

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

#define success200 "200 Command okay.\r\n"
#define success200_1 "200 Type set to A.\r\n"
#define success200_2 "200 Type set to I.\r\n"

extern const char success211[];
extern const char success214[];

#define success215     "215 UNIX Type: L8\r\n"
#define success220     "220 LightFTP server v2.0b ready\r\n"
#define success221     "221 Goodbye!\r\n"
#define success226     "226 Transfer complete. Closing data connection.\r\n"
#define success227     "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u).\r\n"
#define success229     "229 Entering Extended Passive Mode (|||%u|)\r\n"
#define success230     "230 User logged in, proceed.\r\n"
#define success234     "234 AUTH command OK. Initializing TLS connection.\r\n"
#define success250     "250 Requested file action okay, completed.\r\n"
#define success257     "257 Directory created.\r\n"
#define error425       "425 Can not open data connection.\r\n"
#define error426       "426 Connection closed; transfer aborted.\r\n"
#define error451       "451 Requested action aborted. Local error in processing.\r\n"
#define error500       "500 Syntax error, command unrecognized.\r\n"
#define error500_auth  "500 AUTH unsuccessful.\r\n"
#define error501       "501 Syntax error in parameters or arguments.\r\n"
#define error503       "503 Invalid sequence of commands (AUTH TLS required prior to authentication).\r\n"
#define error504       "504 Command not implemented for that parameter.\r\n"
#define error530       "530 Please login with USER and PASS.\r\n"
#define error530_b     "530 This account is disabled.\r\n"
#define error530_r     "530 Invalid user name or password.\r\n"
#define error550       "550 File or directory unavailable.\r\n"
#define error550_r     "550 Permission denied.\r\n"
#define error550_a     "550 Data channel was closed by ABOR command from client.\r\n"
#define error550_t     "550 Another action is in progress, use ABOR command first.\r\n"
#define error550_m     "550 Insufficient resources.\r\n"
#define interm125      "125 Data connection already open; Transfer starting.\r\n"
#define interm150      "150 File status okay; about to open data connection.\r\n"
#define interm350      "350 REST supported. Ready to resume at byte offset "
#define interm350_ren  "350 File exists. Ready to rename.\r\n"
#define interm331      "331 User "
#define interm331_tail " OK. Password required\r\n"

#define NOSLOTS "MAXIMUM ALLOWED USERS CONNECTED\r\n"

#endif /* FTPSERV_H_ */
