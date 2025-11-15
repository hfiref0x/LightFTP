/*
 * ftpserv.h
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Nov 08, 2025
 *
 *      Author: lightftp
 */

#ifndef FTPSERV_H_
#define FTPSERV_H_ 1

#if !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#if !defined _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <time.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>

#if defined __CYGWIN__
#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE       	 3
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT              16
#endif
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE             TCP_KEEPALIVE
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL            17
#endif
#endif

typedef struct _ftp_config {
    char*           config_file;
    uint64_t        max_users;
    uint64_t        enable_keepalive;
    int             file_open_flags;
    in_port_t       port;
    in_port_t       pasv_port_base;
    in_port_t       pasv_port_max;
    in_addr_t       bind_to_interface;
    in_addr_t       external_interface;
    in_addr_t       local_ip_mask;
} ftp_config, *pftp_config;

#define FTP_VERSION          "2.4"
#define CONFIG_FILE_NAME     "fftp.conf"
#define CONFIG_SECTION_NAME  "ftpconfig"
#define DEFAULT_FTP_PORT     21
#define INVALID_SOCKET       -1
#define SOCKET               int
#define MODE_NORMAL          0
#define MODE_PASSIVE         1
#define MSG_MAXLEN           128

/*
 * NOT_LOGGED_IN = "banned" in config. Not logged in or banned.
 * READONLY = "readonly" in config. Browse and download.
 * CREATENEW = "upload" in config. Creating new directories, store new files. Append, rename and delete disabled.
 * FULL = "admin" in config. All access features enabled.
 */

#define FTP_ACCESS_NOT_LOGGED_IN    0
#define FTP_ACCESS_READONLY         1
#define FTP_ACCESS_CREATENEW        2
#define FTP_ACCESS_FULL             3

#define TRANSMIT_BUFFER_SIZE    65536

typedef struct _session_stats {
    uint64_t    data_rx;
    uint64_t    data_tx;
    uint64_t    files_rx;
    uint64_t    files_tx;
} session_stats, *psession_stats;

typedef struct _ftp_context {
    int                 busy;
    SOCKET              control_socket;
    SOCKET              data_socket;
    pthread_t           worker_thread_id;
    /*
     * worker_thread_valid is output of pthread_create
     * therefore zero is VALID indicator and -1 is invalid.
     */
    int                 worker_thread_valid;
    int                 worker_thread_abort;
    in_addr_t           server_ipv4;
    in_addr_t           client_ipv4;
    in_addr_t           data_ipv4;
    in_port_t           data_port;
    int                 file_fd;
    int                 mode;
    int                 access;
    unsigned int        session_id;
    int                 data_protection_level;
    off_t               rest_point;
    uint64_t            block_size; // reserved for future use
    char                current_dir[PATH_MAX];
    char                user_name[PATH_MAX];
    char                root_dir[PATH_MAX];
    char                rn_from[PATH_MAX];
    char                file_name[2*PATH_MAX];
    gnutls_session_t    tls_session;
    session_stats       stats;
} ftp_context, *pftp_context;

#define LIST_TYPE_UNIX  0
#define LIST_TYPE_MLSD  1
#define STOR_TYPE_RECREATE_TRUNC  0
#define STOR_TYPE_APPEND  1

typedef struct _thcontext {
    pftp_context  context;
    char          th_file_name[2*PATH_MAX];
    int           fn_type;
} thcontext, *pthcontext;

typedef ssize_t (*ftproutine) (pftp_context context, const char* params);

typedef struct _ftproutine_entry {
    const char* name;
    ftproutine  proc;
} ftproutine_entry, *pftproutine_entry;

typedef void * (*pstartroutine)(pthcontext);

extern ftp_config   g_cfg;
extern int          g_log;
extern void*        ftpmain(void* p);
extern char         GOODBYE_MSG[MSG_MAXLEN];

extern gnutls_certificate_credentials_t     x509_cred;
extern gnutls_priority_t                    priority_cache;
extern gnutls_datum_t                       session_keys_storage;

#define FTP_COMMAND(cmdname)    ssize_t cmdname(pftp_context context, const char* params)
#define MAX_CMDS                32
extern const char               shortmonths[12][4];

FTP_COMMAND(ftpUSER);
FTP_COMMAND(ftpQUIT);
FTP_COMMAND(ftpNOOP);
FTP_COMMAND(ftpPWD);
FTP_COMMAND(ftpTYPE);
FTP_COMMAND(ftpPORT);
FTP_COMMAND(ftpLIST);
FTP_COMMAND(ftpAPPE);
FTP_COMMAND(ftpCDUP);
FTP_COMMAND(ftpCWD);
FTP_COMMAND(ftpRETR);
FTP_COMMAND(ftpABOR);
FTP_COMMAND(ftpDELE);
FTP_COMMAND(ftpPASV);
FTP_COMMAND(ftpPASS);
FTP_COMMAND(ftpREST);
FTP_COMMAND(ftpSIZE);
FTP_COMMAND(ftpMKD);
FTP_COMMAND(ftpRMD);
FTP_COMMAND(ftpSTOR);
FTP_COMMAND(ftpSYST);
FTP_COMMAND(ftpFEAT);
FTP_COMMAND(ftpRNFR);
FTP_COMMAND(ftpRNTO);
FTP_COMMAND(ftpOPTS);
FTP_COMMAND(ftpMLSD);
FTP_COMMAND(ftpAUTH);
FTP_COMMAND(ftpPBSZ);
FTP_COMMAND(ftpPROT);
FTP_COMMAND(ftpEPSV);
FTP_COMMAND(ftpHELP);
FTP_COMMAND(ftpSITE);

#define success200     "200 Command okay.\r\n"
#define success200_1   "200 Type set to A.\r\n"
#define success200_2   "200 Type set to I.\r\n"

extern const char success211[];
extern const char success214[];

#define success215     "215 UNIX Type: L8\r\n"
#define success220     "220 LightFTP server ready\r\n"
#define success221     "221 Goodbye!\r\n"
#define success226     "226 Transfer complete. Closing data connection.\r\n"
#define success230     "230 User logged in, proceed.\r\n"
#define success234     "234 AUTH command OK. Initialize TLS connection.\r\n"
#define success250     "250 Requested file action okay, completed.\r\n"
#define success257     "257 Directory created.\r\n"
#define error425       "425 Can not open data connection.\r\n"
#define error426       "426 Connection closed; transfer aborted.\r\n"
#define error450       "450 Requested file action not taken.\r\n"
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
#define interm350_ren  "350 File exists. Ready to rename.\r\n"

#define error451_max   "451 MAXIMUM ALLOWED USERS CONNECTED.\r\n"

#endif /* FTPSERV_H_ */
