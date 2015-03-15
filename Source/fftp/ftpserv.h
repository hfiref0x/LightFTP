#ifndef _FTPSERV_
#define _FTPSERV_

#pragma warning(disable: 6258) //using TerminateThread does not allow proper thread clean up.

#pragma comment(lib, "ws2_32.lib")

static const char success200[]		= "200 Command okay.\r\n";
static const char success200_1[]	= "200 Type set to A.\r\n";
static const char success200_2[]	= "200 Type set to I.\r\n";
static const char success211[]		= "211-Features:\n TVFS\n REST STREAM\n SIZE\r\n";
static const char success211_end[]	= "211 End\r\n\r\n";
static const char success215[]		= "215 Windows_NT Type: L8\r\n";
static const char success220[]		= "220 LightFTP server v1.0 ready\r\n";
static const char success221[]		= "221 Goodbye!\r\n";
static const char success226[]		= "226 Transfer complete. Closing data connection.\r\n";
static const char success227[]		= "227 Entering Passive Mode (";
static const char success230[]		= "230 User logged in, proceed.\r\n";
static const char success250[]		= "250 Requested file action okay, completed.\r\n";
static const char success257[]		= "257 Directory created.\r\n";
static const char error425[]		= "425 Can not open data connection.\r\n";
static const char error426[]		= "426 Connection closed; transfer aborted.\r\n";
static const char error451[]		= "451 Requested action aborted. Local error in processing.\r\n";
static const char error500[]		= "500 Syntax error, command unrecognized.\r\n";
static const char error501[]		= "501 Syntax error in parameters or arguments.\r\n";
static const char error530[]		= "530 Please login with USER and PASS.\r\n";
static const char error530_b[]		= "530 This account is disabled.\r\n";
static const char error530_r[]		= "530 Invalid user name of password.\r\n";
static const char error550[]		= "550 File or directory unavailable.\r\n";
static const char error550_r[]		= "550 Permission denied.\r\n";
static const char error550_a[]		= "550 Data channel was closed by ABOR command from client.\r\n";
static const char error550_t[]		= "550 Another action is in progress, use ABOR command first.\r\n";
static const char interm125[]		= "125 Data connection already open; Transfer starting.\r\n";
static const char interm150[]		= "150 File status okay; about to open data connection.\r\n";
static const char interm350[]		= "350 REST supported. Ready to resume at byte offset ";
static const char interm350_ren[]	= "350 File exists. Ready to rename.\r\n";
static const char interm331[]		= "331 Enter password.\r\n";
static const char noslots[]			= "MAXIMUM ALLOWED USERS CONNECTED\r\n";
static const char CRLF[]			= "\r\n";

#define MODE_NORMAL			0
#define MODE_PASSIVE		1

#define FTP_ACCESS_NOT_LOGGED_IN	0 // not logged in or banned. "banned"
#define FTP_ACCESS_READONLY			1 // browse and download. "readonly"
#define FTP_ACCESS_CREATENEW		2 // creating new directories, store new files, append disabled. "upload"
#define FTP_ACCESS_FULL				3 // read, write, append, delete, rename. "admin"

#define TRANSMIT_BUFFER_SIZE	65536
#define	MAX_CMDS				24

#define	CONFIG_FILE_NAME		TEXT("fftp.cfg")
#define	CONFIG_SECTION_NAME		TEXT("ftpconfig")
#define	DEFAULT_FTP_PORT		21

typedef struct	_FTPCONTEXT {
	SOCKET				ControlSocket;
	SOCKET				DataSocket;
	HANDLE				WorkerThread;
	HANDLE				FileHandle;
	HANDLE				LogHandle;
	ULONG				ServerIPv4;
	ULONG				ClientIPv4;
	ULONG				DataIPv4;
	ULONG				DataPort;
	ULONG				Mode;
	ULONG				Access;
	ULONG				SessionID;
	BOOL				Stop;
	LARGE_INTEGER		RestPoint;
	CRITICAL_SECTION	MTLock;
	CHAR				CurrentDir[MAX_PATH];
	CHAR				RootDir[MAX_PATH];
	TCHAR				RenFrom[MAX_PATH];
	TCHAR				UserName[MAX_PATH];
	TCHAR				TextBuffer[MAX_PATH*2];
} FTPCONTEXT, *PFTPCONTEXT;

BOOL WINAPI ftpUSER(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpQUIT(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpNOOP(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpPWD(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpTYPE(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpPORT(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpLIST(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpAPPE(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpCDUP(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpCWD(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpRETR(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpABOR(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpDELE(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpPASV(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpPASS(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpREST(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpSIZE(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpMKD(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpRMD(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpSTOR(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpSYST(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpFEAT(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpRNFR(IN PFTPCONTEXT context, IN const char *params);
BOOL WINAPI ftpRNTO(IN PFTPCONTEXT context, IN const char *params);

typedef struct _FTP_CONFIG {
	ULONG	Port;
	ULONG	NetInterface;
	ULONG	MaxUsers;
	HANDLE	LogHandle;
	SOCKET	ListeningSocket; // OUT
} FTP_CONFIG, *PFTP_CONFIG;

typedef BOOL (__stdcall *FTPROUTINE) (
	IN PFTPCONTEXT	context,
	IN const char	*params);

static const char *ftpcmds[MAX_CMDS] = {
	"USER", "QUIT", "NOOP", "PWD",  "TYPE", "PORT", "LIST", "CDUP",
	"CWD",  "RETR", "ABOR", "DELE", "PASV", "PASS", "REST", "SIZE",
	"MKD",  "RMD",  "STOR", "SYST", "FEAT", "APPE", "RNFR", "RNTO"
};

static const FTPROUTINE ftpprocs[MAX_CMDS] = {
	ftpUSER, ftpQUIT, ftpNOOP, ftpPWD, ftpTYPE, ftpPORT, ftpLIST, ftpCDUP,
	ftpCWD, ftpRETR, ftpABOR, ftpDELE, ftpPASV, ftpPASS, ftpREST, ftpSIZE,
	ftpMKD, ftpRMD, ftpSTOR, ftpSYST, ftpFEAT, ftpAPPE, ftpRNFR, ftpRNTO
};

DWORD WINAPI ftpmain(PFTP_CONFIG p);
BOOL writeconsolestr(HANDLE LogHandle, const char *Buffer);

#endif /* _FTPSERV_ */
