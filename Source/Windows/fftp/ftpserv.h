#ifndef _FTPSERV_
#define _FTPSERV_
#pragma comment(lib, "ws2_32.lib")

static const char success200[]		= "200 Command okay.\r\n";
static const char success200_1[]	= "200 Type set to A.\r\n";
static const char success200_2[]	= "200 Type set to I.\r\n";
static const char success211[]		= "211-Extensions supported:\r\n PASV\r\n UTF8\r\n TVFS\r\n REST STREAM\n SIZE\r\n MLSD\r\n";
static const char success211_end[]	= "211 End.\r\n";
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
static const char interm331[]		= "331 User ";
static const char interm331_tail[]  = " OK. Password required\r\n";
static const char noslots[]			= "MAXIMUM ALLOWED USERS CONNECTED\r\n";
static const char CRLF[]			= "\r\n";

static const TCHAR shortmonths[]	= TEXT("JanFebMarAprMayJunJulAugSepOctNovDec");

#define MODE_NORMAL			0
#define MODE_PASSIVE		1

#define FTP_ACCESS_NOT_LOGGED_IN	0 // not logged in or banned. "banned"
#define FTP_ACCESS_READONLY			1 // browse and download. "readonly"
#define FTP_ACCESS_CREATENEW		2 // creating new directories, store new files, append disabled. "upload"
#define FTP_ACCESS_FULL				3 // read, write, append, delete, rename. "admin"

#define TRANSMIT_BUFFER_SIZE	65536  // should be greater than 128

#define	CONFIG_FILE_NAME		TEXT("fftp.cfg")
#define	CONFIG_SECTION_NAME		"ftpconfig"
#define	DEFAULT_FTP_PORT		21

typedef struct	_FTPCONTEXT {
	SOCKET				ControlSocket;
	SOCKET				DataSocket;
	HANDLE				WorkerThread;
	HANDLE				FileHandle;
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
	CHAR				UserName[256];
	CHAR				CurrentDir[MAX_PATH];
	CHAR				RootDir[MAX_PATH];
	TCHAR				RenFrom[MAX_PATH];
	TCHAR				TextBuffer[MAX_PATH*2];
} FTPCONTEXT, *PFTPCONTEXT;

BOOL ftpUSER(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpQUIT(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpNOOP(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpPWD(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpTYPE(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpPORT(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpLIST(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpAPPE(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpCDUP(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpCWD(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpRETR(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpABOR(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpDELE(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpPASV(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpPASS(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpREST(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpSIZE(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpMKD(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpRMD(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpSTOR(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpSYST(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpFEAT(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpRNFR(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpRNTO(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpOPTS(IN PFTPCONTEXT context, IN const char *params);
BOOL ftpMLSD(IN PFTPCONTEXT context, IN const char *params);

typedef struct _FTP_CONFIG {
	PCHAR	ConfigFile;
	ULONG	Port;
	ULONG	BindToInterface;
	ULONG	ExternalInterface;
	ULONG	LocalIPMask;
	ULONG	PasvPortBase;
	ULONG	PasvPortMax;
	ULONG	MaxUsers;
	SOCKET	ListeningSocket; // OUT
} FTP_CONFIG, *PFTP_CONFIG;

typedef BOOL (*FTPROUTINE) (
	IN PFTPCONTEXT	context,
	IN const char	*params);

#define	MAX_CMDS 26

static const char *ftpcmds[MAX_CMDS] = {
	"USER", "QUIT", "NOOP", "PWD",  "TYPE", "PORT", "LIST", "CDUP",
	"CWD",  "RETR", "ABOR", "DELE", "PASV", "PASS", "REST", "SIZE",
	"MKD",  "RMD",  "STOR", "SYST", "FEAT", "APPE", "RNFR", "RNTO",
	"OPTS", "MLSD"
};

static const FTPROUTINE ftpprocs[MAX_CMDS] = {
	ftpUSER, ftpQUIT, ftpNOOP, ftpPWD, ftpTYPE, ftpPORT, ftpLIST, ftpCDUP,
	ftpCWD, ftpRETR, ftpABOR, ftpDELE, ftpPASV, ftpPASS, ftpREST, ftpSIZE,
	ftpMKD, ftpRMD, ftpSTOR, ftpSYST, ftpFEAT, ftpAPPE, ftpRNFR, ftpRNTO,
	ftpOPTS, ftpMLSD
};

FTP_CONFIG	g_cfg;
HANDLE		g_LogHandle;

DWORD WINAPI ftpmain(LPVOID p);
BOOL writeconsolestr(const char *Buffer);
int ParseConfig(const char *pcfg, const char *section_name, const char *key_name, char *value, unsigned long value_size_max);

#endif /* _FTPSERV_ */
