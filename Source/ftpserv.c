/*
* ftpserv.c
*
*  Created on: Aug 20, 2016
*
*  Modified on: Feb 09, 2018
*
*      Author: lightftp
*/

#include "ftpserv.h"
#include "cfgparse.h"
#include "x_malloc.h"

__inline char lowcase_a(char c);

static const FTPROUTINE ftpprocs[MAX_CMDS] = {
	ftpUSER, ftpQUIT, ftpNOOP, ftpPWD, ftpTYPE, ftpPORT, ftpLIST, ftpCDUP,
	ftpCWD, ftpRETR, ftpABOR, ftpDELE, ftpPASV, ftpPASS, ftpREST, ftpSIZE,
	ftpMKD, ftpRMD, ftpSTOR, ftpSYST, ftpFEAT, ftpAPPE, ftpRNFR, ftpRNTO,
	ftpOPTS, ftpMLSD, ftpAUTH, ftpPBSZ, ftpPROT
};

static const char *ftpcmds[MAX_CMDS] = {
	"USER", "QUIT", "NOOP", "PWD",  "TYPE", "PORT", "LIST", "CDUP",
	"CWD",  "RETR", "ABOR", "DELE", "PASV", "PASS", "REST", "SIZE",
	"MKD",  "RMD",  "STOR", "SYST", "FEAT", "APPE", "RNFR", "RNTO",
	"OPTS", "MLSD", "AUTH", "PBSZ", "PROT"
};

/*
 * must be in sync with ftpprocs & ftpcmds "PASS" index
 */

#define FTP_PASSCMD_INDEX	13

unsigned int g_newid = 0;

char lowcase_a(char c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + ('a'-'A');
	else
		return c;
}

size_t ultostr(unsigned long x, char *s)
{
        unsigned long   t=x;
        size_t			i, r=1;

        while ( t >= 10 ) {
                t /= 10;
                r++;
        }

        if (s == 0)
                return r;

        for (i = r; i != 0; i--) {
                s[i-1] = (char)(x % 10) + '0';
                x /= 10;
        }

        s[r] = (char)0;
        return r;
}

size_t u64tostr(unsigned long long x, char *s)
{
	unsigned long long	t = x;
	size_t	i, r=1;

	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;

	for (i = r; i != 0; i--) {
		s[i-1] = (char)(x % 10) + '0';
		x /= 10;
	}

	s[r] = 0;
	return r;
}

int strncmpi(const char *s1, const char *s2, size_t cchars)
{
	char c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	if ( cchars==0 )
		return 0;

	do {
		c1 = lowcase_a(*s1);
		c2 = lowcase_a(*s2);
		++s1;
		++s2;
		cchars--;
	} while ( (c1 != 0) && (c1 == c2) && (cchars>0) );

	return (int)(c1 - c2);
}

int strcmpi(const char *s1, const char *s2)
{
        char c1, c2;

        if ( s1==s2 )
                return 0;

        if ( s1==0 )
                return -1;

        if ( s2==0 )
                return 1;

        do {
                c1 = lowcase_a(*s1);
                c2 = lowcase_a(*s2);
                ++s1;
                ++s2;
        } while ( (c1 != 0) && (c1 == c2) );

        return (int)(c1 - c2);
}

int delete_last_slash(char *s)
{
	if (*s == 0)
		return 0;

	/*
	 * don't remove root directory sign as special case
	 */
	if ((s[0] == '/') && (s[1] == 0))
		return 0;

	while (s[1] != 0)
		++s;

	if (*s == '/') {
		*s = 0;
		return 1;
	}
	else
		return 0;
}

int add_last_slash(char *s)
{
	if (*s == 0)
		return 0;

	while (s[1] != 0)
		++s;

	if (*s == '/')
		return 0;
	else
	{
		s[1] = '/';
		s[2] = 0;
		return 1;
	}
}

char *filepath(char *s)
{
	char	*p = s;

	if (*s == 0)
		return s;
/*
 * leave root directory sign untouched
 */
	if (*s == '/')
	{
		++s;
		++p;
	}

	while (*s != 0) {
		if (*s == '/')
			p = s;
		++s;
	}

	*p = 0;

	return p;
}

/*
 * This function filters the path out of ".." members
 * not allowing user to escape the home directory
*/
void format_path(char *input_path, char *filtered_path)
{
	char	*p0, *pnext, *fp0;
	size_t	sl;

	if (*input_path == '/')
	{
		++input_path;
		*filtered_path = '/';
		++filtered_path;
	}

	p0 = input_path;
	pnext = input_path;
	fp0 = filtered_path;
	*fp0 = 0;

	while (1)
	{
		while ((*pnext != '/') && (*pnext != 0))
			++pnext;

		sl = pnext - p0;

		while (sl > 0)
		{
			if (sl == 1)
				if (*p0 == '.')
					break;

			if (sl == 2)
				if ((p0[0] == '.') && (p0[1] == '.'))
				{
					delete_last_slash(filtered_path);
					fp0 = filepath(filtered_path);
					if (fp0 != filtered_path)
					{
						*fp0 = '/';
						++fp0;
						*fp0 = 0;
					}
					break;
				}

			strncpy(fp0, p0, sl);
			fp0 += sl;
			if (*pnext != 0)
			{
				*fp0 = '/';
				++fp0;
			}
			*fp0 = 0;

			break;
		}

		if (*pnext == 0)
			break;

		++pnext;
		p0 = pnext;
	}
}

char *finalpath(char *root_dir, char *current_dir, char *params, char *result_path)
{
	char	*tmp, *user_root;
	size_t	total_len;

	total_len = strlen(root_dir)+strlen(current_dir);
	if (params != NULL)
		total_len += strlen(params);

	if (total_len >= PATH_MAX*4)
		return NULL;

	tmp = x_malloc(PATH_MAX*4);

	strcpy(result_path, root_dir);
	add_last_slash(result_path);
	user_root = result_path+strlen(result_path);

	do {
		if ( params == NULL )
		{
			strcpy(tmp, current_dir);
			add_last_slash(tmp);
			break;
		}

		if ( params[0] != '/' )
		{
			strcpy(tmp, current_dir);
			add_last_slash(tmp);
		}

		strcat(tmp, params);
	} while (0);

	format_path(tmp, user_root);
	free(tmp);
	return result_path;
}

static void cleanup_handler(void *arg)
{
	PFTPCONTEXT context = (PFTPCONTEXT)arg;

	pthread_mutex_unlock(&context->MTLock);
}

ssize_t sendstring_plaintext(SOCKET s, const char *Buffer)
{
	return (send(s, Buffer, strlen(Buffer), MSG_NOSIGNAL) >= 0);
}

int InitTLSSession(gnutls_session_t *session, SOCKET s, int send_success_string)
{
	int ret;

	while (session != NULL)
	{
		if (gnutls_init(session, GNUTLS_SERVER | GNUTLS_NO_SIGNAL) < 0)
			break;

		if (gnutls_priority_set(*session, priority_cache) < 0)
			break;

		if (gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred) < 0)
			break;

		gnutls_certificate_server_set_request(*session, GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
		gnutls_transport_set_int2(*session, s, s);

		if (send_success_string != 0)
			sendstring_plaintext(s, success234);

		do {
			ret = gnutls_handshake(*session);
		} while ((ret < 0) && (gnutls_error_is_fatal(ret) == 0));

		if (ret < 0)
		{
			gnutls_deinit(*session);
			*session = NULL;
		}

		return 1;
	}

	return sendstring_plaintext(s, error500_auth);
}

SOCKET create_datasocket(PFTPCONTEXT context)
{
	SOCKET				clientsocket = INVALID_SOCKET;
	struct sockaddr_in	laddr;
	socklen_t			asz;

	memset(&laddr, 0, sizeof(laddr));

	switch ( context->Mode ) {
	case MODE_NORMAL:
		clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		context->DataSocket = clientsocket;
		if ( clientsocket == INVALID_SOCKET )
			return INVALID_SOCKET;

		laddr.sin_family = AF_INET;
		laddr.sin_port = context->DataPort;
		laddr.sin_addr.s_addr = context->DataIPv4;
		if ( connect(clientsocket, (const struct sockaddr *)&laddr, sizeof(laddr)) == -1 ) {
			close(clientsocket);
			return INVALID_SOCKET;
		}
		break;

	case MODE_PASSIVE:
		asz = sizeof(laddr);
		clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
		close(context->DataSocket);
		context->DataSocket = clientsocket;

		if ( clientsocket == INVALID_SOCKET )
			return INVALID_SOCKET;

		context->DataIPv4 = 0;
		context->DataPort = 0;
		context->Mode = MODE_NORMAL;
		break;

	default:
		return INVALID_SOCKET;
	}
	return clientsocket;
}

ssize_t sendstring(PFTPCONTEXT context, const char *Buffer)
{
	size_t	l = strlen(Buffer);

	if (context->TLS_session == NULL)
		return (send(context->ControlSocket, Buffer, l, MSG_NOSIGNAL) >= 0);
	else
		return (gnutls_record_send(context->TLS_session, Buffer, l) >= 0);
}

ssize_t sendstring_auto(SOCKET s, gnutls_session_t session, const char *Buffer)
{
	size_t	l = strlen(Buffer);

	if (session == NULL)
		return (send(s, Buffer, l, MSG_NOSIGNAL) >= 0);
	else
		return (gnutls_record_send(session, Buffer, l) >= 0);
}

ssize_t send_auto(int __fd, gnutls_session_t session, const void *__buf, size_t __n)
{
	if (session == NULL)
		return (send(__fd, __buf, __n, MSG_NOSIGNAL));
	else
		return (gnutls_record_send(session, __buf, __n));
}

ssize_t recv_auto(int __fd, gnutls_session_t session, void *__buf, size_t __n)
{
	if (session == NULL)
		return (recv(__fd, __buf, __n, 0));
	else
		return (gnutls_record_recv(session, __buf, __n));
}

ssize_t writeconsolestr(const char *Buffer)
{
	size_t	l = strlen(Buffer);

	if ( g_log != -1 )
		write(g_log, Buffer, l);

	return write(STDOUT_FILENO, Buffer, l);
}

int writelogentry(PFTPCONTEXT context, const char *logtext1, const char *logtext2)
{
	char		cvbuf[32], _text[PATH_MAX*4];
	time_t		itm = time(NULL);
	struct tm	ltm;

	localtime_r(&itm, &ltm);

	_text[0] = 0;

	if ( ltm.tm_mday < 10 )
		strcat(_text, "0");
	ultostr(ltm.tm_mday, cvbuf);
	strcat(_text, cvbuf);
	strcat(_text, "-");

	if ( ltm.tm_mon+1 < 10 )
		strcat(_text, "0");
	ultostr(ltm.tm_mon+1, cvbuf);
	strcat(_text, cvbuf);
	strcat(_text, "-");

	ultostr(ltm.tm_year+1900, cvbuf);
	strcat(_text, cvbuf);
	strcat(_text, " ");

	if ( ltm.tm_hour < 10 )
		strcat(_text, "0");
	ultostr(ltm.tm_hour, cvbuf);
	strcat(_text, cvbuf);
	strcat(_text, ":");

	if ( ltm.tm_min < 10 )
		strcat(_text, "0");
	ultostr(ltm.tm_min, cvbuf);
	strcat(_text, cvbuf);
	strcat(_text, ":");

	if ( ltm.tm_sec < 10 )
		strcat(_text, "0");
	ultostr(ltm.tm_sec, cvbuf);
	strcat(_text, cvbuf);

	if (context) {
		strcat(_text, " S-id=");
		ultostr(context->SessionID, cvbuf);
		strcat(_text, cvbuf);
	}
	strcat(_text, ": ");

	if (logtext1)
		strcat(_text, logtext1);

	if (logtext2)
		strcat(_text, logtext2);

	strcat(_text, CRLF);

	return writeconsolestr(_text);
}

void WorkerThreadCleanup(PFTPCONTEXT context)
{
	int					err;
	void				*retv = NULL;

	if ( context->WorkerThreadValid == 0 ) {

		/*
		 * trying to stop gracefully
		 */
		context->WorkerThreadAbort = 1;

		err = pthread_join(context->WorkerThreadId, &retv);
		if ( err != 0)
			pthread_cancel(context->WorkerThreadId);

		context->WorkerThreadValid = -1;
	}

	if ( context->DataSocket != INVALID_SOCKET ) {
		close(context->DataSocket);
		context->DataSocket = INVALID_SOCKET;
	}

	if ( context->File != -1 ) {
		close(context->File);
		context->File = -1;
	}

	context->DataIPv4 = 0;
	context->DataPort = 0;
}

int ftpUSER(PFTPCONTEXT context, const char *params)
{
	if ( params == NULL )
		return sendstring(context, error501);

	context->Access = FTP_ACCESS_NOT_LOGGED_IN;
	strcpy(context->GPBuffer, params);
	writelogentry(context, " USER: ", (char *)params);
	sendstring(context, interm331);
	sendstring(context, params);
	return sendstring(context, interm331_tail);
}

int ftpQUIT(PFTPCONTEXT context, const char *params)
{
	writelogentry(context, " QUIT", NULL);
	sendstring(context, success221);
	return 0;
}

int ftpNOOP(PFTPCONTEXT context, const char *params)
{
	return sendstring(context, success200);
}

int ftpPWD(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	sendstring(context, "257 \"");
	sendstring(context, context->CurrentDir);
	return sendstring(context, "\" is a current directory.\r\n");
}

int ftpTYPE(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	if (params == NULL)
		return sendstring(context, error501);

	switch (*params)
	{
	case 'A':
	case 'a':
		return sendstring(context, success200_1);
	case 'I':
	case 'i':
		return sendstring(context, success200_2);
	}

	return sendstring(context, error501);
}

int ftpPORT(PFTPCONTEXT context, const char *params)
{
	int			c;
	in_addr_t	DataIP = 0, DataPort = 0;
	char		*p = (char *)params;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	if ( params == NULL )
		return sendstring(context, error501);

	for (c = 0; c < 4; c++) {
		DataIP += ((unsigned char)strtoul(p, NULL, 10)) << c*8;
		while ( (*p >= '0') && (*p <= '9') )
			p++;
		if ( *p == 0 )
			break;
		p++;
	}

	for (c = 0; c < 2; c++) {
		DataPort += ((unsigned char)strtoul(p, NULL, 10)) << c*8;
		while ( (*p >= '0') && (*p <= '9') )
			p++;
		if ( *p == 0 )
			break;
		p++;
	}

	if ( DataIP != context->ClientIPv4 )
		return sendstring(context, error501);

	context->DataIPv4 = DataIP;
	context->DataPort = DataPort;
	context->Mode = MODE_NORMAL;

	return sendstring(context, success200);
}

int list_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
{
	char			_text[PATH_MAX*4], *p;
	struct stat		filestats;
	struct tm		ftm_fields;
	time_t			deltatime;

	if (strcmp(entry->d_name, ".") == 0)
		return 1;
	if (strcmp(entry->d_name, "..") == 0)
		return 1;

	strcpy(_text, dirname);
	add_last_slash(_text);
	strcat(_text, entry->d_name);

	if ( stat(_text, &filestats) == 0 )
	{
		if ( S_ISDIR(filestats.st_mode) )
			strcpy(_text, "drwxrwxrwx ");
		else
			strcpy(_text, "-rw-rw-rw- ");

		p = &_text[11];
		p += u64tostr(filestats.st_nlink, p);
		strcpy(p, " 9001 9001 ");
		p+=11;

		p += u64tostr(filestats.st_size, p);
		strcpy(p, " ");
		++p;

		localtime_r(&filestats.st_mtim.tv_sec, &ftm_fields);

		/* month */
		strncpy(p, &shortmonths[(ftm_fields.tm_mon) * 3], 3);
		p+=3;
		strcpy(p, " ");
		++p;

		/* day of month */
		if (ftm_fields.tm_mday < 10)
		{
			strcpy(p, "0");
			++p;
		}
		p += ultostr(ftm_fields.tm_mday, p);
		strcpy(p, " ");
		++p;

		deltatime = time(NULL) - filestats.st_mtim.tv_sec;
		if (deltatime > 180*24*60*60) {
			/* year */
			p += ultostr(ftm_fields.tm_year + 1900, p);
		}
		else
		{
			/* hours */
			if (ftm_fields.tm_hour < 10)
			{
				strcpy(p, "0");
				++p;
			}
			p += ultostr(ftm_fields.tm_hour, p);
			strcpy(p, ":");
			++p;

			/* minutes */
			if (ftm_fields.tm_min < 10)
			{
				strcpy(p, "0");
				++p;
			}
			p += ultostr(ftm_fields.tm_min, p);

		}
		strcpy(p, " ");
		++p;

		if (sendstring_auto(s, session, _text) <= 0)
			return 0;
	}

	if (sendstring_auto(s, session, entry->d_name) <= 0)
		return 0;

	return sendstring_auto(s, session, CRLF);
}

void *list_thread(PFTPCONTEXT context)
{
	SOCKET				clientsocket;
	gnutls_session_t	TLS_datasession;
	int					ret;
	DIR					*pdir;
	struct dirent		*entry;

	pthread_mutex_lock(&context->MTLock);
	pthread_cleanup_push(cleanup_handler, context);
	ret = 0;
	TLS_datasession = NULL;

	clientsocket = create_datasocket(context);
	while (clientsocket != INVALID_SOCKET)
	{
		if (context->TLS_session != NULL)
			InitTLSSession(&TLS_datasession, clientsocket, 0);

		pdir = opendir(context->GPBuffer);
		if (pdir == NULL)
			break;

		while ((entry = readdir(pdir)) != NULL) {
			ret = list_sub(context->GPBuffer, clientsocket, TLS_datasession, entry);
			if ( (ret == 0) || (context->WorkerThreadAbort != 0 ))
				break;
		}

		closedir(pdir);
		break;
	}

	if (TLS_datasession != NULL)
	{
		gnutls_bye(TLS_datasession, GNUTLS_SHUT_RDWR);
		gnutls_deinit(TLS_datasession);
	}

	if (clientsocket != INVALID_SOCKET)
		close(clientsocket);

	writelogentry(context, " LIST complete", NULL);

	if (clientsocket == INVALID_SOCKET) {
		sendstring(context, error451);
	}
	else {
		if ((context->WorkerThreadAbort == 0) && (ret != 0))
			sendstring(context, success226);
		else
			sendstring(context, error426);
	}

	context->WorkerThreadValid = -1;
	pthread_cleanup_pop(0);
	pthread_mutex_unlock(&context->MTLock);
	return NULL;
}

int ftpLIST(PFTPCONTEXT context, const char *params)
{
	struct	stat	filestats;
	pthread_t		tid;

	if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
		return sendstring(context, error530);
	if (context->WorkerThreadValid == 0)
		return sendstring(context, error550_t);

	if (params != NULL)
		if (strcmp(params, "-l") == 0)
			params = NULL;

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	while (stat(context->GPBuffer, &filestats) == 0)
	{
		if ( !S_ISDIR(filestats.st_mode) )
			break;

		sendstring(context, interm150);
		writelogentry(context, " LIST", (char *)params);
		context->WorkerThreadAbort = 0;

		pthread_mutex_lock(&context->MTLock);

		context->WorkerThreadValid = pthread_create(&tid, NULL, (__ptr_thread_start_routine)&list_thread, context);
		if ( context->WorkerThreadValid == 0 )
			context->WorkerThreadId = tid;
		else
			sendstring(context, error451);

		pthread_mutex_unlock(&context->MTLock);

		return 1;
	}

	return sendstring(context, error550);
}

int ftpCDUP(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	if ( strcmp(context->CurrentDir, "/") == 0 )
		return sendstring(context, success250);

	delete_last_slash(context->CurrentDir);
	filepath(context->CurrentDir);

	writelogentry(context, " CDUP", NULL);
	return sendstring(context, success250);
}

int ftpCWD(PFTPCONTEXT context, const char *params)
{
	struct	stat	filestats;
	size_t			rl;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	if ( params == NULL )
		return sendstring(context, error501);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( stat(context->GPBuffer, &filestats) == 0 )
		if ( S_ISDIR(filestats.st_mode) )
		{
			rl = strlen(context->RootDir);
			strcpy(context->CurrentDir, context->GPBuffer+rl);
			writelogentry(context, " CWD: ", context->CurrentDir);
			return sendstring(context, success250);
		}

	return sendstring(context, error550);
}

void *retr_thread(PFTPCONTEXT context)
{
	volatile SOCKET		clientsocket;
	int					sent_ok, f;
	off_t				offset;
	ssize_t				sz, sz_total;
	size_t				buffer_size;
	char				*buffer;
	struct timespec		t;
	signed long long	lt0, lt1, dtx;
	gnutls_session_t	TLS_datasession;

	pthread_mutex_lock(&context->MTLock);
	pthread_cleanup_push(cleanup_handler, context);

	sent_ok = 0;
	sz_total = 0;
	buffer = NULL;
	TLS_datasession = NULL;
	f = -1;
	clock_gettime(CLOCK_MONOTONIC, &t);
	lt0 = t.tv_sec*1e9 + t.tv_nsec;

	buffer = malloc(TRANSMIT_BUFFER_SIZE);
	while (buffer != NULL)
	{
        clientsocket = create_datasocket(context);
        if (clientsocket == INVALID_SOCKET)
            break;

		if (context->TLS_session != NULL)
		{
			InitTLSSession(&TLS_datasession, clientsocket, 0);
			buffer_size = gnutls_record_get_max_size(TLS_datasession);
			if (buffer_size > TRANSMIT_BUFFER_SIZE)
				buffer_size = TRANSMIT_BUFFER_SIZE;
		}
		else
			buffer_size = TRANSMIT_BUFFER_SIZE;

		f = open(context->GPBuffer, O_RDONLY);
		context->File = f;
		if (f == -1)
			break;

		offset = lseek(f, context->RestPoint, SEEK_SET);
		if (offset != context->RestPoint)
			break;

		while ( context->WorkerThreadAbort == 0 ) {
			sz = read(f, buffer, buffer_size);
			if (sz <= 0)
				break;

			sz_total += sz;

			if (send_auto(clientsocket, TLS_datasession, buffer, sz) == sz)
				sent_ok = 1;
			else
			{
				sent_ok = 0;
				break;
			}
		}

		break;
	}

	clock_gettime(CLOCK_MONOTONIC, &t);
	lt1 = t.tv_sec*1e9 + t.tv_nsec;

	if (f != -1)
		close(f);

	context->File = -1;

	if (TLS_datasession != NULL)
	{
		gnutls_bye(TLS_datasession, GNUTLS_SHUT_RDWR);
		gnutls_deinit(TLS_datasession);
	}

	if (clientsocket != INVALID_SOCKET)
		close(clientsocket);

	/* calculating performance */
	dtx = lt1 - lt0;

    if (buffer != NULL) {
	    sprintf(buffer,  " RETR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
	    	sz_total, sz_total/1048576.0, dtx/1000000000.0, (1000000000.0*sz_total)/dtx/1048576);
        writelogentry(context, buffer, NULL);
        free(buffer);
    }

	if (clientsocket == INVALID_SOCKET) {
		sendstring(context, error451);
	}
	else {
		if ((context->WorkerThreadAbort == 0) && (sent_ok != 0))
			sendstring(context, success226);
		else
			sendstring(context, error426);
	}

	context->WorkerThreadValid = -1;
	pthread_cleanup_pop(0);
	pthread_mutex_unlock(&context->MTLock);
	return NULL;
}

int ftpRETR(PFTPCONTEXT context, const char *params)
{
	struct	stat	filestats;
	pthread_t		tid;

	if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
		return sendstring(context, error530);
	if (context->WorkerThreadValid == 0)
		return sendstring(context, error550_t);
	if ( params == NULL )
		return sendstring(context, error501);

	if ( context->File != -1 ) {
		close(context->File);
		context->File = -1;
	}

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	while (stat(context->GPBuffer, &filestats) == 0)
	{
		if ( S_ISDIR(filestats.st_mode) )
			break;

		sendstring(context, interm150);
		writelogentry(context, " RETR: ", (char *)params);
		context->WorkerThreadAbort = 0;

		pthread_mutex_lock(&context->MTLock);

		context->WorkerThreadValid = pthread_create(&tid, NULL, (__ptr_thread_start_routine)&retr_thread, context);
		if ( context->WorkerThreadValid == 0 )
			context->WorkerThreadId = tid;
		else
			sendstring(context, error451);

		pthread_mutex_unlock(&context->MTLock);

		return 1;
	}

	return sendstring(context, error550);
}

int ftpABOR(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	WorkerThreadCleanup(context);
	return sendstring(context, success226);
}

int ftpDELE(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( unlink(context->GPBuffer) == 0 ) {
		sendstring(context, success250);
		writelogentry(context, " DELE: ", (char *)params);
	}
	else
		sendstring(context, error550_r);

	return 1;
}

int ftpPASV(PFTPCONTEXT context, const char *params)
{
	SOCKET				datasocket;
	struct sockaddr_in	laddr;
	int					socketret = -1;
	unsigned long		c;
	struct	timespec	rtctime;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->WorkerThreadValid == 0 )
		return sendstring(context, error550_t);
	if ( context->DataSocket != INVALID_SOCKET )
		close(context->DataSocket);

	context->DataSocket = INVALID_SOCKET;

	datasocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (datasocket == INVALID_SOCKET)
		return sendstring(context, error451);

	for (c = g_cfg.PasvPortBase; c <= g_cfg.PasvPortMax; c++) {
		clock_gettime(CLOCK_REALTIME, &rtctime);
		memset(&laddr, 0, sizeof(laddr));
		laddr.sin_family = AF_INET;
		laddr.sin_port = htons((in_port_t)(g_cfg.PasvPortBase +
			(rtctime.tv_nsec % (g_cfg.PasvPortMax-g_cfg.PasvPortBase))));
		laddr.sin_addr.s_addr = context->ServerIPv4;
		socketret = bind(datasocket, (struct sockaddr *)&laddr, sizeof(laddr));
		if ( socketret == 0 )
			break;
	}

	if ( socketret != 0 ) {
		close(datasocket);
		return sendstring(context, error451);
	}

	socketret = listen(datasocket, SOMAXCONN);
	if (socketret != 0) {
		close(datasocket);
		return sendstring(context, error451);
	}

	if ((context->ClientIPv4 & g_cfg.LocalIPMask) == (context->ServerIPv4 & g_cfg.LocalIPMask))
	{
		context->DataIPv4 = context->ServerIPv4;
		writelogentry(context, " local client.", NULL);
	} else {
		context->DataIPv4 = g_cfg.ExternalInterface;
		writelogentry(context, " nonlocal client.", NULL);
	}

	context->DataPort = laddr.sin_port;
	context->DataSocket = datasocket;
	context->Mode = MODE_PASSIVE;

	sendstring(context, success227);
	for (c = 0; c < 4; c++) {
		ultostr((context->DataIPv4 >> (c*8)) & 0xff, context->GPBuffer);
		strcat(context->GPBuffer, ",");
		sendstring(context, context->GPBuffer);
	}

	ultostr(context->DataPort & 0xff, context->GPBuffer);
	strcat(context->GPBuffer, ",");
	sendstring(context, context->GPBuffer);
	ultostr((context->DataPort >> 8) & 0xff, context->GPBuffer);
	strcat(context->GPBuffer, ").");
	strcat(context->GPBuffer, CRLF);

	writelogentry(context, " entering passive mode", NULL);

	return sendstring(context, context->GPBuffer);
}

int ftpPASS(PFTPCONTEXT context, const char *params)
{
	char	temptext[256];

	if ( params == NULL )
		return sendstring(context, error501);

	memset(temptext, 0, sizeof(temptext));
	if (!ParseConfig(g_cfg.ConfigFile, context->GPBuffer, "pswd", temptext, sizeof(temptext)))
		return sendstring(context, error530_r);

	if ( (strcmp(temptext, params) == 0) || (temptext[0] == '*') )
	{
		memset(context->RootDir, 0, sizeof(context->RootDir));
		memset(temptext, 0, sizeof(temptext));

		ParseConfig(g_cfg.ConfigFile, context->GPBuffer, "root", context->RootDir, sizeof(context->RootDir));
		ParseConfig(g_cfg.ConfigFile, context->GPBuffer, "accs", temptext, sizeof(temptext));

		context->Access = FTP_ACCESS_NOT_LOGGED_IN;
		do {
			if ( strcmpi(temptext, "admin") == 0 ) {
				context->Access = FTP_ACCESS_FULL;
				break;
			}

			if ( strcmpi(temptext, "upload") == 0 ) {
				context->Access = FTP_ACCESS_CREATENEW;
				break;
			}

			if ( strcmpi(temptext, "readonly") == 0 ) {
				context->Access = FTP_ACCESS_READONLY;
				break;
			}

			return sendstring(context, error530_b);
		} while (0);

		writelogentry(context, " PASS->successful logon", NULL);
	}
	else
		return sendstring(context, error530_r);

	return sendstring(context, success230);
}

int ftpREST(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	if ( params == NULL )
		return sendstring(context, error501);

	context->RestPoint = strtoull(params, NULL, 10);
	sendstring(context, interm350);
	u64tostr(context->RestPoint, context->GPBuffer);
	strcat(context->GPBuffer, CRLF);
	return sendstring(context, context->GPBuffer);
}

int ftpSIZE(PFTPCONTEXT context, const char *params)
{
	struct stat		filestats;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( params == NULL )
		return sendstring(context, error501);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( stat(context->GPBuffer, &filestats) == 0 )
	{
		sendstring(context, "213 ");
		u64tostr(filestats.st_size, context->GPBuffer);
		strcat(context->GPBuffer, CRLF);
		sendstring(context, context->GPBuffer);
	}
	else
		sendstring(context, error550);

	return 1;
}

int ftpMKD(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_CREATENEW )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( mkdir(context->GPBuffer, 0755) == 0 ) {
		sendstring(context, success257);
		writelogentry(context, " MKD: ", (char *)params);
	}
	else
		sendstring(context, error550_r);

	return 1;
}

int ftpRMD(PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( rmdir(context->GPBuffer) == 0 ) {
		sendstring(context, success250);
		writelogentry(context, " DELE: ", (char *)params);
	}
	else
		sendstring(context, error550_r);

	return 1;
}

void *stor_thread(PFTPCONTEXT context)
{
	SOCKET				clientsocket;
	int					f;
	ssize_t				sz, sz_total;
	char				*buffer;
	struct timespec		t;
	signed long long	lt0, lt1, dtx;
	gnutls_session_t	TLS_datasession;

	pthread_mutex_lock(&context->MTLock);
	pthread_cleanup_push(cleanup_handler, context);

	f = -1;
	sz_total = 0;
	buffer = NULL;
	TLS_datasession = NULL;
	clock_gettime(CLOCK_MONOTONIC, &t);
	lt0 = t.tv_sec*1e9 + t.tv_nsec;

	clientsocket = create_datasocket(context);
	while (clientsocket != INVALID_SOCKET)
	{
		buffer = malloc(TRANSMIT_BUFFER_SIZE);
		if (buffer == NULL)
			break;

		if (context->TLS_session != NULL)
			InitTLSSession(&TLS_datasession, clientsocket, 0);

		f = open(context->GPBuffer, context->CreateMode, S_IRWXU | S_IRGRP | S_IROTH);
		context->File = f;
		if (f == -1)
			break;

		while ( context->WorkerThreadAbort == 0 ) {
			sz = recv_auto(clientsocket, TLS_datasession, buffer, TRANSMIT_BUFFER_SIZE);
			if (sz > 0)
			{
				sz_total += sz;
				write(f, buffer, sz);
			}
			else
				break;
		}

		break;
	}

	clock_gettime(CLOCK_MONOTONIC, &t);
	lt1 = t.tv_sec*1e9 + t.tv_nsec;

	if (f != -1)
		close(f);

	context->File = -1;

	if (TLS_datasession != NULL)
	{
		gnutls_bye(TLS_datasession, GNUTLS_SHUT_RDWR);
		gnutls_deinit(TLS_datasession);
	}

	if (clientsocket != INVALID_SOCKET)
		close(clientsocket);

	/* calculating performance */
	if (buffer != NULL)
	{
		dtx = lt1 - lt0;
		sprintf(buffer,  " STOR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
				sz_total, sz_total/1048576.0, dtx/1000000000.0, (1000000000.0*sz_total)/dtx/1048576);
		writelogentry(context, buffer, NULL);
		free(buffer);
	}

	if (clientsocket == INVALID_SOCKET) {
		sendstring(context, error451);
	}
	else {
		if (context->WorkerThreadAbort == 0)
			sendstring(context, success226);
		else
			sendstring(context, error426);
	}

	context->WorkerThreadValid = -1;
	pthread_cleanup_pop(0);
	pthread_mutex_unlock(&context->MTLock);
	return NULL;
}

int ftpSTOR(PFTPCONTEXT context, const char *params)
{
	struct	stat	filestats;
	pthread_t		tid;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_CREATENEW )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);
	if ( context->WorkerThreadValid == 0 )
		return sendstring(context, error550_t);

	if ( context->File != -1 ) {
		close(context->File);
		context->File = -1;
	}

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( context->Access == FTP_ACCESS_FULL )
		context->CreateMode = O_CREAT | O_WRONLY| O_TRUNC;
	else
	{
		context->CreateMode = O_CREAT | O_WRONLY| O_EXCL;
		if (stat(context->GPBuffer, &filestats) == 0)
			return sendstring(context, error550_r);
	}

	sendstring(context, interm150);
	writelogentry(context, " STOR: ", (char *)params);
	context->WorkerThreadAbort = 0;

	pthread_mutex_lock(&context->MTLock);

	context->WorkerThreadValid = pthread_create(&tid, NULL, (__ptr_thread_start_routine)&stor_thread, context);
	if ( context->WorkerThreadValid == 0 )
		context->WorkerThreadId = tid;
	else
		sendstring(context, error451);

	pthread_mutex_unlock(&context->MTLock);

	return 1;
}

int ftpSYST(PFTPCONTEXT context, const char *params)
{
	return sendstring(context, success215);
}

int ftpFEAT(PFTPCONTEXT context, const char *params)
{
	sendstring(context, success211);
	return sendstring(context, success211_end);
}

void *append_thread(PFTPCONTEXT context)
{
	SOCKET				clientsocket;
	int					f = -1;
	ssize_t				sz;
	char				*buffer = NULL;
	gnutls_session_t	TLS_datasession;

	pthread_mutex_lock(&context->MTLock);
	pthread_cleanup_push(cleanup_handler, context);
	TLS_datasession = NULL;

	clientsocket = create_datasocket(context);
	while (clientsocket != INVALID_SOCKET)
	{
		if (context->TLS_session != NULL)
			InitTLSSession(&TLS_datasession, clientsocket, 0);

		f = open(context->GPBuffer, O_RDWR);
		context->File = f;
		if (f == -1)
			break;

		lseek(f, 0, SEEK_END);
		buffer = malloc(TRANSMIT_BUFFER_SIZE);
		if (buffer == NULL)
			break;

		while ( context->WorkerThreadAbort == 0 ) {
			sz = recv_auto(clientsocket, TLS_datasession, buffer, TRANSMIT_BUFFER_SIZE);
			if (sz > 0)
				write(f, buffer, sz);
			else
				break;
		}

		break;
	}

	if (buffer != NULL)
		free(buffer);

	if (f != -1)
		close(f);

	context->File = -1;

	if (TLS_datasession != NULL)
	{
		gnutls_bye(TLS_datasession, GNUTLS_SHUT_RDWR);
		gnutls_deinit(TLS_datasession);
	}

	if (clientsocket != INVALID_SOCKET)
		close(clientsocket);

	writelogentry(context, " STOR complete", NULL);

	if (clientsocket == INVALID_SOCKET) {
		sendstring(context, error451);
	}
	else {
		if (context->WorkerThreadAbort == 0)
			sendstring(context, success226);
		else
			sendstring(context, error426);
	}

	context->WorkerThreadValid = -1;
	pthread_cleanup_pop(0);
	pthread_mutex_unlock(&context->MTLock);
	return NULL;
}

int ftpAPPE(PFTPCONTEXT context, const char *params)
{
	struct	stat	filestats;
	pthread_t		tid;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);
	if ( context->WorkerThreadValid == 0 )
		return sendstring(context, error550_t);

	if ( context->File != -1 ) {
		close(context->File);
		context->File = -1;
	}

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	/*
	 * stat must NOT fail
	 */
	while (stat(context->GPBuffer, &filestats) == 0)
	{
		/*
		 * do not try to "append" for directories
		*/
		if ( S_ISDIR(filestats.st_mode) )
			break;

		sendstring(context, interm150);
		writelogentry(context, " APPE: ", (char *)params);
		context->WorkerThreadAbort = 0;

		pthread_mutex_lock(&context->MTLock);

		context->WorkerThreadValid = pthread_create(&tid, NULL, (__ptr_thread_start_routine)&append_thread, context);
		if ( context->WorkerThreadValid == 0 )
			context->WorkerThreadId = tid;
		else
			sendstring(context, error451);

		pthread_mutex_unlock(&context->MTLock);

		return 1;
	}

	return sendstring(context, error550);
}

int ftpRNFR(PFTPCONTEXT context, const char *params)
{
	struct stat		filestats;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	if ( stat(context->GPBuffer, &filestats) == 0 )
	{
		writelogentry(context, " RNFR: ", context->GPBuffer);
		sendstring(context, interm350_ren);
	}
	else
		sendstring(context, error550);

	return 1;
}

int ftpRNTO(PFTPCONTEXT context, const char *params)
{
	char	*_text;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context, error550_r);
	if ( params == NULL )
		return sendstring(context, error501);

	_text = x_malloc(PATH_MAX * 4);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, _text) == NULL)
	{
		free(_text);
		return 0;
	}

	if ( rename(context->GPBuffer, _text) == 0 )
	{
		writelogentry(context, " RNTO: ", _text);
		sendstring(context, success250);
	}
	else
		sendstring(context, error550);

	free(_text);
	return 1;
}

int ftpOPTS(PFTPCONTEXT context, const char *params)
{
	return sendstring(context, success200);
}

int ftpAUTH(PFTPCONTEXT context, const char *params)
{
	if ( params == NULL )
		return sendstring(context, error501);

	if ( strcmpi(params, "TLS") == 0 )
		/* InitTLSSession will send reply */
		return InitTLSSession(&context->TLS_session, context->ControlSocket, 1);
	else
		return sendstring(context, error504);
}

int ftpPBSZ (PFTPCONTEXT context, const char *params)
{
	if ( params == NULL )
		return sendstring(context, error501);

	if ( context->TLS_session == NULL )
		return sendstring(context, error503);

	context->BlockSize = strtoul(params, NULL, 10);
	return sendstring(context, success200);
}

int ftpPROT (PFTPCONTEXT context, const char *params)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context, error530);

	if ( params == NULL )
			return sendstring(context, error501);

	if ( context->TLS_session == NULL )
		return sendstring(context, error503);

	switch (*params)
	{
	case 'C':
		context->DataProtectionLevel = 0;
		return sendstring(context, success200);
		break;

	case 'P':
		context->DataProtectionLevel = 100;
		return sendstring(context, success200);
		break;

	default:
		return sendstring(context, error504);
	}
}

int mlsd_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
{
	char			_text[PATH_MAX*4], *p;
	struct stat		filestats;
	struct tm		ftm_fields;

	if (strcmp(entry->d_name, ".") == 0)
		return 1;
	if (strcmp(entry->d_name, "..") == 0)
		return 1;

	strcpy(_text, dirname);
	add_last_slash(_text);
	strcat(_text, entry->d_name);

	if ( stat(_text, &filestats) == 0 )
	{
		strcpy(_text, "type=");
		if ( S_ISDIR(filestats.st_mode) )
			strcat(_text, "dir;sizd=");
		else
			strcat(_text, "file;size=");

		p = &_text[0] + strlen(_text);
		p += u64tostr(filestats.st_size, p);
		strcpy(p, ";modify=");

		localtime_r(&filestats.st_mtim.tv_sec, &ftm_fields);
		++ftm_fields.tm_mon;

		p = &_text[0] + strlen(_text);
		p += ultostr(ftm_fields.tm_year + 1900, p);

		if (ftm_fields.tm_mon < 10)
		{
			strcpy(p, "0");
			++p;
		}
		p += ultostr(ftm_fields.tm_mon, p);

		/* day of month */
		if (ftm_fields.tm_mday < 10)
		{
			strcpy(p, "0");
			++p;
		}
		p += ultostr(ftm_fields.tm_mday, p);

		/* hours */
		if (ftm_fields.tm_hour < 10)
		{
			strcpy(p, "0");
			++p;
		}
		p += ultostr(ftm_fields.tm_hour, p);

		/* minutes */
		if (ftm_fields.tm_min < 10)
		{
			strcpy(p, "0");
			++p;
		}
		p += ultostr(ftm_fields.tm_min, p);

		/* seconds */
		if (ftm_fields.tm_sec < 10)
		{
			strcpy(p, "0");
			++p;
		}
		p += ultostr(ftm_fields.tm_sec, p);

		strcpy(p, "; ");
		if (sendstring_auto(s, session, _text) <= 0)
			return 0;
	}

	if (sendstring_auto(s, session, entry->d_name) <= 0)
		return 0;

	return sendstring_auto(s, session, CRLF);
}

void *msld_thread(PFTPCONTEXT context)
{
	SOCKET				clientsocket;
	gnutls_session_t	TLS_datasession;
	int					ret;
	DIR					*pdir;
	struct dirent		*entry;

	pthread_mutex_lock(&context->MTLock);
	pthread_cleanup_push(cleanup_handler, context);
	ret = 0;
	TLS_datasession = NULL;

	clientsocket = create_datasocket(context);
	while (clientsocket != INVALID_SOCKET)
	{
		if (context->TLS_session != NULL)
			InitTLSSession(&TLS_datasession, clientsocket, 0);

		pdir = opendir(context->GPBuffer);
		if (pdir == NULL)
			break;

		while ((entry = readdir(pdir)) != NULL) {
			ret = mlsd_sub(context->GPBuffer, clientsocket, TLS_datasession, entry);
			if ( (ret == 0) || (context->WorkerThreadAbort != 0 ))
				break;
		}

		closedir(pdir);
		break;
	}

	if (TLS_datasession != NULL)
	{
		gnutls_bye(TLS_datasession, GNUTLS_SHUT_RDWR);
		gnutls_deinit(TLS_datasession);
	}

	if (clientsocket != INVALID_SOCKET)
		close(clientsocket);

	writelogentry(context, " LIST complete", NULL);

	if (clientsocket == INVALID_SOCKET) {
		sendstring(context, error451);
	}
	else {
		if ((context->WorkerThreadAbort == 0) && (ret != 0))
			sendstring(context, success226);
		else
			sendstring(context, error426);
	}

	context->WorkerThreadValid = -1;
	pthread_cleanup_pop(0);
	pthread_mutex_unlock(&context->MTLock);
	return NULL;
}

int ftpMLSD(PFTPCONTEXT context, const char *params)
{
	struct	stat	filestats;
	pthread_t		tid;

	if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
		return sendstring(context, error530);
	if (context->WorkerThreadValid == 0)
		return sendstring(context, error550_t);

	if (finalpath(
			context->RootDir,
			context->CurrentDir,
			(char *)params, context->GPBuffer) == NULL)
		return 0;

	while (stat(context->GPBuffer, &filestats) == 0)
	{
		if ( !S_ISDIR(filestats.st_mode) )
			break;

		sendstring(context, interm150);
		writelogentry(context, " MLSD-LIST", (char *)params);
		context->WorkerThreadAbort = 0;

		pthread_mutex_lock(&context->MTLock);

		context->WorkerThreadValid = pthread_create(&tid, NULL, (__ptr_thread_start_routine)&msld_thread, context);
		if ( context->WorkerThreadValid == 0 )
			context->WorkerThreadId = tid;
		else
			sendstring(context, error451);

		pthread_mutex_unlock(&context->MTLock);

		return 1;
	}

	return sendstring(context, error550);
}

int recvcmd(PFTPCONTEXT context, char *buffer, size_t buffer_size)
{
	ssize_t	l, p = 0;

	if ( buffer_size < 5 )
		return 0;

	memset(buffer, 0, buffer_size);
	--buffer_size;

	while (buffer_size > 0)
	{
		if (context->TLS_session == NULL)
			l = recv(context->ControlSocket, buffer+p, buffer_size, 0);
		else
			l = gnutls_record_recv(context->TLS_session, buffer+p, buffer_size);

		if ( l <= 0 )
			return 0;

		buffer_size -= l;
		p += l;

		if ( p >= 2 )
			if ( (buffer[p-2] == '\r') && (buffer[p-1] == '\n') )
			{
				buffer[p-2] = 0;
				return 1;
			}
	}

	return 0;
}

void *ftp_client_thread(SOCKET *s)
{
	FTPCONTEXT				ctx __attribute__ ((aligned (16)));
	char					*cmd, *params, rcvbuf[PATH_MAX*2];
	int						c, cmdno, rv;
	size_t					i, cmdlen;
	socklen_t				asz;
	struct sockaddr_in		laddr;
	pthread_mutexattr_t		m_attr;

	memset(&ctx, 0, sizeof(ctx));
	ctx.Access = FTP_ACCESS_NOT_LOGGED_IN;
	ctx.ControlSocket = *s;
	ctx.GPBuffer = x_malloc(PATH_MAX*4);

	memset(&laddr, 0, sizeof(laddr));
	asz = sizeof(laddr);
	while ( getsockname(ctx.ControlSocket, (struct sockaddr *)&laddr, &asz) == 0 )
	{
		ctx.ServerIPv4 = laddr.sin_addr.s_addr;

		memset(&laddr, 0, sizeof(laddr));
		asz = sizeof(laddr);
		if ( getpeername(ctx.ControlSocket, (struct sockaddr *)&laddr, &asz) != 0 )
			break;

		ctx.ClientIPv4 = laddr.sin_addr.s_addr;
		ctx.Mode = MODE_NORMAL;
		ctx.WorkerThreadAbort = 0;
		ctx.WorkerThreadValid = -1;
		ctx.SessionID = __sync_add_and_fetch(&g_newid, 1);
		ctx.File = -1;
		ctx.DataSocket = INVALID_SOCKET;

		pthread_mutexattr_init(&m_attr);
#if defined(PTHREAD_MUTEX_RECURSIVE) || defined(__FreeBSD__)
		pthread_mutexattr_settype(&m_attr, PTHREAD_MUTEX_RECURSIVE);
#else
        pthread_mutexattr_settype(&m_attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
        pthread_mutex_init(&ctx.MTLock, &m_attr);

		ctx.CurrentDir[0] = '/';
		sendstring(&ctx, success220);

		memset(&rcvbuf, 0, sizeof(rcvbuf));

		inet_ntop(AF_INET, &laddr.sin_addr, rcvbuf, INET_ADDRSTRLEN+1);
		strcat(rcvbuf, ":");
		cmdlen = strlen(rcvbuf);
		ultostr(ntohs(laddr.sin_port), &rcvbuf[cmdlen]);
		writelogentry(&ctx, "<- New user IP=", rcvbuf);

		while ( ctx.ControlSocket != INVALID_SOCKET ) {
			if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) )
				break;

			i = 0;
			while (rcvbuf[i] == ' ')
				i++;

			cmd = &rcvbuf[i];
			while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' '))
				i++;

			cmdlen = &rcvbuf[i] - cmd;
			while (rcvbuf[i] == ' ')
				i++;

			if (rcvbuf[i] == 0)
				params = NULL;
			else
				params = &rcvbuf[i];

			cmdno = -1;
			for (c=0; c<MAX_CMDS; c++)
				if (strncmpi(cmd, ftpcmds[c], cmdlen) == 0)
				{
					cmdno = c;
					rv = ftpprocs[c](&ctx, params);
					break;
				}

			if ( cmdno != FTP_PASSCMD_INDEX )
				writelogentry(&ctx, " @@ CMD: ", rcvbuf);
			else
				writelogentry(&ctx, " @@ CMD: ", "PASS ***");

			if ( cmdno == -1 )
				sendstring(&ctx, error500);

			if ( rv <= 0 )
				break;
		};

		WorkerThreadCleanup(&ctx);

		pthread_mutex_destroy(&ctx.MTLock);
		pthread_mutexattr_destroy(&m_attr);
		writelogentry(&ctx, "User disconnected", NULL);
		break;
	}

	if (ctx.TLS_session != NULL)
		gnutls_deinit(ctx.TLS_session);

	free(ctx.GPBuffer);
	close(ctx.ControlSocket);
	*s = INVALID_SOCKET;
	return NULL;
}

void *ftpmain(void *p)
{
	struct sockaddr_in	laddr;

	int		ftpsocket = INVALID_SOCKET,
			clientsocket,
			*scb = NULL,
			socketret,
			rv;

	socklen_t	asz;
	uint32_t	i;
	pthread_t	th;

	ftpsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( ftpsocket == INVALID_SOCKET )
	{
		printf("\r\n socket create error\r\n");
		return 0;
	}

	rv = 1;
	setsockopt(ftpsocket, SOL_SOCKET, SO_REUSEADDR, &rv, sizeof(rv));

	scb = (SOCKET *)x_malloc(sizeof(SOCKET)*g_cfg.MaxUsers);
	for (i = 0; i<g_cfg.MaxUsers; i++)
		scb[i] = INVALID_SOCKET;

	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons(g_cfg.Port);
	laddr.sin_addr.s_addr = g_cfg.BindToInterface;
	socketret = bind(ftpsocket, (struct sockaddr *)&laddr, sizeof(laddr));
	if  ( socketret != 0 ) {
		printf("\r\n Failed to start server. Can not bind to address\r\n\r\n");
		free(scb);
		close(ftpsocket);
		return 0;
	}

	writelogentry(NULL, success220, NULL);

	socketret = listen(ftpsocket, SOMAXCONN);
	while ( socketret == 0 ) {
		memset(&laddr, 0, sizeof(laddr));
		asz = sizeof(laddr);
		clientsocket = accept(ftpsocket, (struct sockaddr *)&laddr, &asz);
		if (clientsocket != INVALID_SOCKET) {
			rv = -1;
			for (i=0; i<g_cfg.MaxUsers; i++) {
				if ( scb[i] == INVALID_SOCKET ) {

					scb[i] = clientsocket;
					rv = pthread_create(&th, NULL, (__ptr_thread_start_routine)&ftp_client_thread, &scb[i]);
					if ( rv != 0 )
						scb[i] = INVALID_SOCKET;

					break;
				}
			}

			if ( rv != 0 ) {
				sendstring_plaintext(clientsocket, NOSLOTS);
				close(clientsocket);
			}
		}
	}

	free(scb);
	close(ftpsocket);

	return NULL;
}
