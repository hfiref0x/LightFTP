/*
 * ftpserv.c
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Jun 30, 2024
 *
 *      Author: lightftp
 */

#include "ftpserv.h"
#include "cfgparse.h"
#include "x_malloc.h"
#include "fspathtools.h"

static const FTPROUTINE_ENTRY ftpprocs[MAX_CMDS] = {
        {"USER", ftpUSER}, {"QUIT", ftpQUIT}, {"NOOP", ftpNOOP}, {"PWD",  ftpPWD },
        {"TYPE", ftpTYPE}, {"PORT", ftpPORT}, {"LIST", ftpLIST}, {"CDUP", ftpCDUP},
        {"CWD",  ftpCWD }, {"RETR", ftpRETR}, {"ABOR", ftpABOR}, {"DELE", ftpDELE},
        {"PASV", ftpPASV}, {"PASS", ftpPASS}, {"REST", ftpREST}, {"SIZE", ftpSIZE},
        {"MKD",  ftpMKD }, {"RMD",  ftpRMD }, {"STOR", ftpSTOR}, {"SYST", ftpSYST},
        {"FEAT", ftpFEAT}, {"APPE", ftpAPPE}, {"RNFR", ftpRNFR}, {"RNTO", ftpRNTO},
        {"OPTS", ftpOPTS}, {"MLSD", ftpMLSD}, {"AUTH", ftpAUTH}, {"PBSZ", ftpPBSZ},
        {"PROT", ftpPROT}, {"EPSV", ftpEPSV}, {"HELP", ftpHELP}, {"SITE", ftpSITE}
};

void *mlsd_thread(PTHCONTEXT tctx);
void *list_thread(PTHCONTEXT tctx);
int list_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry);
int mlsd_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry);
void *append_thread(PTHCONTEXT tctx);
void *stor_thread(PTHCONTEXT tctx);
void *retr_thread(PTHCONTEXT tctx);

/*
 * FTP_PASSCMD_INDEX
 * must be in sync with ftpprocs "PASS" index
 */
#define FTP_PASSCMD_INDEX   13

unsigned int g_newid = 0, g_threads = 0;
unsigned long long int g_client_sockets_created = 0, g_client_sockets_closed = 0;

static void cleanup_handler(void *arg)
{
    PTHCONTEXT tctx = (PTHCONTEXT)arg;

    pthread_mutex_unlock(&tctx->context->MTLock);
    free(tctx);
}

ssize_t sendstring_plaintext(SOCKET s, const char *Buffer)
{
    return (send(s, Buffer, strlen(Buffer), MSG_NOSIGNAL) >= 0);
}

void ftp_shutdown_tls_session(gnutls_session_t session)
{
    if (session != NULL) {
        gnutls_bye(session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session);
    }
}

int ftp_init_tls_session(gnutls_session_t *session, SOCKET s, int send_status)
{
    int ret;
    gnutls_session_t nsession = NULL;

    if (session == NULL)
        return 0;

    if (gnutls_init(&nsession, GNUTLS_SERVER | GNUTLS_NO_SIGNAL) < 0)
        return 0;

    if (gnutls_priority_set(nsession, priority_cache) < 0 ||
        gnutls_credentials_set(nsession, GNUTLS_CRD_CERTIFICATE, x509_cred) < 0) {
        gnutls_deinit(nsession);

        if (send_status)
            sendstring_plaintext(s, error500_auth);
        return 0;
    }

    gnutls_certificate_server_set_request(nsession, GNUTLS_CERT_IGNORE);
    gnutls_handshake_set_timeout(nsession, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    gnutls_transport_set_int2(nsession, s, s);
    gnutls_session_ticket_enable_server(nsession, &session_keys_storage);

    if (send_status)
        sendstring_plaintext(s, success234);

    do {
        ret = gnutls_handshake(nsession);
    } while (ret < 0 && !gnutls_error_is_fatal(ret));

    if (ret < 0) {
        gnutls_deinit(nsession);

        if (send_status)
            sendstring_plaintext(s, error500_auth);
        return 0;
    }

    *session = nsession;
    return 1;
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
    __attribute__((__unused__)) size_t r;

    if ( g_log != -1 )
        r = write(g_log, Buffer, l);

    return write(STDOUT_FILENO, Buffer, l);
}

int writelogentry(PFTPCONTEXT context, const char *logtext1, const char *logtext2)
{
    char		text[2*PATH_MAX];
    time_t		itm = time(NULL);
    struct tm	ltm;

    localtime_r(&itm, &ltm);

    if (context == NULL)
    {
        snprintf(text, sizeof(text), "%02u-%02u-%u %02u:%02u:%02u : %s%s\r\n",
                ltm.tm_mday, ltm.tm_mon+1, ltm.tm_year+1900,
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec, logtext1, logtext2);
    }
    else
    {
        snprintf(text, sizeof(text), "%02u-%02u-%u %02u:%02u:%02u S-id=%u : %s%s\r\n",
                ltm.tm_mday, ltm.tm_mon+1, ltm.tm_year+1900,
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec,
                context->SessionID, logtext1, logtext2);
    }

    return writeconsolestr(text);
}

void worker_thread_cleanup(PFTPCONTEXT context)
{
    int					err;
    void				*retv = NULL;
    struct timespec     timeout;

    if ( context->WorkerThreadValid == 0 ) {
        context->WorkerThreadAbort = 1;

        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 2;

        if ( context->DataSocket != INVALID_SOCKET ) {
          close(context->DataSocket);
          context->DataSocket = INVALID_SOCKET;
        }

        if ( context->hFile != -1 ) {
          close(context->hFile);
          context->hFile = -1;
        }

        context->DataIPv4 = 0;
        context->DataPort = 0;

        if ( context->WorkerThreadValid == -1 )
          return;

        err = pthread_timedjoin_np(context->WorkerThreadId, &retv, &timeout);
        if (err != 0) {
            writelogentry(context, "Thread didn't exit, canceling", "");
            if (pthread_cancel(context->WorkerThreadId) != 0) {
                writelogentry(context, "Thread cancel failed", "");
            } else {
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += 2;
            	err = pthread_timedjoin_np(context->WorkerThreadId, &retv, &timeout);
                if (err != 0) {
                	writelogentry(context, "Thread didn't exit after cancel", "");
                }
            }
        }

        context->WorkerThreadValid = -1;
    }
}

void worker_thread_start(PFTPCONTEXT context, PSTARTROUTINE fn)
{
    pthread_t       tid;
    PTHCONTEXT      tctx;

    context->WorkerThreadAbort = 0;
    pthread_mutex_lock(&context->MTLock);

    tctx = x_malloc(sizeof(THCONTEXT));
    tctx->context = context;
    tctx->FnType = 0;
    strncpy(tctx->thFileName, context->FileName, sizeof(tctx->thFileName) - 1);

    context->WorkerThreadValid = pthread_create(&tid, NULL, (void * (*)(void *))fn, tctx);
    if ( context->WorkerThreadValid == 0 )
        context->WorkerThreadId = tid;
    else
    {
        free(tctx);
        sendstring(context, error451);
    }

    pthread_mutex_unlock(&context->MTLock);
}

int ftpUSER(PFTPCONTEXT context, const char *params)
{
    char text[PATH_MAX];

    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(text, sizeof(text), "331 User %s OK. Password required\r\n", params);
    sendstring(context, text);

    /* Save login name to UserName for the next PASS command */
    strncpy(context->UserName, params, sizeof(context->UserName) - 1);
    context->UserName[sizeof(context->UserName) - 1] = '\0';
    return 1;
}

int ftpQUIT(PFTPCONTEXT context, const char *params)
{
    char text[PATH_MAX];

    writelogentry(context, " QUIT", "");
    snprintf(text, sizeof(text), "221 %s\r\n", GOODBYE_MSG);
    /* sendstring(context, success221); */
    sendstring(context, text);

    /* return 0 to break command processing loop */
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

    snprintf(context->FileName, sizeof(context->FileName), "257 \"%s\" is a current directory.\r\n", context->CurrentDir);
    return sendstring(context, context->FileName);
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

    default:
        return sendstring(context, error501);
    }
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

/*
filemode.c -- make a string describing file modes

  Copyright (C) 1985, 1990, 1993, 1998-2000, 2004, 2006, 2009-2018 Free
  Software Foundation, Inc.
 */

/* Return a character indicating the type of file described by
   file mode BITS:
   '-' regular file
   'b' block special file
   'c' character special file
   'C' high performance ("contiguous data") file
   'd' directory
   'D' door
   'l' symbolic link
   'm' multiplexed file (7th edition Unix; obsolete)
   'n' network special file (HP-UX)
   'p' fifo (named pipe)
   'P' port
   's' socket
   'w' whiteout (4.4BSD)
   '?' some other file type  */

static char
ftypelet (mode_t bits)
{
    /* These are the most common, so test for them first.  */
    if (S_ISREG (bits))
        return '-';
    if (S_ISDIR (bits))
        return 'd';

    /* Other letters standardized by POSIX 1003.1-2004.  */
    if (S_ISBLK (bits))
        return 'b';
    if (S_ISCHR (bits))
        return 'c';
    if (S_ISLNK (bits))
        return 'l';
    if (S_ISFIFO (bits))
        return 'p';

    /* Other file types (though not letters) standardized by POSIX.  */
    if (S_ISSOCK (bits))
        return 's';

    return '?';
}

/* Like filemodestring, but rely only on MODE.  */

void
strmode (mode_t mode, char *str)
{
    str[0] = ftypelet (mode);
    str[1] = mode & S_IRUSR ? 'r' : '-';
    str[2] = mode & S_IWUSR ? 'w' : '-';
    str[3] = (mode & S_ISUID
            ? (mode & S_IXUSR ? 's' : 'S')
                    : (mode & S_IXUSR ? 'x' : '-'));
    str[4] = mode & S_IRGRP ? 'r' : '-';
    str[5] = mode & S_IWGRP ? 'w' : '-';
    str[6] = (mode & S_ISGID
            ? (mode & S_IXGRP ? 's' : 'S')
                    : (mode & S_IXGRP ? 'x' : '-'));
    str[7] = mode & S_IROTH ? 'r' : '-';
    str[8] = mode & S_IWOTH ? 'w' : '-';
    str[9] = (mode & S_ISVTX
            ? (mode & S_IXOTH ? 't' : 'T')
                    : (mode & S_IXOTH ? 'x' : '-'));
    str[10] = ' ';
    str[11] = '\0';
}

/*
	END  filemode.c
 */

int list_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
{
    char			text[2*PATH_MAX], sacl[12];
    struct stat		filestats;
    struct tm		ftm_fields;
    time_t			deltatime;

    if (strcmp(entry->d_name, ".") == 0)
        return 1;
    if (strcmp(entry->d_name, "..") == 0)
        return 1;

    snprintf(text, sizeof(text), "%s/%s", dirname, entry->d_name);

    if ( lstat(text, &filestats) == 0 )
    {
        strmode(filestats.st_mode, sacl);

        localtime_r(&filestats.st_mtime, &ftm_fields);
        deltatime = time(NULL) - filestats.st_mtime;

        if (deltatime <= 180*24*60*60) {
            snprintf(text, sizeof(text), "%s %lu %lu %lu %llu %s %02u %02u:%02u %s\r\n",
                    sacl, filestats.st_nlink,
                    (unsigned long int)filestats.st_uid,
                    (unsigned long int)filestats.st_gid,
                    (unsigned long long int)filestats.st_size,
                    shortmonths[(ftm_fields.tm_mon)], ftm_fields.tm_mday,
                    ftm_fields.tm_hour, ftm_fields.tm_min, entry->d_name);
        }
        else
        {
            snprintf(text, sizeof(text), "%s %lu %lu %lu %llu %s %02u %02u %s\r\n",
                    sacl, filestats.st_nlink,
                    (unsigned long int)filestats.st_uid,
                    (unsigned long int)filestats.st_gid,
                    (unsigned long long int)filestats.st_size,
                    shortmonths[(ftm_fields.tm_mon)], ftm_fields.tm_mday,
                    ftm_fields.tm_year + 1900, entry->d_name);
        }

    }

    return sendstring_auto(s, session, text);
}

void *list_thread(PTHCONTEXT tctx)
{
    volatile SOCKET     clientsocket;
    gnutls_session_t	TLS_datasession;
    int					ret;
    DIR					*pdir;
    struct dirent		*entry;
    PFTPCONTEXT         context = tctx->context;

    pthread_detach(pthread_self());
    pthread_mutex_lock(&context->MTLock);
    pthread_cleanup_push(cleanup_handler, tctx);
    ret = 0;
    TLS_datasession = NULL;

    clientsocket = create_datasocket(context);
    while (clientsocket != INVALID_SOCKET)
    {
        if (context->TLS_session != NULL)
            if (!ftp_init_tls_session(&TLS_datasession, clientsocket, 0))
                break;

        pdir = opendir(tctx->thFileName);
        if (pdir == NULL)
            break;

        while ((entry = readdir(pdir)) != NULL) {
            if (tctx->FnType == LIST_TYPE_MLSD)
                ret = mlsd_sub(tctx->thFileName, clientsocket, TLS_datasession, entry);
            else
                ret = list_sub(tctx->thFileName, clientsocket, TLS_datasession, entry);
            if ( (ret == 0) || (context->WorkerThreadAbort != 0 ))
                break;
        }

        closedir(pdir);
        break;
    }

    ftp_shutdown_tls_session(TLS_datasession);

    writelogentry(context, " LIST/MLSD complete", "");

    if (clientsocket == INVALID_SOCKET) {
        sendstring(context, error451);
    }
    else {
        if ((context->WorkerThreadAbort == 0) && (ret != 0))
            sendstring(context, success226);
        else
            sendstring(context, error426);

        close(clientsocket);
        context->DataSocket = INVALID_SOCKET;
    }

    context->WorkerThreadValid = -1;
    pthread_cleanup_pop(0);
    free(tctx);
    pthread_mutex_unlock(&context->MTLock);
    return NULL;
}

int ftpLIST(PFTPCONTEXT context, const char *params)
{
    struct  stat    filestats;

    if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if ((context->WorkerThreadValid == 0) || (context->hFile != -1))
        return sendstring(context, error550_t);

    if (params != NULL)
    {
        if ((strcmp(params, "-a") == 0) || (strcmp(params, "-l") == 0))
            params = NULL;
    }

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " LIST", (char *)params);
        worker_thread_start(context, list_thread);
        return 1;
    }

    return sendstring(context, error550);
}

/*
 * Cuts off filename from string leaving only path.
 * Return value: pointer to a terminating null character at the end of path
 */

int ftpCDUP(PFTPCONTEXT context, const char *params)
{
    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( strcmp(context->CurrentDir, "/") == 0 )
        return sendstring(context, success250);

    filepath(context->CurrentDir);

    writelogentry(context, " CDUP", "");
    return sendstring(context, success250);
}

int ftpCWD(PFTPCONTEXT context, const char *params)
{
    struct	stat	filestats;

    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    if ( stat(context->FileName, &filestats) == 0 )
        if ( S_ISDIR(filestats.st_mode) )
        {
            ftp_effective_path("/", context->CurrentDir, params, sizeof(context->FileName), context->FileName);
            memset(context->CurrentDir, 0, sizeof(context->CurrentDir));
            strncpy(context->CurrentDir, context->FileName, sizeof(context->CurrentDir)-1);
            writelogentry(context, " CWD: ", context->CurrentDir);
            return sendstring(context, success250);
        }

    return sendstring(context, error550);
}

void *retr_thread(PTHCONTEXT tctx)
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
    PFTPCONTEXT         context = tctx->context;

    pthread_detach(pthread_self());
    pthread_mutex_lock(&context->MTLock);
    pthread_cleanup_push(cleanup_handler, tctx);

    f = -1;
    sent_ok = 0;
    sz_total = 0;
    buffer = NULL;
    TLS_datasession = NULL;
    clientsocket = INVALID_SOCKET;
    clock_gettime(CLOCK_MONOTONIC, &t);
    lt0 = t.tv_sec*1000000000ll + t.tv_nsec;
    dtx = t.tv_sec+30;

    buffer = x_malloc(TRANSMIT_BUFFER_SIZE);
    while (buffer != NULL)
    {
        clientsocket = create_datasocket(context);
        if (clientsocket == INVALID_SOCKET)
            break;

        if (context->TLS_session != NULL)
        {
            if (!ftp_init_tls_session(&TLS_datasession, clientsocket, 0))
                break;

            buffer_size = gnutls_record_get_max_size(TLS_datasession);
            if (buffer_size > TRANSMIT_BUFFER_SIZE)
                buffer_size = TRANSMIT_BUFFER_SIZE;
        }
        else
            buffer_size = TRANSMIT_BUFFER_SIZE;

        f = open(tctx->thFileName, O_RDONLY);
        context->hFile = f;
        if (f == -1)
            break;

        offset = lseek(f, context->RestPoint, SEEK_SET);
        if (offset != context->RestPoint)
            break;

        sent_ok = 1;
        while ( context->WorkerThreadAbort == 0 ) {
            sz = read(f, buffer, buffer_size);
            if (sz == 0)
                break;

            if (sz < 0)
            {
                sent_ok = 0;
                break;
            }

            if (send_auto(clientsocket, TLS_datasession, buffer, sz) == sz)
            {
                sz_total += sz;
            }
            else
            {
                sent_ok = 0;
                break;
            }
        }

        /* calculating performance */

        clock_gettime(CLOCK_MONOTONIC, &t);
        lt1 = t.tv_sec*1000000000ll + t.tv_nsec;
        dtx = lt1 - lt0;

        context->Stats.DataTx += sz_total;
        ++context->Stats.FilesTx;

        snprintf(buffer, buffer_size, " RETR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
                sz_total, sz_total/1048576.0f, dtx/1000000000.0f, (1000000000.0f*sz_total)/dtx/1048576.0f);
        writelogentry(context, buffer, "");

        break;
    }

    if (f != -1)
        close(f);

    context->hFile = -1;

    if (buffer != NULL) {
        free(buffer);
    }

    ftp_shutdown_tls_session(TLS_datasession);

    if (clientsocket == INVALID_SOCKET) {
        sendstring(context, error451);
    }
    else {
        if ((context->WorkerThreadAbort == 0) && (sent_ok != 0))
            sendstring(context, success226);
        else
            sendstring(context, error426);

        close(clientsocket);
        context->DataSocket = INVALID_SOCKET;
    }

    context->WorkerThreadValid = -1;
    pthread_cleanup_pop(0);
    free(tctx);
    pthread_mutex_unlock(&context->MTLock);
    return NULL;
}

int ftpRETR(PFTPCONTEXT context, const char *params)
{
    struct	stat	filestats;

    if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if ( params == NULL )
        return sendstring(context, error501);
    if ((context->WorkerThreadValid == 0) || (context->hFile != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISREG(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " RETR: ", (char *)params);
        worker_thread_start(context, retr_thread);
        return 1;
    }

    return sendstring(context, error550);
}

int ftpABOR(PFTPCONTEXT context, const char *params)
{
    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    writelogentry(context, " ABORT command", NULL);
    worker_thread_cleanup(context);
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

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    if ( unlink(context->FileName) == 0 ) {
        sendstring(context, success250);
        writelogentry(context, " DELE: ", (char *)params);
    }
    else
        sendstring(context, error550_r);

    return 1;
}

int pasv(PFTPCONTEXT context)
{
    SOCKET				datasocket;
    struct sockaddr_in	laddr;
    int					socketret = -1, result = 0;
    unsigned long		c;
    struct	timespec	rtctime;

    while (1)
    {
        if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        {
            sendstring(context, error530);
            break;
        }

        if ( context->WorkerThreadValid == 0 )
        {
            sendstring(context, error550_t);
            break;
        }

        if ( context->DataSocket != INVALID_SOCKET )
            close(context->DataSocket);

        context->DataSocket = INVALID_SOCKET;

        datasocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (datasocket == INVALID_SOCKET)
        {
            sendstring(context, error451);
            break;
        }

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
            sendstring(context, error451);
            break;
        }

        socketret = listen(datasocket, SOMAXCONN);
        if (socketret != 0) {
            close(datasocket);
            sendstring(context, error451);
            break;
        }

        if ((context->ClientIPv4 & g_cfg.LocalIPMask) == (context->ServerIPv4 & g_cfg.LocalIPMask))
        {
            context->DataIPv4 = context->ServerIPv4;
            writelogentry(context, " local client.", "");
        } else {
            context->DataIPv4 = g_cfg.ExternalInterface;
            writelogentry(context, " nonlocal client.", "");
        }

        context->DataPort = laddr.sin_port;
        context->DataSocket = datasocket;
        context->Mode = MODE_PASSIVE;

        result = 1;
        break;
    }

    return result;
}

int ftpEPSV (PFTPCONTEXT context, const char *params)
{
    if (pasv(context) == 0)
        return 1;

    snprintf(context->FileName, sizeof(context->FileName),
            "229 Entering Extended Passive Mode (|||%u|)\r\n",
            ntohs(context->DataPort));

    writelogentry(context, " entering extended passive mode", "");

    return sendstring(context, context->FileName);
}

int ftpPASV(PFTPCONTEXT context, const char *params)
{
    if (pasv(context) == 0)
        return 1;

    snprintf(context->FileName, sizeof(context->FileName),
            "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u).\r\n",
            context->DataIPv4 & 0xff,
            (context->DataIPv4 >> 8) & 0xff,
            (context->DataIPv4 >> 16) & 0xff,
            (context->DataIPv4 >> 24) & 0xff,
            context->DataPort & 0xff,
            (context->DataPort >> 8) & 0xff);

    writelogentry(context, " entering passive mode", "");

    return sendstring(context, context->FileName);
}

int ftpPASS(PFTPCONTEXT context, const char *params)
{
    volatile char temptext[PATH_MAX];

    if ( params == NULL )
        return sendstring(context, error501);

    memset(temptext, 0, sizeof(temptext));

    /*
     * we have login name saved in context->UserName from USER command
     */
    if (!config_parse(g_cfg.ConfigFile, context->UserName, "pswd", temptext, sizeof(temptext)))
        return sendstring(context, error530_r);

    if ( (strcmp(temptext, params) == 0) || (temptext[0] == '*') )
    {
        memset(context->RootDir, 0, sizeof(context->RootDir));
        memset(temptext, 0, sizeof(temptext));

        config_parse(g_cfg.ConfigFile, context->UserName, "root", context->RootDir, sizeof(context->RootDir));
        config_parse(g_cfg.ConfigFile, context->UserName, "accs", temptext, sizeof(temptext));

        context->Access = FTP_ACCESS_NOT_LOGGED_IN;
        do {

            if ( strcasecmp(temptext, "admin") == 0 ) {
                context->Access = FTP_ACCESS_FULL;
                break;
            }

            if ( strcasecmp(temptext, "upload") == 0 ) {
                context->Access = FTP_ACCESS_CREATENEW;
                break;
            }

            if ( strcasecmp(temptext, "readonly") == 0 ) {
                context->Access = FTP_ACCESS_READONLY;
                break;
            }

            return sendstring(context, error530_b);
        } while (0);

        writelogentry(context, " PASS->successful logon", "");
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
    snprintf(context->FileName, sizeof(context->FileName),
            "350 REST supported. Ready to resume at byte offset %llu\r\n",
            (unsigned long long int)context->RestPoint);

    return sendstring(context, context->FileName);
}

int ftpSIZE(PFTPCONTEXT context, const char *params)
{
    struct stat		filestats;

    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    if ( stat(context->FileName, &filestats) == 0 )
    {
        snprintf(context->FileName, sizeof(context->FileName), "213 %llu\r\n",
                (unsigned long long int)filestats.st_size);
        sendstring(context, context->FileName);
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

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    if ( mkdir(context->FileName, 0755) == 0 ) {
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

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    if ( rmdir(context->FileName) == 0 ) {
        sendstring(context, success250);
        writelogentry(context, " DELE: ", (char *)params);
    }
    else
        sendstring(context, error550_r);

    return 1;
}

void *stor_thread(PTHCONTEXT tctx)
{
    volatile SOCKET     clientsocket;
    int					f;
    ssize_t				wsz, sz, sz_total;
    size_t				buffer_size;
    char				*buffer;
    struct timespec		t;
    signed long long	lt0, lt1, dtx;
    gnutls_session_t	TLS_datasession;
    PFTPCONTEXT         context = tctx->context;

    pthread_detach(pthread_self());
    pthread_mutex_lock(&context->MTLock);
    pthread_cleanup_push(cleanup_handler, tctx);

    f = -1;
    sz_total = 0;
    buffer = NULL;
    TLS_datasession = NULL;
    clientsocket = INVALID_SOCKET;
    clock_gettime(CLOCK_MONOTONIC, &t);
    lt0 = t.tv_sec*1000000000ll + t.tv_nsec;
    dtx = t.tv_sec+30;

    buffer = x_malloc(TRANSMIT_BUFFER_SIZE);
    while (buffer != NULL)
    {
        clientsocket = create_datasocket(context);
        if (clientsocket == INVALID_SOCKET)
            break;

        if (context->TLS_session != NULL)
        {
            if (!ftp_init_tls_session(&TLS_datasession, clientsocket, 0))
                break;

            buffer_size = gnutls_record_get_max_size(TLS_datasession);
            if (buffer_size > TRANSMIT_BUFFER_SIZE)
                buffer_size = TRANSMIT_BUFFER_SIZE;
        }
        else
            buffer_size = TRANSMIT_BUFFER_SIZE;

        if (tctx->FnType == STOR_TYPE_APPEND)
            f = open(tctx->thFileName, O_RDWR);
        else
            f = open(tctx->thFileName, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

        context->hFile = f;
        if (f == -1)
            break;

        lseek(f, 0, SEEK_END);

        while ( context->WorkerThreadAbort == 0 ) {
            sz = recv_auto(clientsocket, TLS_datasession, buffer, buffer_size);
            if (sz > 0)
            {
                sz_total += sz;
                wsz = write(f, buffer, sz);
                if (wsz != sz)
                    break;
            }
            else
                break;
        }

        /* calculating performance */

        clock_gettime(CLOCK_MONOTONIC, &t);
        lt1 = t.tv_sec*1000000000ll + t.tv_nsec;
        dtx = lt1 - lt0;

        context->Stats.DataRx += sz_total;
        ++context->Stats.FilesRx;

        snprintf(buffer, buffer_size, " STOR/APPEND complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
                sz_total, sz_total/1048576.0f, dtx/1000000000.0f, (1000000000.0f*sz_total)/dtx/1048576.0f);
        writelogentry(context, buffer, "");

        break;
    }

    if (f != -1)
        close(f);

    context->hFile = -1;

    if (buffer != NULL) {
        free(buffer);
    }

    ftp_shutdown_tls_session(TLS_datasession);

    if (clientsocket == INVALID_SOCKET) {
        sendstring(context, error451);
    }
    else {
        if (context->WorkerThreadAbort == 0)
            sendstring(context, success226);
        else
            sendstring(context, error426);

        close(clientsocket);
        context->DataSocket = INVALID_SOCKET;
    }

    context->WorkerThreadValid = -1;
    pthread_cleanup_pop(0);
    free(tctx);
    pthread_mutex_unlock(&context->MTLock);
    return NULL;
}

int ftpSTOR(PFTPCONTEXT context, const char *params)
{
    struct  stat    filestats;

    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->Access < FTP_ACCESS_CREATENEW )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);
    if ((context->WorkerThreadValid == 0) || (context->hFile != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    /* check: do not overwrite existing files if not full access */
    if ( stat(context->FileName, &filestats) == 0 )
    {
        if ( context->Access != FTP_ACCESS_FULL )
            return sendstring(context, error550_r);
        /* is it a regular file? */
        if ( !S_ISREG(filestats.st_mode) )
            return sendstring(context, error550);
    }

    sendstring(context, interm150);
    writelogentry(context, " STOR: ", (char *)params);
    worker_thread_start(context, stor_thread);
    return 1;
}

int ftpSYST(PFTPCONTEXT context, const char *params)
{
    return sendstring(context, success215);
}

int ftpHELP(PFTPCONTEXT context, const char *params)
{
    return sendstring(context, success214);
}

int isoctaldigit(char c)
{
    return ((c >= '0') && (c < '8'));
}

int parseCHMOD(PFTPCONTEXT context, const char* params)
{
    mode_t flags = 0;

    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->Access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);

    while (isoctaldigit(*params))
    {
        flags <<= 3;
        flags += ((unsigned int)*params) - (unsigned int)'0';
        ++params;
    }

    if (*params != ' ')
        return 0;

    while (*params == ' ')
        ++params;

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);
    return (chmod(context->FileName, flags) == 0);
}

int ftpSITE(PFTPCONTEXT context, const char *params)
{
    if ( params != NULL )
    {
        if (strcasecmp(params, "help") == 0)
            return sendstring(context, "200 chmod\r\n");

        if (strncasecmp(params, "chmod ", 6) == 0)
        {
            if (parseCHMOD(context, &params[6]))
                return sendstring(context, "200 chmod OK\r\n");

            return sendstring(context, error501);
        }
    }

    return sendstring(context, error500);
}

int ftpFEAT(PFTPCONTEXT context, const char *params)
{
    return sendstring(context, success211);
}

void *append_thread(PTHCONTEXT tctx)
{
    tctx->FnType = STOR_TYPE_APPEND;
    return stor_thread(tctx);
}

int ftpAPPE(PFTPCONTEXT context, const char *params)
{
    struct	stat	filestats;

    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->Access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);
    if ((context->WorkerThreadValid == 0) || (context->hFile != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    /* stat must NOT fail */
    while (stat(context->FileName, &filestats) == 0)
    {
        /* do not try to "append" for directories */
        if ( !S_ISREG(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " APPE: ", (char *)params);
        worker_thread_start(context, append_thread);
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

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->RnFrom), context->RnFrom);

    if ( stat(context->RnFrom, &filestats) == 0 )
    {
        writelogentry(context, " RNFR: ", context->RnFrom);
        sendstring(context, interm350_ren);
    }
    else
        sendstring(context, error550);

    return 1;
}

int ftpRNTO(PFTPCONTEXT context, const char *params)
{
    if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->Access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);
    if ( rename(context->RnFrom, context->FileName) == 0 )
    {
        writelogentry(context, " RNTO: ", context->FileName);
        sendstring(context, success250);
    }
    else
        sendstring(context, error550);

    memset(&context->RnFrom, 0, sizeof(context->RnFrom));
    return 1;
}

int ftpOPTS(PFTPCONTEXT context, const char *params)
{
    if ( params != NULL )
        if (strcasecmp(params, "utf8 on") == 0)
            return sendstring(context, "200 Always in UTF8 mode.\r\n");

    writelogentry(context, " unsupported OPTS: ", params);
    return sendstring(context, error500);
}

int ftpAUTH(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    if ( strcasecmp(params, "TLS") == 0 )
    {
        /* ftp_init_tls_session will send a status reply */
        ftp_init_tls_session(&context->TLS_session, context->ControlSocket, 1);
        return 1;
    }
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
    char			text[2*PATH_MAX], *entrytype, *sizetype;
    struct stat		filestats;
    struct tm		ftm_fields;

    if (strcmp(entry->d_name, ".") == 0)
        return 1;
    if (strcmp(entry->d_name, "..") == 0)
        return 1;

    snprintf(text, sizeof(text), "%s/%s", dirname, entry->d_name);

    if ( lstat(text, &filestats) == 0 )
    {
        if ( S_ISDIR(filestats.st_mode) )
        {
            entrytype = "dir";
            sizetype = "sizd";
        }
        else
        {
            entrytype = "file";
            sizetype = "size";
        }

        if (S_ISLNK(filestats.st_mode))
        {
            entrytype = "OS.unix=slink";
        }

        localtime_r(&filestats.st_mtime, &ftm_fields);
        ++ftm_fields.tm_mon;

        snprintf(text, sizeof(text),
                "type=%s;%s=%llu;UNIX.mode=%lo;UNIX.owner=%lu;UNIX.group=%lu;modify=%u%02u%02u%02u%02u%02u; %s\r\n",
                entrytype, sizetype,
                (unsigned long long int)filestats.st_size,
                (unsigned long int)filestats.st_mode,
                (unsigned long int)filestats.st_uid,
                (unsigned long int)filestats.st_gid,
                ftm_fields.tm_year + 1900, ftm_fields.tm_mon, ftm_fields.tm_mday,
                ftm_fields.tm_hour, ftm_fields.tm_min, ftm_fields.tm_sec, entry->d_name
        );
    }

    return sendstring_auto(s, session, text);
}

void *mlsd_thread(PTHCONTEXT tctx)
{
    tctx->FnType = LIST_TYPE_MLSD;
    return list_thread(tctx);
}

int ftpMLSD(PFTPCONTEXT context, const char *params)
{
    struct  stat    filestats;

    if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if ((context->WorkerThreadValid == 0) || (context->hFile != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " MLSD-LIST ", (char *)params);
        worker_thread_start(context, mlsd_thread);
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
        if (p >= (ssize_t)buffer_size) {
            buffer[p-1] = 0;
            return 0;
        }

        if ( p >= 2 )
            if ( (buffer[p-2] == '\r') && (buffer[p-1] == '\n') )
            {
                buffer[p-2] = 0;
                return 1;
            }
    }

    buffer[buffer_size-1] = 0;
    return 0;
}

void *ftp_client_thread(SOCKET s)
{
    FTPCONTEXT				ctx __attribute__ ((aligned (16)));
    char					*cmd, *params, rcvbuf[PATH_MAX];
    int						c, cmdno, rv, tn;
    size_t					i, cmdlen;
    socklen_t				asz;
    struct sockaddr_in		laddr;
    pthread_mutexattr_t		m_attr;

    pthread_detach(pthread_self());
    memset(&rcvbuf, 0, sizeof(rcvbuf));
    memset(&ctx, 0, sizeof(ctx));

    ctx.Access = FTP_ACCESS_NOT_LOGGED_IN;
    ctx.ControlSocket = s;
    ctx.SessionID = __sync_add_and_fetch(&g_newid, 1);
    tn = __sync_add_and_fetch(&g_threads, 1);
    snprintf(rcvbuf, sizeof(rcvbuf), "<- New thread. Thread counter g_threads=%i", tn);
    writelogentry(&ctx, rcvbuf, "");

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
        ctx.WorkerThreadAbort = 1;
        ctx.WorkerThreadValid = -1;
        ctx.hFile = -1;
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

        snprintf(rcvbuf, sizeof(rcvbuf), "<- New user IP=%u.%u.%u.%u:%u",
                laddr.sin_addr.s_addr & 0xff,
                (laddr.sin_addr.s_addr >> 8 ) & 0xff,
                (laddr.sin_addr.s_addr >> 16 ) & 0xff,
                (laddr.sin_addr.s_addr >> 24 ) & 0xff,
                ntohs(laddr.sin_port)
        );

        writelogentry(&ctx, rcvbuf, "");

        while ( ctx.ControlSocket != INVALID_SOCKET ) {
            if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) )
                break;

            i = 0;
            while ((rcvbuf[i] != 0) && (isalpha(rcvbuf[i]) == 0))
                ++i;

            cmd = &rcvbuf[i];
            while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' '))
                ++i;

            cmdlen = &rcvbuf[i] - cmd;
            while (rcvbuf[i] == ' ')
                ++i;

            if (rcvbuf[i] == 0)
                params = NULL;
            else
                params = &rcvbuf[i];

            cmdno = -1;
            rv = 1;
            for (c=0; c<MAX_CMDS; c++)
                if (strncasecmp(cmd, ftpprocs[c].Name, cmdlen) == 0)
                {
                    cmdno = c;
                    rv = ftpprocs[c].Proc(&ctx, params);
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

        worker_thread_cleanup(&ctx);

        pthread_mutex_destroy(&ctx.MTLock);
        pthread_mutexattr_destroy(&m_attr);
        snprintf(rcvbuf, sizeof(rcvbuf),
            " User disconnected. \n==== Session %u statistics ====\n"
            "Rx: %zd bytes (%f MBytes) total received by server in %zd files,\n"
            "Tx: %zd bytes (%f MBytes) total sent to the client in %zd files.\n",
            ctx.SessionID,
            ctx.Stats.DataRx, ctx.Stats.DataRx / 1048576.0f, ctx.Stats.FilesRx,
            ctx.Stats.DataTx, ctx.Stats.DataTx / 1048576.0f, ctx.Stats.FilesTx);

        writelogentry(&ctx, rcvbuf, "");
        break;
    }

    ftp_shutdown_tls_session(ctx.TLS_session);

    close(ctx.ControlSocket);
    __sync_add_and_fetch(&g_client_sockets_closed, 1);
    tn = __sync_sub_and_fetch(&g_threads, 1);
    snprintf(rcvbuf, sizeof(rcvbuf), "<- Thread exit. Thread counter g_threads=%i", tn);
    writelogentry(&ctx, rcvbuf, "");

    return NULL;
}

void socket_set_keepalive(int s) {
    int opt = 1;

    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) != 0)
    {
        printf("\r\n SO_KEEPALIVE set failed.\r\n");
        return;
    }

    opt = 16; /* set idle status after 16 seconds since last data transfer */;
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));

    opt = 16; /* send keep alive packet every 16 seconds */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));

    opt = 8; /* drop after 8 unanswered packets */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt));
}

void *ftpmain(void *p)
{
    struct  sockaddr_in laddr;

    int     ftpsocket = INVALID_SOCKET,
            clientsocket,
            socketret,
            rv;

    socklen_t       asz;
    pthread_t       th;
    char            text[512];

    ftpsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( ftpsocket == INVALID_SOCKET )
    {
        printf("\r\n socket create error\r\n");
        return 0;
    }

    rv = 1;
    setsockopt(ftpsocket, SOL_SOCKET, SO_REUSEADDR, &rv, sizeof(rv));

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(g_cfg.Port);
    laddr.sin_addr.s_addr = g_cfg.BindToInterface;
    socketret = bind(ftpsocket, (struct sockaddr *)&laddr, sizeof(laddr));
    if  ( socketret != 0 ) {
        printf("\r\n Failed to start server. Can not bind to address\r\n\r\n");
        close(ftpsocket);
        return 0;
    }

    writelogentry(NULL, success220, "");

    socketret = listen(ftpsocket, SOMAXCONN);
    while ( socketret == 0 ) {

        memset(&laddr, 0, sizeof(laddr));
        asz = sizeof(laddr);
        clientsocket = accept(ftpsocket, (struct sockaddr *)&laddr, &asz);
        if (clientsocket == INVALID_SOCKET)
            continue;

        __sync_add_and_fetch(&g_client_sockets_created, 1);

        rv = -1;
        if (g_threads < g_cfg.MaxUsers)
        {
            if (g_cfg.EnableKeepalive != 0)
                socket_set_keepalive(clientsocket);

            rv = pthread_create(&th, NULL, (void * (*)(void *))ftp_client_thread, (void *)clientsocket);
            if (rv != 0)
                sendstring_plaintext(clientsocket, error451);
        }
        else
        {
            sendstring_plaintext(clientsocket, error451_max);
        }

        if (rv != 0)
        {
            close(clientsocket);
            __sync_add_and_fetch(&g_client_sockets_closed, 1);
        }

        snprintf(text, sizeof(text),
                "MAIN LOOP stats: g_threads=%i, g_cfg.MaxUsers=%i, g_client_sockets_created=%llu, g_client_sockets_closed=%llu\r\n",
                g_threads, g_cfg.MaxUsers, g_client_sockets_created, g_client_sockets_closed);

        writelogentry(NULL, text, "");
    }

    close(ftpsocket);

    return NULL;
}
