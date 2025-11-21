/*
 * ftpserv.c
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Nov 08, 2025
 *
 *      Author: lightftp
 */

#include "inc/ftpserv.h"
#include "inc/cfgparse.h"
#include "inc/x_malloc.h"
#include "inc/fspathtools.h"
#include "inc/sha256sum.h"

static const ftproutine_entry ftpprocs[MAX_CMDS] = {
        {"USER", ftpUSER}, {"QUIT", ftpQUIT}, {"NOOP", ftpNOOP}, {"PWD",  ftpPWD },
        {"TYPE", ftpTYPE}, {"PORT", ftpPORT}, {"LIST", ftpLIST}, {"CDUP", ftpCDUP},
        {"CWD",  ftpCWD }, {"RETR", ftpRETR}, {"ABOR", ftpABOR}, {"DELE", ftpDELE},
        {"PASV", ftpPASV}, {"PASS", ftpPASS}, {"REST", ftpREST}, {"SIZE", ftpSIZE},
        {"MKD",  ftpMKD }, {"RMD",  ftpRMD }, {"STOR", ftpSTOR}, {"SYST", ftpSYST},
        {"FEAT", ftpFEAT}, {"APPE", ftpAPPE}, {"RNFR", ftpRNFR}, {"RNTO", ftpRNTO},
        {"OPTS", ftpOPTS}, {"MLSD", ftpMLSD}, {"AUTH", ftpAUTH}, {"PBSZ", ftpPBSZ},
        {"PROT", ftpPROT}, {"EPSV", ftpEPSV}, {"HELP", ftpHELP}, {"SITE", ftpSITE}
};

void *mlsd_thread(pthcontext tctx);
void *list_thread(pthcontext tctx);
ssize_t list_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry);
ssize_t mlsd_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry);
void *append_thread(pthcontext tctx);
void *stor_thread(pthcontext tctx);
void *retr_thread(pthcontext tctx);

/*
 * FTP_PASSCMD_INDEX
 * must be in sync with ftpprocs "PASS" index
 */
#define FTP_PASSCMD_INDEX   13

#define WORKER_CLEANUP_TIMEOUT_NS   500000000
#define KEEPALIVE_IDLE_SEC          16
#define KEEPALIVE_INTERVAL_SEC      16
#define KEEPALIVE_PROBE_COUNT       8

unsigned int g_newid = 0, g_threads = 0;
unsigned long long int g_client_sockets_created = 0, g_client_sockets_closed = 0;

static void cleanup_handler(void *arg)
{
    pthcontext tctx = (pthcontext)arg;
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

SOCKET create_datasocket(pftp_context context)
{
    SOCKET				client_socket = INVALID_SOCKET;
    struct sockaddr_in	laddr;
    socklen_t			asz;

    memset(&laddr, 0, sizeof(laddr));

    switch ( context->mode ) {
    case MODE_NORMAL:
        client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        context->data_socket = client_socket;
        if ( client_socket == INVALID_SOCKET )
            return INVALID_SOCKET;

        laddr.sin_family = AF_INET;
        laddr.sin_port = context->data_port;
        laddr.sin_addr.s_addr = context->data_ipv4;
        if ( connect(client_socket, (const struct sockaddr *)&laddr, sizeof(laddr)) == -1 ) {
            close(client_socket);
            return INVALID_SOCKET;
        }
        break;

    case MODE_PASSIVE:
        asz = sizeof(laddr);
        client_socket = accept(context->data_socket, (struct sockaddr *)&laddr, &asz);
        close(context->data_socket);
        context->data_socket = client_socket;

        if ( client_socket == INVALID_SOCKET )
            return INVALID_SOCKET;

        context->data_ipv4 = 0;
        context->data_port = 0;
        context->mode = MODE_NORMAL;
        break;

    default:
        return INVALID_SOCKET;
    }
    return client_socket;
}

ssize_t sendstring(pftp_context context, const char *Buffer)
{
    size_t	l = strlen(Buffer);

    if (context->tls_session == NULL)
        return (send(context->control_socket, Buffer, l, MSG_NOSIGNAL) >= 0);
    else
        return (gnutls_record_send(context->tls_session, Buffer, l) >= 0);
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
    __attribute__((__unused__)) ssize_t un;
    size_t  l = strlen(Buffer);

    if ( g_log != -1 )
    	un = write(g_log, Buffer, l);

    return write(STDOUT_FILENO, Buffer, l);
}

ssize_t writelogentry(pftp_context context, const char *logtext1, const char *logtext2)
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
                context->session_id, logtext1, logtext2);
    }

    return writeconsolestr(text);
}

void worker_thread_cleanup(pftp_context context)
{
	pthread_t			tid;
    struct timespec     timeout = {0};

    tid = context->worker_thread_id;
    if ( context->worker_thread_valid == 0 )
    {
        context->worker_thread_abort = 1;

        timeout.tv_sec = 0;
        timeout.tv_nsec = WORKER_CLEANUP_TIMEOUT_NS;

        if ( context->data_socket != INVALID_SOCKET ) {
          close(context->data_socket);
          context->data_socket = INVALID_SOCKET;
        }

        if ( context->file_fd != -1 ) {
          close(context->file_fd);
          context->file_fd = -1;
        }

        context->data_ipv4 = 0;
        context->data_port = 0;

        nanosleep(&timeout, NULL);
        if ( context->worker_thread_valid == -1 )
          return;

        if (pthread_cancel(tid) != 0)
        {
            writelogentry(context, "Thread cancel failed", "");
        }
        context->worker_thread_valid = -1;
    }
}

void worker_thread_start(pftp_context context, pstartroutine fn)
{
    pthread_t       tid;
    pthcontext      tctx;

    context->worker_thread_abort = 0;

    if (__sync_val_compare_and_swap(&context->busy, 0, 1) != 0)
    {
         sendstring(context, error450);
         return;
    }

    tctx = x_malloc(sizeof(thcontext));
    tctx->context = context;
    tctx->fn_type = 0;
    snprintf(tctx->th_file_name, sizeof(tctx->th_file_name), "%s", context->file_name);

    context->worker_thread_valid = pthread_create(&tid, NULL, (void * (*)(void *))fn, tctx);
    if ( context->worker_thread_valid == 0 )
        context->worker_thread_id = tid;
    else
    {
        free(tctx);
        sendstring(context, error451);
        context->busy = __sync_sub_and_fetch(&context->busy, 1);
    }
}

ssize_t ftpUSER(pftp_context context, const char *params)
{
    char text[PATH_MAX];

    if ( params == NULL )
        return (int)sendstring(context, error501);

    context->access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(text, sizeof(text), "331 User %s OK. Password required\r\n", params);
    sendstring(context, text);

    /* Save login name to UserName for the next PASS command */
    memset(context->user_name, 0, sizeof(context->user_name));
    snprintf(context->user_name, sizeof(context->user_name), "%s", params);
    return 1;
}

ssize_t ftpQUIT(pftp_context context, const char *params)
{
    __attribute__((__unused__)) const char *un = params;
    char text[PATH_MAX];

    writelogentry(context, " QUIT", "");
    snprintf(text, sizeof(text), "221 %s\r\n", GOODBYE_MSG);
    sendstring(context, text);

    /* return 0 to break command processing loop */
    return 0;
}

ssize_t ftpNOOP(pftp_context context, const char *params)
{
    __attribute__((__unused__)) const char *un = params;
    return sendstring(context, success200);
}

ssize_t ftpPWD(pftp_context context, const char *params)
{
    __attribute__((__unused__)) const char *un = params;
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    snprintf(context->file_name, sizeof(context->file_name), "257 \"%s\" is a current directory.\r\n", context->current_dir);
    return sendstring(context, context->file_name);
}

ssize_t ftpTYPE(pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
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
    
    case 'L':
        return sendstring(context, error504);
    case 'E':
        return sendstring(context, error504);

    default:
        return sendstring(context, error501);
    }
}

ssize_t ftpPORT(pftp_context context, const char *params)
{
    int			c;
    in_addr_t	data_ipv4 = 0, data_port = 0;
    char		*p = (char *)params;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( params == NULL )
        return sendstring(context, error501);

    for (c = 0; c < 4; ++c) {
        data_ipv4 += ((in_addr_t)strtoul(p, NULL, 10)) << c*8;
        while ( (*p >= '0') && (*p <= '9') )
            ++p;
        if ( *p == 0 )
            break;
        ++p;
    }

    for (c = 0; c < 2; ++c) {
        data_port += ((in_addr_t)strtoul(p, NULL, 10)) << c*8;
        while ( (*p >= '0') && (*p <= '9') )
            ++p;
        if ( *p == 0 )
            break;
        ++p;
    }

    if ( data_ipv4 != context->client_ipv4 )
        return sendstring(context, error501);

    context->data_ipv4 = data_ipv4;
    context->data_port = (in_port_t)data_port;
    context->mode = MODE_NORMAL;

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

ssize_t list_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
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

void *list_thread(pthcontext tctx)
{
    volatile SOCKET     client_socket;
    gnutls_session_t	TLS_datasession;
    int					fd;
    ssize_t             ret;
    DIR					*pdir;
    struct dirent		*entry;
    pftp_context        context = tctx->context;

    pthread_detach(pthread_self());
    pthread_cleanup_push(cleanup_handler, tctx);
    ret = 0;
    TLS_datasession = NULL;

    client_socket = create_datasocket(context);
    while (client_socket != INVALID_SOCKET)
    {
        if (context->tls_session != NULL)
            if (!ftp_init_tls_session(&TLS_datasession, client_socket, 0))
                break;
        
        fd = open(tctx->th_file_name, O_DIRECTORY | O_RDONLY | g_cfg.file_open_flags);
        if (fd == -1)
            break;

        pdir = fdopendir(fd);
        if (pdir == NULL) {
            close(fd);
            break;
        }

        while ((entry = readdir(pdir)) != NULL) {
            if (tctx->fn_type == LIST_TYPE_MLSD)
                ret = mlsd_sub(tctx->th_file_name, client_socket, TLS_datasession, entry);
            else
                ret = list_sub(tctx->th_file_name, client_socket, TLS_datasession, entry);
            if ( (ret == 0) || (context->worker_thread_abort != 0 ))
                break;
        }
/* fd will be closed automatically */
        closedir(pdir);
        break;
    }

    ftp_shutdown_tls_session(TLS_datasession);

    writelogentry(context, " LIST/MLSD complete", "");

    if (client_socket == INVALID_SOCKET) {
        sendstring(context, error451);
    }
    else {
        if ((context->worker_thread_abort == 0) && (ret != 0))
            sendstring(context, success226);
        else
            sendstring(context, error426);

        close(client_socket);
        context->data_socket = INVALID_SOCKET;
    }

    context->worker_thread_valid = -1;
    pthread_cleanup_pop(0);
    context->busy = __sync_sub_and_fetch(&context->busy, 1);
    free(tctx);
    return NULL;
}

ssize_t ftpLIST(pftp_context context, const char *params)
{
    struct  stat    filestats;

    if (context->access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if ((context->worker_thread_valid == 0) || (context->file_fd != -1))
        return sendstring(context, error550_t);

    if (params != NULL)
    {
        if ((strcmp(params, "-a") == 0) || (strcmp(params, "-l") == 0))
            params = NULL;
    }

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    while (stat(context->file_name, &filestats) == 0)
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

ssize_t ftpCDUP(pftp_context context, const char *params)
{
    __attribute__((__unused__)) const char *un = params;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( strcmp(context->current_dir, "/") == 0 )
        return sendstring(context, success250);

    filepath(context->current_dir);

    writelogentry(context, " CDUP", "");
    return sendstring(context, success250);
}

ssize_t ftpCWD(pftp_context context, const char *params)
{
    struct	stat	filestats;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    if ( stat(context->file_name, &filestats) == 0 )
        if ( S_ISDIR(filestats.st_mode) )
        {
            ftp_effective_path("/", context->current_dir, params, sizeof(context->file_name), context->file_name);
            memset(context->current_dir, 0, sizeof(context->current_dir));
            snprintf(context->current_dir, sizeof(context->current_dir), "%s", context->file_name);
            writelogentry(context, " CWD: ", context->current_dir);
            return sendstring(context, success250);
        }

    return sendstring(context, error550);
}

void *retr_thread(pthcontext tctx)
{
    volatile SOCKET		client_socket;
    int					sent_ok, file_fd;
    off_t				offset;
    ssize_t				sz, sz_total;
    size_t				buffer_size;
    char				*buffer;
    struct timespec		t;
    signed long long	lt0, lt1, dtx;
    gnutls_session_t	TLS_datasession;
    pftp_context        context = tctx->context;

    pthread_detach(pthread_self());
    pthread_cleanup_push(cleanup_handler, tctx);

    file_fd = -1;
    sent_ok = 0;
    sz_total = 0;
    buffer = NULL;
    TLS_datasession = NULL;
    client_socket = INVALID_SOCKET;
    clock_gettime(CLOCK_MONOTONIC, &t);
    lt0 = t.tv_sec*1000000000ll + t.tv_nsec;
    dtx = t.tv_sec+30;

    buffer = x_malloc(TRANSMIT_BUFFER_SIZE);
    while (buffer != NULL)
    {
        client_socket = create_datasocket(context);
        if (client_socket == INVALID_SOCKET)
            break;

        if (context->tls_session != NULL)
        {
            if (!ftp_init_tls_session(&TLS_datasession, client_socket, 0))
                break;

            buffer_size = gnutls_record_get_max_size(TLS_datasession);
            if (buffer_size > TRANSMIT_BUFFER_SIZE)
                buffer_size = TRANSMIT_BUFFER_SIZE;
        }
        else
            buffer_size = TRANSMIT_BUFFER_SIZE;

        file_fd = open(tctx->th_file_name, O_RDONLY | g_cfg.file_open_flags);
        context->file_fd = file_fd;
        if (file_fd == -1)
            break;

        offset = lseek(file_fd, context->rest_point, SEEK_SET);
        if (offset != context->rest_point)
            break;

        sent_ok = 1;
        while ( context->worker_thread_abort == 0 ) {
            sz = read(file_fd, buffer, buffer_size);
            if (sz == 0)
                break;

            if (sz < 0)
            {
                sent_ok = 0;
                break;
            }

            if (send_auto(client_socket, TLS_datasession, buffer, sz) == sz)
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

        context->stats.data_tx += (size_t)sz_total;
        ++context->stats.files_tx;

        snprintf(buffer, buffer_size, " RETR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
                sz_total, sz_total/1048576.0f, dtx/1000000000.0f, (1000000000.0f*sz_total)/dtx/1048576.0f);

        writelogentry(context, buffer, "");

        break;
    }

    if (file_fd != -1)
        close(file_fd);

    context->file_fd = -1;

    if (buffer != NULL) {
        free(buffer);
    }

    ftp_shutdown_tls_session(TLS_datasession);

    if (client_socket == INVALID_SOCKET) {
        sendstring(context, error451);
    }
    else {
        if ((context->worker_thread_abort == 0) && (sent_ok != 0))
            sendstring(context, success226);
        else
            sendstring(context, error426);

        close(client_socket);
        context->data_socket = INVALID_SOCKET;
    }

    context->worker_thread_valid = -1;
    pthread_cleanup_pop(0);
    context->busy = __sync_sub_and_fetch(&context->busy, 1);
    free(tctx);
    return NULL;
}

ssize_t ftpRETR(pftp_context context, const char *params)
{
    struct	stat	filestats;

    if (context->access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if ( params == NULL )
        return sendstring(context, error501);
    if ((context->worker_thread_valid == 0) || (context->file_fd != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    while (stat(context->file_name, &filestats) == 0)
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

ssize_t ftpABOR(pftp_context context, const char *params)
{
    __attribute__((__unused__)) const char *un = params;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    writelogentry(context, " ABORT command", NULL);
    worker_thread_cleanup(context);
    context->busy = __sync_val_compare_and_swap(&context->busy, 1, 0);
    return sendstring(context, success226);
}

ssize_t ftpDELE(pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    if ( unlink(context->file_name) == 0 ) {
        sendstring(context, success250);
        writelogentry(context, " DELE: ", (char *)params);
    }
    else
        sendstring(context, error550_r);

    return 1;
}

int pasv(pftp_context context)
{
    SOCKET				data_socket;
    struct sockaddr_in	laddr;
    int					socketret = -1, result = 0;
    unsigned long		c;
    struct	timespec	rtctime;

    while (1)
    {
        if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        {
            sendstring(context, error530);
            break;
        }

        if ( context->worker_thread_valid == 0 )
        {
            sendstring(context, error550_t);
            break;
        }

        if ( context->data_socket != INVALID_SOCKET )
            close(context->data_socket);

        context->data_socket = INVALID_SOCKET;

        data_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (data_socket == INVALID_SOCKET)
        {
            sendstring(context, error451);
            break;
        }

        for (c = g_cfg.pasv_port_base; c <= g_cfg.pasv_port_max; c++) {
            clock_gettime(CLOCK_REALTIME, &rtctime);
            memset(&laddr, 0, sizeof(laddr));
            laddr.sin_family = AF_INET;
            laddr.sin_port = htons((in_port_t)(g_cfg.pasv_port_base +
                    (rtctime.tv_nsec % (g_cfg.pasv_port_max-g_cfg.pasv_port_base))));
            laddr.sin_addr.s_addr = context->server_ipv4;
            socketret = bind(data_socket, (struct sockaddr *)&laddr, sizeof(laddr));
            if ( socketret == 0 )
                break;
        }

        if ( socketret != 0 ) {
            close(data_socket);
            sendstring(context, error451);
            break;
        }

        socketret = listen(data_socket, SOMAXCONN);
        if (socketret != 0) {
            close(data_socket);
            sendstring(context, error451);
            break;
        }

        if ((context->client_ipv4 & g_cfg.local_ip_mask) == (context->server_ipv4 & g_cfg.local_ip_mask))
        {
            context->data_ipv4 = context->server_ipv4;
            writelogentry(context, " local client.", "");
        } else {
            context->data_ipv4 = g_cfg.external_interface;
            writelogentry(context, " nonlocal client.", "");
        }

        context->data_port = laddr.sin_port;
        context->data_socket = data_socket;
        context->mode = MODE_PASSIVE;

        result = 1;
        break;
    }

    return result;
}

ssize_t ftpEPSV (pftp_context context, const char *params)
{
	__attribute__((unused)) const char *un = params;

    if (pasv(context) == 0)
        return 1;

    snprintf(context->file_name, sizeof(context->file_name),
            "229 Entering Extended Passive Mode (|||%u|)\r\n",
            ntohs(context->data_port));

    writelogentry(context, " entering extended passive mode", "");

    return sendstring(context, context->file_name);
}

ssize_t ftpPASV(pftp_context context, const char *params)
{
	__attribute__((unused)) const char *un = params;

    if (pasv(context) == 0)
        return 1;

    snprintf(context->file_name, sizeof(context->file_name),
            "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u).\r\n",
            context->data_ipv4 & 0xff,
            (context->data_ipv4 >> 8) & 0xff,
            (context->data_ipv4 >> 16) & 0xff,
            (context->data_ipv4 >> 24) & 0xff,
            context->data_port & 0xff,
            (context->data_port >> 8) & 0xff);

    writelogentry(context, " entering passive mode", "");

    return sendstring(context, context->file_name);
}

ssize_t ftpPASS(pftp_context context, const char *params)
{
    char temptext[PATH_MAX];

    if ( params == NULL )
        return sendstring(context, error501);

    memset(temptext, 0, sizeof(temptext));

    /*
     * we have login name saved in context->user_name from USER command
     */
    if (!config_parse(g_cfg.config_file, context->user_name, "pswd", temptext, sizeof(temptext)))
        return sendstring(context, error530_r);

    if ( (strcmp(temptext, params) == 0) || (temptext[0] == '*') )
    {
        memset(context->root_dir, 0, sizeof(context->root_dir));
        memset(temptext, 0, sizeof(temptext));

        config_parse(g_cfg.config_file, context->user_name, "root", context->root_dir, sizeof(context->root_dir));
        config_parse(g_cfg.config_file, context->user_name, "accs", temptext, sizeof(temptext));

        context->access = FTP_ACCESS_NOT_LOGGED_IN;
        do {

            if ( strcasecmp(temptext, "admin") == 0 ) {
                context->access = FTP_ACCESS_FULL;
                break;
            }

            if ( strcasecmp(temptext, "upload") == 0 ) {
                context->access = FTP_ACCESS_CREATENEW;
                break;
            }

            if ( strcasecmp(temptext, "readonly") == 0 ) {
                context->access = FTP_ACCESS_READONLY;
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

ssize_t ftpREST(pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( params == NULL )
        return sendstring(context, error501);

    context->rest_point = (off_t)strtoull(params, NULL, 10);
    snprintf(context->file_name, sizeof(context->file_name),
            "350 REST supported. Ready to resume at byte offset %llu\r\n",
            (unsigned long long int)context->rest_point);

    return sendstring(context, context->file_name);
}

ssize_t ftpSIZE(pftp_context context, const char *params)
{
    struct stat		filestats;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    if ( stat(context->file_name, &filestats) == 0 )
    {
        snprintf(context->file_name, sizeof(context->file_name), "213 %llu\r\n",
                (unsigned long long int)filestats.st_size);
        sendstring(context, context->file_name);
    }
    else
        sendstring(context, error550);

    return 1;
}

ssize_t ftpMKD(pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_CREATENEW )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    if ( mkdir(context->file_name, 0755) == 0 ) {
        sendstring(context, success257);
        writelogentry(context, " MKD: ", (char *)params);
    }
    else
        sendstring(context, error550_r);

    return 1;
}

ssize_t ftpRMD(pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    if ( rmdir(context->file_name) == 0 ) {
        sendstring(context, success250);
        writelogentry(context, " DELE: ", (char *)params);
    }
    else
        sendstring(context, error550_r);

    return 1;
}

void *stor_thread(pthcontext tctx)
{
    volatile SOCKET     client_socket;
    int					file_fd;
    ssize_t				wsz, sz, sz_total;
    size_t				buffer_size;
    char				*buffer;
    struct timespec		t;
    signed long long	lt0, lt1, dtx;
    gnutls_session_t	TLS_datasession;
    pftp_context        context = tctx->context;

    pthread_detach(pthread_self());
    pthread_cleanup_push(cleanup_handler, tctx);

    file_fd = -1;
    sz_total = 0;
    buffer = NULL;
    TLS_datasession = NULL;
    client_socket = INVALID_SOCKET;
    clock_gettime(CLOCK_MONOTONIC, &t);
    lt0 = t.tv_sec*1000000000ll + t.tv_nsec;
    dtx = t.tv_sec+30;

    buffer = x_malloc(TRANSMIT_BUFFER_SIZE);
    while (buffer != NULL)
    {
        client_socket = create_datasocket(context);
        if (client_socket == INVALID_SOCKET)
            break;

        if (context->tls_session != NULL)
        {
            if (!ftp_init_tls_session(&TLS_datasession, client_socket, 0))
                break;

            buffer_size = gnutls_record_get_max_size(TLS_datasession);
            if (buffer_size > TRANSMIT_BUFFER_SIZE)
                buffer_size = TRANSMIT_BUFFER_SIZE;
        }
        else
            buffer_size = TRANSMIT_BUFFER_SIZE;

        if (tctx->fn_type == STOR_TYPE_APPEND)
            file_fd = open(tctx->th_file_name, O_RDWR | g_cfg.file_open_flags);
        else
            file_fd = open(tctx->th_file_name, O_CREAT | O_RDWR | O_TRUNC | g_cfg.file_open_flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

        context->file_fd = file_fd;
        if (file_fd == -1)
            break;

        lseek(file_fd, 0, SEEK_END);

        while ( context->worker_thread_abort == 0 ) {
            sz = recv_auto(client_socket, TLS_datasession, buffer, buffer_size);
            if (sz > 0)
            {
                sz_total += sz;
                wsz = write(file_fd, buffer, (size_t)sz);
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

        context->stats.data_rx += (size_t)sz_total;
        ++context->stats.files_rx;

        snprintf(buffer, buffer_size, " STOR/APPEND complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)",
                sz_total, sz_total/1048576.0f, dtx/1000000000.0f, (1000000000.0f*sz_total)/dtx/1048576.0f);
        writelogentry(context, buffer, "");

        break;
    }

    if (file_fd != -1)
        close(file_fd);

    context->file_fd = -1;

    if (buffer != NULL) {
        free(buffer);
    }

    ftp_shutdown_tls_session(TLS_datasession);

    if (client_socket == INVALID_SOCKET) {
        sendstring(context, error451);
    }
    else {
        if (context->worker_thread_abort == 0)
            sendstring(context, success226);
        else
            sendstring(context, error426);

        close(client_socket);
        context->data_socket = INVALID_SOCKET;
    }

    context->worker_thread_valid = -1;
    pthread_cleanup_pop(0);
    context->busy = __sync_sub_and_fetch(&context->busy, 1);
    free(tctx);
    return NULL;
}

ssize_t ftpSTOR(pftp_context context, const char *params)
{
    struct  stat    filestats;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_CREATENEW )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);
    if ((context->worker_thread_valid == 0) || (context->file_fd != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    /* check: do not overwrite existing files if not full access */
    if ( stat(context->file_name, &filestats) == 0 )
    {
        if ( context->access != FTP_ACCESS_FULL )
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

ssize_t ftpSYST(pftp_context context, const char *params)
{
	__attribute__((unused)) const char *un = params;
    return sendstring(context, success215);
}

ssize_t ftpHELP(pftp_context context, const char *params)
{
	__attribute__((unused)) const char *un = params;
    return sendstring(context, success214);
}

int isoctaldigit(char c)
{
    return ((c >= '0') && (c < '8'));
}

ssize_t parseCHMOD(pftp_context context, const char* params)
{
    mode_t flags = 0;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_FULL )
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

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);
    return (chmod(context->file_name, flags) == 0);
}

ssize_t ftpSITE(pftp_context context, const char *params)
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

ssize_t ftpFEAT(pftp_context context, const char *params)
{
	__attribute__((unused)) const char *un = params;
    return sendstring(context, success211);
}

void *append_thread(pthcontext tctx)
{
    tctx->fn_type = STOR_TYPE_APPEND;
    return stor_thread(tctx);
}

ssize_t ftpAPPE(pftp_context context, const char *params)
{
    struct	stat	filestats;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);
    if ((context->worker_thread_valid == 0) || (context->file_fd != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    /* stat must NOT fail */
    while (stat(context->file_name, &filestats) == 0)
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

ssize_t ftpRNFR(pftp_context context, const char *params)
{
    struct stat		filestats;

    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->rn_from), context->rn_from);

    if ( stat(context->rn_from, &filestats) == 0 )
    {
        writelogentry(context, " RNFR: ", context->rn_from);
        sendstring(context, interm350_ren);
    }
    else
        sendstring(context, error550);

    return 1;
}

ssize_t ftpRNTO(pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);
    if ( context->access < FTP_ACCESS_FULL )
        return sendstring(context, error550_r);
    if ( params == NULL )
        return sendstring(context, error501);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);
    if ( rename(context->rn_from, context->file_name) == 0 )
    {
        writelogentry(context, " RNTO: ", context->file_name);
        sendstring(context, success250);
    }
    else
        sendstring(context, error550);

    memset(&context->rn_from, 0, sizeof(context->rn_from));
    return 1;
}

ssize_t ftpOPTS(pftp_context context, const char *params)
{
    if ( params != NULL )
        if (strcasecmp(params, "utf8 on") == 0)
            return sendstring(context, "200 Always in UTF8 mode.\r\n");

    writelogentry(context, " unsupported OPTS: ", params);
    return sendstring(context, error500);
}

ssize_t ftpAUTH(pftp_context context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    if ( strcasecmp(params, "TLS") == 0 )
    {
        /* ftp_init_tls_session will send a status reply */
        ftp_init_tls_session(&context->tls_session, context->control_socket, 1);
        return 1;
    }
    else
        return sendstring(context, error504);
}

ssize_t ftpPBSZ (pftp_context context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    if ( context->tls_session == NULL )
        return sendstring(context, error503);

    context->block_size = strtoul(params, NULL, 10);
    return sendstring(context, success200);
}

ssize_t ftpPROT (pftp_context context, const char *params)
{
    if ( context->access == FTP_ACCESS_NOT_LOGGED_IN )
        return sendstring(context, error530);

    if ( params == NULL )
        return sendstring(context, error501);

    if ( context->tls_session == NULL )
        return sendstring(context, error503);

    switch (*params)
    {
    case 'C':
        context->data_protection_level = 0;
        return sendstring(context, success200);
        break;

    case 'P':
        context->data_protection_level = 100;
        return sendstring(context, success200);
        break;

    default:
        return sendstring(context, error504);
    }
}

ssize_t mlsd_sub (char *dirname, SOCKET s, gnutls_session_t session, struct dirent *entry)
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

void *mlsd_thread(pthcontext tctx)
{
    tctx->fn_type = LIST_TYPE_MLSD;
    return list_thread(tctx);
}

ssize_t ftpMLSD(pftp_context context, const char *params)
{
    struct  stat    filestats;

    if (context->access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if ((context->worker_thread_valid == 0) || (context->file_fd != -1))
        return sendstring(context, error550_t);

    ftp_effective_path(context->root_dir, context->current_dir, params, sizeof(context->file_name), context->file_name);

    while (stat(context->file_name, &filestats) == 0)
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

int recvcmd(pftp_context context, char *buffer, size_t buffer_size)
{
    ssize_t	l, p = 0;

    if ( buffer_size < 5 )
        return 0;

    memset(buffer, 0, buffer_size);
    --buffer_size;

    while (buffer_size > 0)
    {
        if (context->tls_session == NULL)
            l = recv(context->control_socket, buffer+p, buffer_size, 0);
        else
            l = gnutls_record_recv(context->tls_session, buffer+p, buffer_size);

        if ( l <= 0 )
            return 0;

        buffer_size -= (size_t)l;
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
    ftp_context             ctx __attribute__ ((aligned (16)));
    char                    *cmd, *params, rcvbuf[PATH_MAX];
    int                     c, cmdno;
    ssize_t                 rv;
    unsigned int            tn;
    size_t                  i, cmdlen;
    socklen_t               asz;
    struct sockaddr_in      laddr;

    pthread_detach(pthread_self());
    memset(&rcvbuf, 0, sizeof(rcvbuf));
    memset(&ctx, 0, sizeof(ctx));

    ctx.busy = 0;
    ctx.access = FTP_ACCESS_NOT_LOGGED_IN;
    ctx.control_socket = s;
    ctx.session_id = __sync_add_and_fetch(&g_newid, 1);
    tn = __sync_add_and_fetch(&g_threads, 1);
    snprintf(rcvbuf, sizeof(rcvbuf), "<- New thread. Thread counter g_threads=%i", tn);
    writelogentry(&ctx, rcvbuf, "");

    memset(&laddr, 0, sizeof(laddr));
    asz = sizeof(laddr);
    while ( getsockname(ctx.control_socket, (struct sockaddr *)&laddr, &asz) == 0 )
    {
        ctx.server_ipv4 = laddr.sin_addr.s_addr;

        memset(&laddr, 0, sizeof(laddr));
        asz = sizeof(laddr);
        if ( getpeername(ctx.control_socket, (struct sockaddr *)&laddr, &asz) != 0 )
            break;

        ctx.client_ipv4 = laddr.sin_addr.s_addr;
        ctx.mode = MODE_NORMAL;
        ctx.worker_thread_abort = 1;
        ctx.worker_thread_valid = -1;
        ctx.file_fd = -1;
        ctx.data_socket = INVALID_SOCKET;

        ctx.current_dir[0] = '/';
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

        while ( ctx.control_socket != INVALID_SOCKET ) {
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
                if (strncasecmp(cmd, ftpprocs[c].name, cmdlen) == 0)
                {
                    cmdno = c;
                    rv = ftpprocs[c].proc(&ctx, params);
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

        snprintf(rcvbuf, sizeof(rcvbuf),
            " User disconnected. \n==== Session %u statistics ====\n"
            "Rx: %zd bytes (%f MBytes) total received by server in %zd files,\n"
            "Tx: %zd bytes (%f MBytes) total sent to the client in %zd files.\n",
            ctx.session_id,
            ctx.stats.data_rx, ctx.stats.data_rx / 1048576.0f, ctx.stats.files_rx,
            ctx.stats.data_tx, ctx.stats.data_tx / 1048576.0f, ctx.stats.files_tx);

        writelogentry(&ctx, rcvbuf, "");
        break;
    }

    ftp_shutdown_tls_session(ctx.tls_session);

    close(ctx.control_socket);
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

    opt = KEEPALIVE_IDLE_SEC; /* set idle status after KEEPALIVE_IDLE_SEC seconds since last data transfer */;
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));

    opt = KEEPALIVE_IDLE_SEC; /* send keep alive packet every KEEPALIVE_IDLE_SEC seconds */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));

    opt = KEEPALIVE_PROBE_COUNT; /* drop after KEEPALIVE_PROBE_COUNT unanswered packets */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt));
}

void *ftpmain(void *p)
{
    struct  sockaddr_in laddr;

    int     ftpsocket = INVALID_SOCKET,
            client_socket,
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
    laddr.sin_port = htons(g_cfg.port);
    laddr.sin_addr.s_addr = g_cfg.bind_to_interface;
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
        client_socket = accept(ftpsocket, (struct sockaddr *)&laddr, &asz);
        if (client_socket == INVALID_SOCKET)
            continue;

        __sync_add_and_fetch(&g_client_sockets_created, 1);

        rv = -1;
        if (g_threads < g_cfg.max_users)
        {
            if (g_cfg.enable_keepalive != 0)
                socket_set_keepalive(client_socket);

            rv = pthread_create(&th, NULL, (void * (*)(void *))ftp_client_thread, (void *)client_socket);
            if (rv != 0)
                sendstring_plaintext(client_socket, error451);
        }
        else
        {
            sendstring_plaintext(client_socket, error451_max);
        }

        if (rv != 0)
        {
            close(client_socket);
            __sync_add_and_fetch(&g_client_sockets_closed, 1);
        }

        snprintf(text, sizeof(text),
                "MAIN LOOP stats: g_threads=%i, g_cfg.max_users=%" PRIu64 ", g_client_sockets_created=%llu, g_client_sockets_closed=%llu\r\n",
                g_threads, g_cfg.max_users, g_client_sockets_created, g_client_sockets_closed);

        writelogentry(NULL, text, "");
    }

    close(ftpsocket);

    return p;
}
