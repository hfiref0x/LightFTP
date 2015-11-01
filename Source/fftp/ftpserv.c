// ftpserv.c - simple ftp server
#include <windows.h>
#include "minirtl\minirtl.h"
#include "minirtl\cmdline.h"
#include "ftpserv.h"

static HANDLE	g_LogHandle = NULL;
LONG			g_NewID = 0;

BOOL sendstring(
	SOCKET s, 
	const char *Buffer
	)
{
	return ( send(s, Buffer, (int)_strlen_a(Buffer), 0) >= 0 );
}

BOOL writeconsolestr(
	HANDLE LogHandle, 
	const char *Buffer
	)
{
	DWORD	bytesIO, l;

	l = (DWORD)_strlen_a(Buffer);

	if ( (LogHandle != NULL) && (LogHandle != INVALID_HANDLE_VALUE) )
		WriteFile(LogHandle, Buffer, l, &bytesIO, NULL);
	
	return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), Buffer, l, &bytesIO, NULL);
}

BOOL writelogentry(
	PFTPCONTEXT context, 
	char *logtext1, 
	char *logtext2
	)
{
	char		cvbuf[32], textbuf[MAX_PATH*2];
	SYSTEMTIME	tm;

	GetLocalTime(&tm);

	textbuf[0] = 0;

	if ( tm.wDay < 10 )
		_strcat_a(textbuf, "0");
	ultostr_a(tm.wDay, cvbuf);
	_strcat_a(textbuf, cvbuf);
	_strcat_a(textbuf, "-");
	if ( tm.wMonth < 10 )
		_strcat_a(textbuf, "0");
	ultostr_a(tm.wMonth, cvbuf);
	_strcat_a(textbuf, cvbuf);
	_strcat_a(textbuf, "-");
	ultostr_a(tm.wYear, cvbuf);
	_strcat_a(textbuf, cvbuf);
	_strcat_a(textbuf, " ");
	
	if ( tm.wHour < 10 )
		_strcat_a(textbuf, "0");
	ultostr_a(tm.wHour, cvbuf);
	_strcat_a(textbuf, cvbuf);
	_strcat_a(textbuf, ":");
	if ( tm.wMinute < 10 )
		_strcat_a(textbuf, "0");
	ultostr_a(tm.wMinute, cvbuf);
	_strcat_a(textbuf, cvbuf);
	_strcat_a(textbuf, ":");
	if ( tm.wSecond < 10 )
		_strcat_a(textbuf, "0");
	ultostr_a(tm.wSecond, cvbuf);
	_strcat_a(textbuf, cvbuf);

	_strcat_a(textbuf, " S-id=");
	ultostr_a(context->SessionID, _strend_a(textbuf));
	_strcat_a(textbuf, ": ");
	_strcat_a(textbuf, logtext1);
	_strcat_a(textbuf, logtext2);
	_strcat_a(textbuf, CRLF);

	return writeconsolestr(context->LogHandle, textbuf);
}

void unixpath(
	char *s
	)
{
	while ( *s != 0 ) {
		if ( *s == '\\' )
			*s = '/';
		s++;
	}
}

void ntpath(
	char *s
	)
{
	while ( *s != 0 ) {
		if ( *s == '/' )
			*s = '\\';
		s++;
	}
}

void nolastslash(
	char *s
	)
{
	if ( s == NULL )
		return;

	if ( *s == 0 )
		return;

	if ( (*s == '\\') && (s[1] == 0) )
		return;

	while ( s[1] != 0 )
		s++;

	if ( *s == '\\' )
		*s = 0;
}

void addlastslash(
	char *s
	)
{
	if ( s == NULL )
		return;

	if ( *s == 0 ) {
		*s = '\\';
		s[1] = 0;
		return;
	}

	while ( s[1] != 0 )
		s++;

	if ( *s == '\\' )
		return;

	s[1] = '\\';
	s[2] = 0;
}

void formatpath( // removes multiple slashes, dots
	char *s
	) 
{
	char	*d = s, *p = s;

	while ( *p != 0 ) {
		if ( *p == '\\' )
			if ( p[1] == '.' ) {
				if ( p[2] == '.' )
					if ( p[3] == '\\' ) {
						while ( d < p+3 ) {
							*d = '\\';
							d++;
						}
						p = s;
						d = s;
						continue;
					}
			} else
				if ( p[1] != '\\' )
					d = p;
		p++;
	}

	d = s;
	p = s;

	while ( *p != 0 ) {
		if ( *p == '\\' ) {
			if ( p[1] == '\\' ) {
				p++;
				continue;
			}

			if ( p[1] == '.' ) {
				if ( p[2] == '\\' ) {
					p += 2;
					continue;
				}
			}
		}

		*d = *p;
		d++;
		p++;
	}
	*d = 0;
}

void filepath(
	char *s
	)
{
	char	*p = s;

	if ( (*s == '\\') && (s[1] == 0) )
		return;

	while ( *s != 0 ) {
		if ( *s == '\\' )
			p = s;
		s++;
	}
	*p = 0;
}

void finalpath(
	LPCSTR RootDir, 
	LPCSTR CurrentDir, 
	LPSTR Params, 
	LPSTR Buffer
	)
{
	char	*root = Buffer;

	_strcpy_a(Buffer, RootDir);
	root = _strend_a(Buffer);

	if ( Params == NULL ) {
		addlastslash(root);
		_strcat_a(root, CurrentDir);
		addlastslash(root);
		formatpath(root);
		return;
	}

	ntpath(Params);
	if ( *Params != '\\' ) {
		addlastslash(root);
		_strcat_a(root, CurrentDir);
	}

	_strcat_a(root, Params);
	addlastslash(root);
	formatpath(root);
	formatpath(Buffer);
}

BOOL list_sub(
	SOCKET s, 
	WIN32_FIND_DATA *fdata
	)
{
	TCHAR			textbuf[MAX_PATH];
	CHAR			sendbuf[MAX_PATH];
	FILETIME		ltm;
	ULARGE_INTEGER	sz, deltatime;
	SYSTEMTIME		tm;

	if ( _strcmp(fdata->cFileName, TEXT(".")) == 0 )
		return TRUE;
	if ( _strcmp(fdata->cFileName, TEXT("..")) == 0 )
		return TRUE;

	RtlSecureZeroMemory(&ltm, sizeof(ltm));
	RtlSecureZeroMemory(&tm, sizeof(tm));

	if ((fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		_strcpy(textbuf, TEXT("-rw-rw-rw- 1"));
	else
		_strcpy(textbuf, TEXT("drwxrwxrwx 2"));

	_strcat(textbuf, TEXT(" 9001 9001 "));

	sz.LowPart = fdata->nFileSizeLow;
	sz.HighPart = fdata->nFileSizeHigh;
	u64tostr(sz.QuadPart, _strend(textbuf));
	_strcat(textbuf, TEXT(" "));

	GetSystemTimeAsFileTime(&ltm);
	sz.HighPart = fdata->ftLastWriteTime.dwHighDateTime;
	sz.LowPart = fdata->ftLastWriteTime.dwLowDateTime;
	deltatime.HighPart = ltm.dwHighDateTime;
	deltatime.LowPart = ltm.dwLowDateTime;
	deltatime.QuadPart -= sz.QuadPart;

	FileTimeToLocalFileTime(&fdata->ftLastWriteTime, &ltm);
	FileTimeToSystemTime(&ltm, &tm);

	_strncpy(_strend(textbuf), 4, &shortmonths[(tm.wMonth-1) * 3], 4);
	_strcat(textbuf, TEXT(" "));

	if ( tm.wDay < 10 )
		_strcat(textbuf, TEXT("0"));
	ultostr(tm.wDay, _strend(textbuf));
	_strcat(textbuf, TEXT(" "));

	if (deltatime.QuadPart < (180*24*60*60*10000000ui64)) {
		if (tm.wHour < 10)
			_strcat(textbuf, TEXT("0"));
		ultostr(tm.wHour, _strend(textbuf));
		_strcat(textbuf, TEXT(":"));

		if (tm.wMinute < 10)
			_strcat(textbuf, TEXT("0"));
		ultostr(tm.wMinute, _strend(textbuf));
	} else {
		ultostr(tm.wYear, _strend(textbuf));
	}
	_strcat(textbuf, TEXT(" "));

	WideCharToMultiByte(CP_UTF8, 0, textbuf, MAX_PATH, sendbuf, MAX_PATH, NULL, NULL);
	if ( !sendstring(s, sendbuf) )
		return FALSE;
	WideCharToMultiByte(CP_UTF8, 0, fdata->cFileName, MAX_PATH, sendbuf, MAX_PATH, NULL, NULL);
	if ( !sendstring(s, sendbuf) )
		return FALSE;

	return sendstring(s, CRLF);
}

BOOL mlsd_sub(
	SOCKET s, 
	WIN32_FIND_DATA *fdata
	)
{
	TCHAR			textbuf[MAX_PATH];
	CHAR			sendbuf[MAX_PATH];
	ULARGE_INTEGER	sz;
	SYSTEMTIME		tm;

	if (_strcmp(fdata->cFileName, TEXT(".")) == 0)
		return TRUE;
	if (_strcmp(fdata->cFileName, TEXT("..")) == 0)
		return TRUE;

	_strcpy(textbuf, TEXT("type="));
	if ((fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		_strcat(textbuf, TEXT("file;size="));
	else
		_strcat(textbuf, TEXT("dir;sizd="));

	sz.LowPart = fdata->nFileSizeLow;
	sz.HighPart = fdata->nFileSizeHigh;
	u64tostr(sz.QuadPart, _strend(textbuf));
	_strcat(textbuf, TEXT(";modify="));

	RtlSecureZeroMemory(&tm, sizeof(tm));
	FileTimeToSystemTime(&fdata->ftLastWriteTime, &tm);

	ultostr(tm.wYear, _strend(textbuf));
	if (tm.wMonth < 10)
		_strcat(textbuf, TEXT("0"));
	ultostr(tm.wMonth, _strend(textbuf));
	if (tm.wDay < 10)
		_strcat(textbuf, TEXT("0"));
	ultostr(tm.wDay, _strend(textbuf));
	if (tm.wHour < 10)
		_strcat(textbuf, TEXT("0"));
	ultostr(tm.wHour, _strend(textbuf));
	if (tm.wMinute < 10)
		_strcat(textbuf, TEXT("0"));
	ultostr(tm.wMinute, _strend(textbuf));
	if (tm.wSecond < 10)
		_strcat(textbuf, TEXT("0"));
	ultostr(tm.wSecond, _strend(textbuf));
	_strcat(textbuf, TEXT("; "));

	WideCharToMultiByte(CP_UTF8, 0, textbuf, MAX_PATH, sendbuf, MAX_PATH, NULL, NULL);
	if (!sendstring(s, sendbuf))
		return FALSE;
	WideCharToMultiByte(CP_UTF8, 0, fdata->cFileName, MAX_PATH, sendbuf, MAX_PATH, NULL, NULL);
	if (!sendstring(s, sendbuf))
		return FALSE;

	return sendstring(s, CRLF);
}

SOCKET create_datasocket(
	IN PFTPCONTEXT context
	)
{
	SOCKET				clientsocket = INVALID_SOCKET;
	struct sockaddr_in	laddr;
	int					asz;

	RtlSecureZeroMemory(&laddr, sizeof(laddr));

	switch ( context->Mode ) {
	case MODE_NORMAL:
		clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if ( clientsocket == INVALID_SOCKET )
			return INVALID_SOCKET;

		laddr.sin_family = AF_INET;
		laddr.sin_port = (u_short)context->DataPort;
		laddr.sin_addr.S_un.S_addr = context->DataIPv4;
		if ( connect(clientsocket, (const struct sockaddr *)&laddr, sizeof(laddr)) == SOCKET_ERROR ) {
			closesocket(clientsocket);
			return INVALID_SOCKET;
		}
		break;

	case MODE_PASSIVE:
		asz = sizeof(laddr);
		clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
		if ( clientsocket == INVALID_SOCKET )
			return INVALID_SOCKET;
		context->DataIPv4 = 0;
		context->DataPort = 0;
		context->Mode = MODE_NORMAL;
		closesocket(context->DataSocket);
		context->DataSocket = 0;
		break;

	default:
		return INVALID_SOCKET;
	}
	return clientsocket;
}

DWORD WINAPI list_thread(
	IN PFTPCONTEXT context
	)
{
	SOCKET				clientsocket, control;
	HANDLE				File;
	BOOL				sendok = FALSE;
	WIN32_FIND_DATA		fdata;

	EnterCriticalSection(&context->MTLock);
	control = context->ControlSocket;
	clientsocket = create_datasocket(context);
	if ( clientsocket == INVALID_SOCKET )
		goto error_exit;

	RtlSecureZeroMemory(&fdata, sizeof(fdata));
	File = FindFirstFile(context->TextBuffer, &fdata);
	if ( File != INVALID_HANDLE_VALUE ) {
		sendok = list_sub(clientsocket, &fdata);
		while ( FindNextFile(File, &fdata) && (!context->Stop) && sendok )
			sendok = list_sub(clientsocket, &fdata);
		FindClose(File);
	}
	sendok = ( context->Stop == FALSE ) && ( sendok != FALSE );

error_exit:
	if ( clientsocket != INVALID_SOCKET )
		closesocket(clientsocket);

	writelogentry(context, " LIST complete", NULL);

	CloseHandle(context->WorkerThread);
	context->WorkerThread = NULL;
	LeaveCriticalSection(&context->MTLock);

	if ( clientsocket == INVALID_SOCKET ) {
		sendstring(control, error451);
	} else {
		if ( sendok )
			sendstring(control, success226);
		else
			sendstring(control, error426);
	}

	return 0;
}

DWORD WINAPI mlsd_thread(
	IN PFTPCONTEXT context
	)
{
	SOCKET				clientsocket, control;
	HANDLE				File;
	BOOL				sendok = FALSE;
	WIN32_FIND_DATA		fdata;

	EnterCriticalSection(&context->MTLock);
	control = context->ControlSocket;
	clientsocket = create_datasocket(context);
	if (clientsocket == INVALID_SOCKET)
		goto error_exit;

	RtlSecureZeroMemory(&fdata, sizeof(fdata));
	File = FindFirstFile(context->TextBuffer, &fdata);
	if (File != INVALID_HANDLE_VALUE) {
		sendok = mlsd_sub(clientsocket, &fdata);
		while (FindNextFile(File, &fdata) && (!context->Stop) && sendok)
			sendok = mlsd_sub(clientsocket, &fdata);
		FindClose(File);
	}
	sendok = (context->Stop == FALSE) && (sendok != FALSE);

error_exit:
	if (clientsocket != INVALID_SOCKET)
		closesocket(clientsocket);

	writelogentry(context, " LIST complete", NULL);

	CloseHandle(context->WorkerThread);
	context->WorkerThread = NULL;
	LeaveCriticalSection(&context->MTLock);

	if (clientsocket == INVALID_SOCKET) {
		sendstring(control, error451);
	}
	else {
		if (sendok)
			sendstring(control, success226);
		else
			sendstring(control, error426);
	}

	return 0;
}

DWORD WINAPI retr_thread(
	IN PFTPCONTEXT context
	)
{
	SOCKET			clientsocket, control;
	LPSTR			textbuf = NULL;
	BOOL			sendok = FALSE;
	int				asz;
	LARGE_INTEGER	lsz, dt0, dt1;
	FILETIME		txtime;

	EnterCriticalSection(&context->MTLock);
	control = context->ControlSocket;

	clientsocket = create_datasocket(context);
	if ( clientsocket == INVALID_SOCKET )
		goto error_exit;

	textbuf = (char *)VirtualAlloc(NULL, TRANSMIT_BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if ( textbuf == NULL )
		goto error_exit;

	lsz.QuadPart = 0;
	GetFileSizeEx(context->FileHandle, &lsz);

	if ( lsz.QuadPart == 0 ) {
		sendok = TRUE;
		goto error_exit;
	}

	GetSystemTimeAsFileTime(&txtime);
	dt0.HighPart = txtime.dwHighDateTime;
	dt0.LowPart = txtime.dwLowDateTime;
	lsz.QuadPart = 0;

	SetFilePointerEx(context->FileHandle, context->RestPoint, NULL, FILE_BEGIN);
	while ( !context->Stop ) {
		asz = 0;
		if ( !ReadFile(context->FileHandle, textbuf, TRANSMIT_BUFFER_SIZE, (LPDWORD)&asz, NULL) ) {
			sendok = FALSE;
			break;
		}

		if ( asz > 0 )
			sendok = (send(clientsocket, textbuf, asz, 0) == asz);
		else
			break;

		if ( !sendok )
			break;
		
		lsz.QuadPart += asz;
		GetSystemTimeAsFileTime(&txtime);
		dt1.HighPart = txtime.dwHighDateTime;
		dt1.LowPart = txtime.dwLowDateTime;
		dt1.QuadPart -= dt0.QuadPart;
		if (dt1.QuadPart > 100000000ui64) { // 10 seconds
			_strcpy_a(textbuf, " retr speed: ");
			u64tostr_a(((10000000ui64*lsz.QuadPart) / dt1.QuadPart) / 1024, _strend_a(textbuf));
			_strcat_a(textbuf, " kBytes/s");
			writelogentry(context, textbuf, NULL);
			lsz.QuadPart = 0;
			dt0.HighPart = txtime.dwHighDateTime;
			dt0.LowPart = txtime.dwLowDateTime;
		}
	}
	sendok = ( context->Stop == FALSE ) && ( sendok != FALSE );

error_exit:
	CloseHandle(context->FileHandle);
	context->FileHandle = INVALID_HANDLE_VALUE;

	if ( textbuf != NULL )
		VirtualFree(textbuf, 0, MEM_RELEASE);
	
	if ( clientsocket != INVALID_SOCKET )
		closesocket(clientsocket);

	writelogentry(context, " RETR complete", NULL);

	CloseHandle(context->WorkerThread);
	context->WorkerThread = NULL;
	LeaveCriticalSection(&context->MTLock);

	if ( clientsocket == INVALID_SOCKET )
		sendstring(control, error451);
	else {
		if ( sendok )
			sendstring(control, success226);
		else
			sendstring(control, error426);
	}

	return 0;
}

DWORD WINAPI stor_thread(
	IN PFTPCONTEXT context
	)
{
	SOCKET	clientsocket, control;
	LPSTR	textbuf = NULL;
	BOOL	sendok = FALSE;
	int		asz, iobytes;

	EnterCriticalSection(&context->MTLock);
	control = context->ControlSocket;

	clientsocket = create_datasocket(context);
	if ( clientsocket == INVALID_SOCKET )
		goto error_exit;

	textbuf = (char *)VirtualAlloc(NULL, TRANSMIT_BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if ( textbuf == NULL )
		goto error_exit;

	while ( !context->Stop )
	{
		asz = 0;
		iobytes = recv(clientsocket, textbuf, TRANSMIT_BUFFER_SIZE, 0);
		if ( (iobytes > 0) && (iobytes != SOCKET_ERROR) )
			WriteFile(context->FileHandle, textbuf, iobytes, (LPDWORD)&asz, NULL);
		else
			break;

		sendok = (iobytes == asz);

		if ( !sendok )
			break;
	}
	sendok = ( context->Stop == FALSE ) && ( sendok != FALSE );

error_exit:
	CloseHandle(context->FileHandle);
	context->FileHandle = INVALID_HANDLE_VALUE;

	if ( textbuf != NULL )
		VirtualFree(textbuf, 0, MEM_RELEASE);
	
	if ( clientsocket != INVALID_SOCKET )
		closesocket(clientsocket);

	writelogentry(context, " STOR complete", NULL);

	CloseHandle(context->WorkerThread);
	context->WorkerThread = NULL;
	LeaveCriticalSection(&context->MTLock);

	if ( clientsocket == INVALID_SOCKET )
		sendstring(control, error451);
	else {
		if ( sendok )
			sendstring(control, success226);
		else
			sendstring(control, error426);
	}

	return 0;
}

void StopWorkerThread(
	IN PFTPCONTEXT context
	)
{
	if ( context->WorkerThread != NULL ) {
		context->Stop = TRUE; // trying to stop gracefully
		if ( WaitForSingleObjectEx(context->WorkerThread, 4000, FALSE) == STATUS_TIMEOUT ) {
			// fail? ok, will do bad things
			TerminateThread(context->WorkerThread, 0);
		}
		CloseHandle(context->WorkerThread);
	}

	if ( context->FileHandle != INVALID_HANDLE_VALUE ) {
		CloseHandle(context->FileHandle);
		context->FileHandle = INVALID_HANDLE_VALUE;
	}

	context->DataIPv4 = 0;
	context->DataPort = 0;

	if ( context->DataSocket != 0 ) {
		closesocket(context->DataSocket);
		context->DataSocket = 0;
	}
	context->WorkerThread = NULL;
}

/* FTP COMMANDS BEGIN */

BOOL WINAPI ftpSTOR(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	HANDLE	wth;
	DWORD	fileaccess;
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_CREATENEW )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);
	if ( context->WorkerThread != NULL )
		return sendstring(context->ControlSocket, error550_t);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( context->Access > FTP_ACCESS_CREATENEW )
		fileaccess = CREATE_ALWAYS;
	else
		fileaccess = CREATE_NEW;

	context->FileHandle = CreateFile(filename, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, fileaccess, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( context->FileHandle == INVALID_HANDLE_VALUE )
		return sendstring(context->ControlSocket, error550);

	sendstring(context->ControlSocket, interm150);
	writelogentry(context, " STOR: ", (char *)params);
	context->Stop = FALSE;

	wth = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&stor_thread, (LPVOID)context, 0, NULL);
	if ( wth == NULL ) {
		CloseHandle(context->FileHandle);
		context->FileHandle = INVALID_HANDLE_VALUE;
		sendstring(context->ControlSocket, error451);
	}
	else
		context->WorkerThread = wth;

	return TRUE;
}

BOOL WINAPI ftpAPPE(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	HANDLE			wth;
	LARGE_INTEGER	fptr;
	CHAR			textbuf[MAX_PATH*3];
	TCHAR			filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);
	if ( context->WorkerThread != NULL )
		return sendstring(context->ControlSocket, error550_t);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	context->FileHandle = CreateFile(filename, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( context->FileHandle == INVALID_HANDLE_VALUE )
		return sendstring(context->ControlSocket, error550);

	fptr.QuadPart = 0;
	SetFilePointerEx(context->FileHandle, fptr, NULL, FILE_END);
	sendstring(context->ControlSocket, interm150);
	writelogentry(context, " APPE: ", (char *)params);
	context->Stop = FALSE;

	wth = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&stor_thread, (LPVOID)context, 0, NULL);
	if ( wth == NULL ) {
		CloseHandle(context->FileHandle);
		context->FileHandle = INVALID_HANDLE_VALUE;
		sendstring(context->ControlSocket, error451);
	} else
		context->WorkerThread = wth;

	return TRUE;
}

BOOL WINAPI ftpRETR(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];
	HANDLE	wth;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);
	if ( context->WorkerThread != NULL )
		return sendstring(context->ControlSocket, error550_t);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	context->FileHandle = CreateFile(filename, SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if ( context->FileHandle == INVALID_HANDLE_VALUE )
		return sendstring(context->ControlSocket, error550);

	sendstring(context->ControlSocket, interm150);
	writelogentry(context, " RETR: ", (char *)params);
	context->Stop = FALSE;

	wth = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&retr_thread, (LPVOID)context, 0, NULL);
	if ( wth == NULL ) {
		CloseHandle(context->FileHandle);
		context->FileHandle = INVALID_HANDLE_VALUE;
		sendstring(context->ControlSocket, error451);
	} else
		context->WorkerThread = wth;

	return TRUE;
}

BOOL WINAPI ftpLIST(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	WIN32_FILE_ATTRIBUTE_DATA	adata;
	HANDLE						wth;
	CHAR						textbuf[MAX_PATH*3];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if (context->WorkerThread != NULL)
		return sendstring(context->ControlSocket, error550_t);

	context->FileHandle = INVALID_HANDLE_VALUE;

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	RtlSecureZeroMemory(context->TextBuffer, sizeof(context->TextBuffer));

	if ( params != NULL )
		if ( (params[0] == '-') && (params[1] == 'l') && (params[2] == 0) )
			params = NULL;

	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, context->TextBuffer, MAX_PATH) <= 0)
		context->TextBuffer[0] = 0;

	if ( !GetFileAttributesEx(context->TextBuffer, GetFileExInfoStandard, &adata) )
		return sendstring(context->ControlSocket, error550);
	if ( (adata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 )
		return sendstring(context->ControlSocket, error550);

	_strcat(context->TextBuffer, TEXT("*"));

	sendstring(context->ControlSocket, interm150);
	writelogentry(context, " LIST: ", (char *)params);
	context->Stop = FALSE;

	wth = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&list_thread, (LPVOID)context, 0, NULL);
	if ( wth == NULL )
		sendstring(context->ControlSocket, error451);
	else
		context->WorkerThread = wth;

	return TRUE;
}

BOOL WINAPI ftpPASV(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	SOCKET				datasocket;
	struct sockaddr_in	laddr;
	int					c, socketret = SOCKET_ERROR;
	CHAR				textbuf[MAX_PATH];

	UNREFERENCED_PARAMETER(params);

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if (context->WorkerThread != NULL)
		return sendstring(context->ControlSocket, error550_t);
	if ( context->DataSocket != 0 )
		closesocket(context->DataSocket);

	datasocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (datasocket == INVALID_SOCKET)
		return sendstring(context->ControlSocket, error451);

	RtlSecureZeroMemory(&laddr, sizeof(laddr));

	for (c = 0; c < 4; c++) {
		RtlSecureZeroMemory(&laddr, sizeof(laddr));
		laddr.sin_family = AF_INET;
		laddr.sin_port = (GetTickCount64() & 0xff7f) + 0x4000;
		laddr.sin_addr.S_un.S_addr = context->ServerIPv4;
		socketret = bind(datasocket, (struct sockaddr *)&laddr, sizeof(laddr));
		if ( socketret == 0 )
			break;
	}

	if ( socketret != 0 ) {
		closesocket(datasocket);
		return sendstring(context->ControlSocket, error451);
	}
	socketret = listen(datasocket, SOMAXCONN);
	if (socketret != 0) {
		closesocket(datasocket);
		return sendstring(context->ControlSocket, error451);
	}
	context->DataIPv4 = context->ServerIPv4;
	context->DataPort = laddr.sin_port;
	context->DataSocket = datasocket;
	context->Mode = MODE_PASSIVE;
	
	sendstring(context->ControlSocket, success227);
	for (c = 0; c < 4; c++) {
		ultostr_a((context->DataIPv4 >> (c*8)) & 0xff, textbuf);
		_strcat_a(textbuf, ",");
		sendstring(context->ControlSocket, textbuf);
	}

	ultostr_a(context->DataPort & 0xff, textbuf);
	_strcat_a(textbuf, ",");
	sendstring(context->ControlSocket, textbuf);
	ultostr_a((context->DataPort >> 8) & 0xff, textbuf);
	_strcat_a(textbuf, ").");
	_strcat_a(textbuf, CRLF);

	writelogentry(context, " entering passive mode", NULL);

	return sendstring(context->ControlSocket, textbuf);
}

BOOL WINAPI ftpPORT(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	int		c;
	ULONG	DataIP = 0, DataP = 0;
	char	*p = (char *)params;

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);

	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	for (c = 0; c < 4; c++) {
		((BYTE *)&DataIP)[c] = (BYTE)strtoul_a(p);
		while ( (*p >= '0') && (*p <= '9') )
			p++;
		if ( *p == 0 )
			break;
		p++;
	}

	for (c = 0; c < 2; c++) {
		((BYTE *)&DataP)[c] = (BYTE)strtoul_a(p);
		while ( (*p >= '0') && (*p <= '9') )
			p++;
		if ( *p == 0 )
			break;
		p++;
	}

	if ( DataIP != context->ClientIPv4 )
		return sendstring(context->ControlSocket, error501);

	context->DataIPv4 = DataIP;
	context->DataPort = DataP;
	context->Mode = MODE_NORMAL;

	return sendstring(context->ControlSocket, success200);
}

BOOL WINAPI ftpREST(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);

	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	context->RestPoint.QuadPart = strtou64_a((char *)params);
	sendstring(context->ControlSocket, interm350);
	u64tostr_a(context->RestPoint.QuadPart, textbuf);
	_strcat_a(textbuf, CRLF);
	return sendstring(context->ControlSocket, textbuf);
}

BOOL WINAPI ftpCWD(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	WIN32_FILE_ATTRIBUTE_DATA	adata;
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	dirname[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, dirname, MAX_PATH) <= 0)
		dirname[0] = 0;

	if ( !GetFileAttributesEx(dirname, GetFileExInfoStandard, &adata) )
		return sendstring(context->ControlSocket, error550);
	if ( (adata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 )
		return sendstring(context->ControlSocket, error550);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	if ( *params != '\\' ) {
		_strcpy_a(textbuf, context->CurrentDir);
		addlastslash(textbuf);
	}
	_strcat_a(textbuf, params);
	addlastslash(textbuf);
	formatpath(textbuf);
	_strcpy_a(context->CurrentDir, textbuf);

	writelogentry(context, " CWD: ", (char *)params);

	return sendstring(context->ControlSocket, success250);
}

BOOL WINAPI ftpDELE(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( DeleteFile(filename) ) {
		sendstring(context->ControlSocket, success250);
		writelogentry(context, " DELE: ", (char *)params);
	}
	else
		sendstring(context->ControlSocket, error550_r);

	return TRUE;
}

BOOL WINAPI ftpRMD(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( RemoveDirectory(filename) ) {
		sendstring(context->ControlSocket, success250);
		writelogentry(context, " RMD: ", (char *)params);
	}
	else
		sendstring(context->ControlSocket, error550_r);

	return TRUE;
}

BOOL WINAPI ftpMKD(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_CREATENEW )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( CreateDirectory(filename, NULL) ) {
		sendstring(context->ControlSocket, success257);
		writelogentry(context, " MKD: ", (char *)params);
	}
	else
		sendstring(context->ControlSocket, error550);

	return TRUE;
}

BOOL WINAPI ftpSIZE(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	WIN32_FILE_ATTRIBUTE_DATA	adata;
	ULARGE_INTEGER				sz;
	CHAR						textbuf[MAX_PATH*3];
	TCHAR						filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( !GetFileAttributesEx(filename, GetFileExInfoStandard, &adata) )
		return sendstring(context->ControlSocket, error550);

	sz.HighPart = adata.nFileSizeHigh;
	sz.LowPart = adata.nFileSizeLow;

	sendstring(context->ControlSocket, "213 ");
	u64tostr_a(sz.QuadPart, textbuf);
	_strcat_a(textbuf, CRLF);
	
	sendstring(context->ControlSocket, textbuf);
	return TRUE;
}

BOOL WINAPI ftpUSER(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH*3];

	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	context->Access = FTP_ACCESS_NOT_LOGGED_IN;

	if (MultiByteToWideChar(CP_UTF8, 0, params, MAX_PATH, context->UserName, MAX_PATH) <= 0)
		context->UserName[0] = 0;

	writelogentry(context, " USER: ", (char *)params);

	_strcpy_a(textbuf, interm331);
	_strcat_a(textbuf, (char *)params);
	_strcat_a(textbuf, interm331_tail);
	return sendstring(context->ControlSocket, textbuf);
}

BOOL WINAPI ftpQUIT(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	UNREFERENCED_PARAMETER(params);

	writelogentry(context, " QUIT", NULL);
	sendstring(context->ControlSocket, success221);
	return FALSE;
}

BOOL WINAPI ftpNOOP(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	UNREFERENCED_PARAMETER(params);

	return sendstring(context->ControlSocket, success200);
}

BOOL WINAPI ftpPASS(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	TCHAR	ConfigFilePath[MAX_PATH+16], pswd[64], temptext[MAX_PATH];
	DWORD	cch, xtrue = TRUE;

	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
	GetCommandLineParam(GetCommandLine(), 1, ConfigFilePath, MAX_PATH, NULL);
	if ( ConfigFilePath[0] == 0 ) {
		GetCommandLineParam(GetCommandLine(), 0, ConfigFilePath, MAX_PATH, NULL);
		ExtractFilePath(ConfigFilePath, ConfigFilePath);
		_strcat(ConfigFilePath, CONFIG_FILE_NAME);
	}

	RtlSecureZeroMemory(pswd, sizeof(pswd));
	if ( GetPrivateProfileString(context->UserName, TEXT("pswd"), NULL, pswd, sizeof(pswd)/sizeof(TCHAR), ConfigFilePath) == 0 )
		return sendstring(context->ControlSocket, error530_r);

	if (MultiByteToWideChar(CP_UTF8, 0, params, MAX_PATH, temptext, MAX_PATH) <= 0)
		temptext[0] = 0;

	if ( (_strcmp(pswd, temptext) != 0) && (pswd[0] != '*') )
		return sendstring(context->ControlSocket, error530_r);
	
	RtlSecureZeroMemory(context->RootDir, sizeof(context->RootDir));
	RtlSecureZeroMemory(temptext, sizeof(temptext));

	cch = GetPrivateProfileString(context->UserName, TEXT("root"), NULL, temptext, MAX_PATH, ConfigFilePath);
	WideCharToMultiByte(CP_UTF8, 0, temptext, cch, context->RootDir, MAX_PATH, NULL, NULL);

	GetPrivateProfileString(context->UserName, TEXT("accs"), NULL, temptext, sizeof(temptext)/sizeof(TCHAR), ConfigFilePath);

	context->Access = FTP_ACCESS_NOT_LOGGED_IN;
	while ( xtrue ) {
		if ( _strcmpi(temptext, TEXT("admin")) == 0 ) {
			context->Access = FTP_ACCESS_FULL;
			break;
		}

		if ( _strcmpi(temptext, TEXT("upload")) == 0 ) {
			context->Access = FTP_ACCESS_CREATENEW;
			break;
		}
		
		if ( _strcmpi(temptext, TEXT("readonly")) == 0 ) {
			context->Access = FTP_ACCESS_READONLY;
			break;
		}

		return sendstring(context->ControlSocket, error530_b);
	};

	writelogentry(context, " PASS->logon successful", NULL);
	return sendstring(context->ControlSocket, success230);
}

BOOL WINAPI ftpSYST(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	UNREFERENCED_PARAMETER(params);

	return sendstring(context->ControlSocket, success215);
}

BOOL WINAPI ftpFEAT(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	UNREFERENCED_PARAMETER(params);

	sendstring(context->ControlSocket, success211);
	return sendstring(context->ControlSocket, success211_end);
}

BOOL WINAPI ftpPWD(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH];

	UNREFERENCED_PARAMETER(params);

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);

	sendstring(context->ControlSocket, "257 \"");
	_strcpy_a(textbuf, context->CurrentDir);
	nolastslash(textbuf);
	unixpath(textbuf);
	sendstring(context->ControlSocket, textbuf);
	sendstring(context->ControlSocket, "\" is a current directory.\r\n");

	return TRUE;
}

BOOL WINAPI ftpTYPE(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);

	if (params == NULL)
		return sendstring(context->ControlSocket, error501);
	
	switch (*params)
	{
	case 'A':
	case 'a':
		return sendstring(context->ControlSocket, success200_1);
	case 'I':
	case 'i':
		return sendstring(context->ControlSocket, success200_2);
	}

	return sendstring(context->ControlSocket, error501);
}

BOOL WINAPI ftpABOR(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	UNREFERENCED_PARAMETER(params);

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);

	StopWorkerThread(context);
	return sendstring(context->ControlSocket, success226);
}

BOOL WINAPI ftpCDUP(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	CHAR	textbuf[MAX_PATH];

	UNREFERENCED_PARAMETER(params);

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	_strcpy_a(textbuf, context->CurrentDir);
	nolastslash(textbuf);
	filepath(textbuf);
	addlastslash(textbuf);
	_strcpy_a(context->CurrentDir, textbuf);

	writelogentry(context, " CDUP", NULL);
	return sendstring(context->ControlSocket, success250);
}

BOOL WINAPI ftpRNFR(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	WIN32_FILE_ATTRIBUTE_DATA	adata;
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	RtlSecureZeroMemory(context->RenFrom, sizeof(context->RenFrom));
	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( GetFileAttributesEx(filename, GetFileExInfoStandard, &adata) == 0 )
		return sendstring(context->ControlSocket, error550);

	_strncpy(context->RenFrom, MAX_PATH, filename, MAX_PATH);

	writelogentry(context, " RNFR: ", (char *)params);
	return sendstring(context->ControlSocket, interm350_ren);
}

BOOL WINAPI ftpRNTO(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	WIN32_FILE_ATTRIBUTE_DATA	adata;
	CHAR	textbuf[MAX_PATH*3];
	TCHAR	filename[MAX_PATH];

	if ( context->Access == FTP_ACCESS_NOT_LOGGED_IN )
		return sendstring(context->ControlSocket, error530);
	if ( context->Access < FTP_ACCESS_FULL )
		return sendstring(context->ControlSocket, error550_r);
	if ( params == NULL )
		return sendstring(context->ControlSocket, error501);

	finalpath(context->RootDir, context->CurrentDir, (char *)params, textbuf);
	nolastslash(textbuf);

	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, filename, MAX_PATH) <= 0)
		filename[0] = 0;

	if ( GetFileAttributesEx(filename, GetFileExInfoStandard, &adata) != 0 )
		return sendstring(context->ControlSocket, error550);
	if ( !MoveFileEx(context->RenFrom, filename, MOVEFILE_COPY_ALLOWED) )
		return sendstring(context->ControlSocket, error550);

	RtlSecureZeroMemory(context->RenFrom, sizeof(context->RenFrom));

	writelogentry(context, " RNTO: ", (char *)params);
	return sendstring(context->ControlSocket, success250);
}

BOOL WINAPI ftpOPTS(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	UNREFERENCED_PARAMETER(params);
	UNREFERENCED_PARAMETER(context);

	return sendstring(context->ControlSocket, success200);
}

BOOL WINAPI ftpMLSD(
	IN PFTPCONTEXT context, 
	IN const char *params
	)
{
	WIN32_FILE_ATTRIBUTE_DATA	adata;
	HANDLE						wth;
	CHAR						textbuf[MAX_PATH * 3];

	UNREFERENCED_PARAMETER(params);

	if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
		return sendstring(context->ControlSocket, error530);
	if (context->WorkerThread != NULL)
		return sendstring(context->ControlSocket, error550_t);

	context->FileHandle = INVALID_HANDLE_VALUE;

	RtlSecureZeroMemory(textbuf, sizeof(textbuf));
	RtlSecureZeroMemory(context->TextBuffer, sizeof(context->TextBuffer));

	finalpath(context->RootDir, context->CurrentDir, NULL, textbuf);
	if (MultiByteToWideChar(CP_UTF8, 0, textbuf, MAX_PATH, context->TextBuffer, MAX_PATH) <= 0)
		context->TextBuffer[0] = 0;

	if (!GetFileAttributesEx(context->TextBuffer, GetFileExInfoStandard, &adata))
		return sendstring(context->ControlSocket, error550);
	if ((adata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		return sendstring(context->ControlSocket, error550);

	_strcat(context->TextBuffer, TEXT("*"));

	sendstring(context->ControlSocket, interm150);
	writelogentry(context, " MLSD-LIST", (char *)params);
	context->Stop = FALSE;

	wth = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&mlsd_thread, (LPVOID)context, 0, NULL);
	if (wth == NULL)
		sendstring(context->ControlSocket, error451);
	else
		context->WorkerThread = wth;

	return TRUE;
}

/* FTP COMMANDS END */

char recvchar(
	SOCKET s
	)
{
	char	c = 0;

	if ( recv(s, &c, 1, 0) != 1 )
		return 0;

	return c;
}

int recvcmd(
	SOCKET s, 
	char *buffer, 
	ULONG maxlen
	)
{
	char	r;
	ULONG	c;

	// skip first spaces or nonliteral characters, that is possible
	do {
		r = recvchar(s);
		if ( r == 0 )
			return FALSE;
	} while ( !( ((r>='a') && (r<='z')) || ((r>='A') && (r<='Z')) ) );

	for (c=0; c<maxlen; c++) {
		
		if ( r == '\r' ) // CR
			if ( recvchar(s) == '\n' ) { // LF
				buffer[c] = 0;
				return 1;
			} else
				return 0;

		if ( r == ' ' ) { // CR
			buffer[c] = 0;
			return 2;
		}

		buffer[c] = r;
		r = recvchar(s);
		if ( r == 0 )
			break;
	}
	return 0;
}

BOOL recvparams(
	SOCKET s, 
	char *buffer, 
	ULONG maxlen
	)
{
	char	r;
	ULONG	c;

	// skip first spaces
	do {
		r = recvchar(s);
		if ( r == 0 )
			return FALSE;
	} while ( r == ' ' );

	for (c=0; c<maxlen; c++) {
		
		if ( r == '\r' ) // CR
			if ( recvchar(s) == '\n' ) { // LF
				buffer[c] = 0;
				return TRUE;
			} else
				return FALSE;

		buffer[c] = r;
		r = recvchar(s);
		if ( r == 0 )
			return FALSE;
	}
	return FALSE;
}

DWORD WINAPI ftpthread(
	SOCKET *s
	)
{
	struct sockaddr_in	laddr;
	char				*p, cmd[8], params[MAX_PATH*2];
	int					c, i, cmdindex, asz, xfalse = FALSE;
	FTPCONTEXT			ctx;

	RtlSecureZeroMemory(&ctx, sizeof(ctx));
	ctx.Access = FTP_ACCESS_NOT_LOGGED_IN;
	ctx.ControlSocket = *s;
	ctx.FileHandle = INVALID_HANDLE_VALUE;
	ctx.LogHandle = g_LogHandle;

	RtlSecureZeroMemory(&laddr, sizeof(laddr));
	asz = sizeof(laddr);
	if ( getsockname(ctx.ControlSocket, (struct sockaddr *)&laddr, &asz) == SOCKET_ERROR ) // our IP
		goto error_exit;

	ctx.ServerIPv4 = laddr.sin_addr.S_un.S_addr;
	RtlSecureZeroMemory(&laddr, sizeof(laddr));
	asz = sizeof(laddr);
	if ( getpeername(ctx.ControlSocket, (struct sockaddr *)&laddr, &asz) == SOCKET_ERROR ) // client IP
		goto error_exit;

	ctx.ClientIPv4 = laddr.sin_addr.S_un.S_addr;
	ctx.Mode = MODE_NORMAL;
	ctx.Stop = FALSE;
	ctx.SessionID = InterlockedIncrement(&g_NewID);
	
	InitializeCriticalSection(&ctx.MTLock);
	do {
		ctx.CurrentDir[0] = '\\';
		sendstring(ctx.ControlSocket, success220);

		params[0] = 0;
		for (c = 0; c < 4; c++) {
			ultostr_a((ctx.ClientIPv4 >> (c*8)) & 0xff, _strend_a(params));

			if (c < 3)
				_strcat_a(params, ".");
			else
				_strcat_a(params, ":");
		}
		ultostr_a(((laddr.sin_port >> 8) & 0xff) + ((laddr.sin_port << 8) & 0xff00), _strend_a(params));
		
		writelogentry(&ctx, "<- New user IP=", params);

		while ( ctx.ControlSocket != INVALID_SOCKET ) {
			RtlSecureZeroMemory(cmd, sizeof(cmd));
			c = recvcmd(ctx.ControlSocket, cmd, 7);
			if ( c == 0 )
				break;

			if ( c == 1 )
				p = NULL;
			else {
				p = params;
				RtlSecureZeroMemory(params, sizeof(params));
				if ( !recvparams(ctx.ControlSocket, params, MAX_PATH*2) )
					break;
			}

			cmdindex = -1;
			for (i=0; i<MAX_CMDS; i++)
				if ( _strcmpi_a(ftpcmds[i], cmd) == 0 ) {
					cmdindex = i;
					break;
				}

			if ( cmdindex < 0 )
				sendstring(ctx.ControlSocket, error500);
			else
				if ( !ftpprocs[cmdindex](&ctx, p) )
					break;

		};
	} while ( xfalse );

	StopWorkerThread(&ctx);
	DeleteCriticalSection(&ctx.MTLock);
	writelogentry(&ctx, "User disconnected", NULL);

error_exit:
	closesocket(ctx.ControlSocket);
	*s = 0;
	return 0;
}

DWORD WINAPI ftpmain(
	PFTP_CONFIG p
	)
{
	SOCKET				ftpsocket = INVALID_SOCKET, clientsocket;
	SOCKET				*scb = NULL;
	struct sockaddr_in	laddr;
	int					socketret, asz;
	ULONG				i, maxusers = p->MaxUsers;
	HANDLE				th;

	p->ListeningSocket = INVALID_SOCKET;
	writeconsolestr(NULL, success220);

	ftpsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( ftpsocket == INVALID_SOCKET )
		return 0;

	scb = (SOCKET *)VirtualAlloc(NULL, sizeof(SOCKET)*maxusers, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if ( scb == NULL ) {
		closesocket(ftpsocket);
		return 0;
	}

	g_LogHandle = p->LogHandle;
	RtlSecureZeroMemory(scb, sizeof(SOCKET)*maxusers);
	RtlSecureZeroMemory(&laddr, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons((u_short)p->Port);
	laddr.sin_addr.S_un.S_addr = p->NetInterface;
	socketret = bind(ftpsocket, (struct sockaddr *)&laddr, sizeof(laddr));
	if  ( socketret != 0 ) {
		VirtualFree(scb, 0, MEM_RELEASE);
		closesocket(ftpsocket);
		return 0;
	}

	socketret = listen(ftpsocket, SOMAXCONN);
	while ( socketret == 0 ) {
		p->ListeningSocket = ftpsocket;
		RtlSecureZeroMemory(&laddr, sizeof(laddr));
		asz = sizeof(laddr);
		clientsocket = accept(ftpsocket, (struct sockaddr *)&laddr, &asz);
		if (clientsocket == INVALID_SOCKET) {
			if (p->ListeningSocket == INVALID_SOCKET)
				break;
		} else {
			th = NULL;
			for (i=0; i<maxusers; i++) {
				if ( scb[i] == 0 ) {
					scb[i] = clientsocket;
					th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&ftpthread, &scb[i], 0, NULL);
					if ( th != NULL )
						CloseHandle(th);
					break;
				}
			}

			if ( th == NULL ) {
				sendstring(clientsocket, noslots);
				closesocket(clientsocket);
			}
		}
	}

	VirtualFree(scb, 0, MEM_RELEASE);
	closesocket(ftpsocket);

	OutputDebugString(TEXT("\r\n*FTP thread exit*\r\n"));
	return 1;
}
