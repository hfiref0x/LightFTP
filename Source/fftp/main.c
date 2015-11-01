
#include <windows.h>
#include <process.h>
#include "minirtl\minirtl.h"
#include "minirtl\cmdline.h"
#include "ftpserv.h"

#if !defined UNICODE
#error ANSI build is not supported
#endif

DWORD		dwMainThreadId = 0;
HANDLE		th = NULL;
FTP_CONFIG	cfg;

BOOL WINAPI ConHandler(
	_In_  DWORD dwCtrlType
	)
{
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:

		closesocket(cfg.ListeningSocket);
		cfg.ListeningSocket = INVALID_SOCKET;
		if (WaitForSingleObjectEx(th, 4000, FALSE) == STATUS_TIMEOUT)
			TerminateThread(th, 0);

		PostThreadMessage(dwMainThreadId, WM_QUIT, 0, 0);
		return TRUE;
	}

	return FALSE;
}

void main()
{
	TCHAR			ConfigFilePath[MAX_PATH+16], textkeybuf[MAX_PATH+40];
	char			logbuf[MAX_PATH];
	WSADATA			wsdat1;
	int				wsaerr;
	MSG				msg1;
	BOOL			rv;
	ULARGE_INTEGER	UT;
	FILETIME		t;

	__security_init_cookie();

	dwMainThreadId = GetCurrentThreadId();
	SetConsoleCtrlHandler(&ConHandler, TRUE);

	RtlSecureZeroMemory(&wsdat1, sizeof(wsdat1));
	wsaerr = WSAStartup(0x0001, &wsdat1);
	if (wsaerr != 0)
		goto err1;

	RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
	GetCommandLineParam(GetCommandLine(), 1, ConfigFilePath, MAX_PATH, NULL);
	if ( ConfigFilePath[0] == 0 ) {
		GetCommandLineParam(GetCommandLine(), 0, ConfigFilePath, MAX_PATH, NULL);
		ExtractFilePath(ConfigFilePath, ConfigFilePath);
		_strcat(ConfigFilePath, CONFIG_FILE_NAME);
	}

	RtlSecureZeroMemory(&textkeybuf, sizeof(textkeybuf));
	GetPrivateProfileString(CONFIG_SECTION_NAME, TEXT("interface"), NULL, textkeybuf, sizeof(textkeybuf)/sizeof(TCHAR), ConfigFilePath);
	WideCharToMultiByte(CP_UTF8, 0, textkeybuf, MAX_PATH, logbuf, MAX_PATH, NULL, NULL);
	cfg.NetInterface = inet_addr(logbuf);

	RtlSecureZeroMemory(&textkeybuf, sizeof(textkeybuf));
	GetPrivateProfileString(CONFIG_SECTION_NAME, TEXT("port"), NULL, textkeybuf, sizeof(textkeybuf)/sizeof(TCHAR), ConfigFilePath);
	cfg.Port = strtoul(textkeybuf);
	if ( cfg.Port == 0 )
		cfg.Port = DEFAULT_FTP_PORT;

	RtlSecureZeroMemory(&textkeybuf, sizeof(textkeybuf));
	GetPrivateProfileString(CONFIG_SECTION_NAME, TEXT("maxusers"), NULL, textkeybuf, sizeof(textkeybuf)/sizeof(TCHAR), ConfigFilePath);
	cfg.MaxUsers = strtoul(textkeybuf);
	if ( cfg.MaxUsers == 0 )
		cfg.MaxUsers = 1;

	RtlSecureZeroMemory(&textkeybuf, sizeof(textkeybuf));
	GetPrivateProfileString(CONFIG_SECTION_NAME, TEXT("logfilepath"), NULL, textkeybuf, sizeof(textkeybuf)/sizeof(TCHAR), ConfigFilePath);

	cfg.LogHandle = NULL;
	if ( textkeybuf[0] != 0 ) {
		GetSystemTimeAsFileTime(&t);
		UT.LowPart = t.dwLowDateTime;
		UT.HighPart = t.dwHighDateTime;
		_strcat(textkeybuf, TEXT("\\ftplog-"));
		u64tostr(UT.QuadPart, _strend(textkeybuf));
		_strcat(textkeybuf, TEXT(".txt"));
		cfg.LogHandle = CreateFile(textkeybuf, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	writeconsolestr(cfg.LogHandle, "Config file : ");
	WideCharToMultiByte(CP_UTF8, 0, ConfigFilePath, MAX_PATH, logbuf, MAX_PATH, NULL, NULL);
	writeconsolestr(cfg.LogHandle, logbuf);
	writeconsolestr(cfg.LogHandle, CRLF);

	writeconsolestr(cfg.LogHandle, "Log file    : ");
	WideCharToMultiByte(CP_UTF8, 0, textkeybuf, MAX_PATH, logbuf, MAX_PATH, NULL, NULL);
	writeconsolestr(cfg.LogHandle, logbuf);
	writeconsolestr(cfg.LogHandle, CRLF);

	writeconsolestr(cfg.LogHandle, "Interface   : ");
	ultostr_a(cfg.NetInterface & 0xff, logbuf);
	_strcat_a(logbuf, ".");
	ultostr_a((cfg.NetInterface >> 8) & 0xff, _strend_a(logbuf));
	_strcat_a(logbuf, ".");
	ultostr_a((cfg.NetInterface >> 16) & 0xff, _strend_a(logbuf));
	_strcat_a(logbuf, ".");
	ultostr_a((cfg.NetInterface >> 24) & 0xff, _strend_a(logbuf));
	_strcat_a(logbuf, CRLF);
	writeconsolestr(cfg.LogHandle, logbuf);

	writeconsolestr(cfg.LogHandle, "Port        : ");
	ultostr_a(cfg.Port, logbuf);
	_strcat_a(logbuf, CRLF);
	writeconsolestr(cfg.LogHandle, logbuf);

	th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&ftpmain, &cfg, 0, NULL);
	if (th == NULL)
		goto err2;

/* common message loop for Windows application */
	do {
		rv = GetMessage(&msg1, NULL, 0, 0);

		if ( rv == -1 )
			break;
		
		TranslateMessage(&msg1);
		DispatchMessage(&msg1);
	} while (rv != 0);

	CloseHandle(th);

	if ( (cfg.LogHandle != NULL) && (cfg.LogHandle != INVALID_HANDLE_VALUE) )
		CloseHandle(cfg.LogHandle);

	OutputDebugString(TEXT("\r\nNormal exit\r\n"));

err2:
	WSACleanup();
err1:
	ExitProcess(1);
}
