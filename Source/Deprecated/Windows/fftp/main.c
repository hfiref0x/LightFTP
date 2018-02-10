#include <windows.h>
#include <process.h>
#include "minirtl\minirtl.h"
#include "minirtl\cmdline.h"
#include "ftpserv.h"

#if !defined UNICODE
#error only UNICODE build is supported
#endif

DWORD		dwMainThreadId = 0;
HANDLE		g_Thread = NULL;

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

		closesocket(g_cfg.ListeningSocket);
		g_cfg.ListeningSocket = INVALID_SOCKET;
		if (WaitForSingleObjectEx(g_Thread, 4000, FALSE) == STATUS_TIMEOUT)
			TerminateThread(g_Thread, 0);

		PostThreadMessage(dwMainThreadId, WM_QUIT, 0, 0);
		return TRUE;
	}

	return FALSE;
}

int ParseConfig(const char *pcfg, const char *section_name, const char *key_name, char *value, unsigned long value_size_max)
{
	unsigned long	p = 0, sp;
	char			vname[256];

	if (value_size_max == 0)
		return 0;
	--value_size_max;

	while (pcfg[p] != 0)
	{
		while ((pcfg[p] != '[') && (pcfg[p] != 0))  // skip all characters before first '['
			++p;

		if (pcfg[p] == 0) // we got eof so quit
			break;

		if ((pcfg[p] == '\r') || (pcfg[p] == '\n'))  // newline - start over again
			continue;

		++p; // skip '[' that we found
		
		sp = 0;
		while ((pcfg[p] != ']') && (pcfg[p] != 0) && (pcfg[p] != '\r') && (pcfg[p] != '\n') && (sp < 255))
		{
			vname[sp] = pcfg[p];
			++sp;
			++p;
		}
		vname[sp] = 0;

		if (pcfg[p] == 0)
			break;

		if ((pcfg[p] == '\r') || (pcfg[p] == '\n'))  // newline - start over again
			continue;

		++p; // skip ']' that we found

		if (strcmp(vname, section_name) == 0)
		{
			do {
				while ((pcfg[p] == ' ') || (pcfg[p] == '\r') || (pcfg[p] == '\n'))
					++p;

				if ((pcfg[p] == 0) || (pcfg[p] == '['))
					break;

				sp = 0;
				while ((pcfg[p] != '=') && (pcfg[p] != 0) && (pcfg[p] != '\r') && (pcfg[p] != '\n') && (sp < 255))
				{
					vname[sp] = pcfg[p];
					++sp;
					++p;
				}
				vname[sp] = 0;

				if (pcfg[p] == 0)
					break;
				++p;

				if (strcmp(vname, key_name) == 0)
				{
					sp = 0;
					while ((pcfg[p] != '\r') && (pcfg[p] != '\n') && (pcfg[p] != 0))
					{
						if (sp < value_size_max)
							value[sp] = pcfg[p];
						else
							return 0;
						++sp;
						++p;
					}
					value[sp] = 0;
					return 1;
				}
				else
				{
					while ((pcfg[p] != '\r') && (pcfg[p] != '\n') && (pcfg[p] != 0))
						++p;
				}

			} while (pcfg[p] != 0);
		}
		else
		{
			// parse and skip all
			do {
				while ((pcfg[p] == ' ') || (pcfg[p] == '\r') || (pcfg[p] == '\n'))
					++p;

				if ((pcfg[p] == 0) || (pcfg[p] == '['))
					break;

				while ((pcfg[p] != '=') && (pcfg[p] != 0) && (pcfg[p] != '\r') && (pcfg[p] != '\n'))
					++p;

				if (pcfg[p] == 0)
					break;
				++p;

				while ((pcfg[p] != '\r') && (pcfg[p] != '\n') && (pcfg[p] != 0))
						++p;

			} while (pcfg[p] != 0);
		}
	}

	return 0;
}

char *InitConfig(LPTSTR cfg_filename)
{
    BOOL            cond = FALSE;
	ULONG			iobytes;
	HANDLE			f = INVALID_HANDLE_VALUE;
	char			*buffer = NULL;
	LARGE_INTEGER	fsz;

	f = CreateFile(cfg_filename, GENERIC_READ | SYNCHRONIZE,
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    do {

        if (f == INVALID_HANDLE_VALUE)
            break;

        fsz.QuadPart = 0;
        if (!GetFileSizeEx(f, &fsz))
            break;

        fsz.LowPart += 1;
        buffer = (char *)VirtualAlloc(NULL, fsz.LowPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buffer == NULL)
            break;

        if (!ReadFile(f, buffer, fsz.LowPart - 1, &iobytes, NULL))
            break;

        buffer[fsz.LowPart - 1] = 0;

    } while (cond);

	if (f != INVALID_HANDLE_VALUE )
		CloseHandle(f);

	return buffer;
}

void main()
{
	WSADATA			wsdat1;
	int				wsaerr;
	MSG				msg1;
	BOOL			rv;
	ULARGE_INTEGER	UT;
	FILETIME		t;
	char			*cfg = NULL, textbuf[MAX_PATH];
	TCHAR			ConfigFilePath[MAX_PATH];

	__security_init_cookie();

	dwMainThreadId = GetCurrentThreadId();
	SetConsoleCtrlHandler(&ConHandler, TRUE);

	RtlSecureZeroMemory(&wsdat1, sizeof(wsdat1));
	wsaerr = WSAStartup(0x0001, &wsdat1);
	
	while (wsaerr == 0)
	{
		RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
		GetCommandLineParam(GetCommandLine(), 1, ConfigFilePath, MAX_PATH, NULL);
		if (ConfigFilePath[0] == 0) {
			GetModuleFileName(NULL, ConfigFilePath, MAX_PATH);
			ExtractFilePath(ConfigFilePath, ConfigFilePath);
			_strcat(ConfigFilePath, CONFIG_FILE_NAME);
		}

        cfg = InitConfig(ConfigFilePath);
		if (cfg == NULL)
		{
			writeconsolestr("Could not find configuration file\r\n\r\n Usage: fftp [CONFIGFILE]\r\n\r\n");
			break;
		}

		g_cfg.ConfigFile = cfg;

		g_cfg.BindToInterface = inet_addr("127.0.0.1");
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "interface", textbuf, MAX_PATH))
			g_cfg.BindToInterface = inet_addr(textbuf);

		g_cfg.ExternalInterface = inet_addr("0.0.0.0");
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "external_ip", textbuf, MAX_PATH))
			g_cfg.ExternalInterface = inet_addr(textbuf);

		g_cfg.LocalIPMask = inet_addr("255.255.255.0");
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "local_mask", textbuf, MAX_PATH))
			g_cfg.LocalIPMask = inet_addr(textbuf);

		g_cfg.Port = DEFAULT_FTP_PORT;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "port", textbuf, MAX_PATH))
			g_cfg.Port = strtoul_a(textbuf);

		g_cfg.MaxUsers = 1;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "maxusers", textbuf, MAX_PATH))
			g_cfg.MaxUsers = strtoul_a(textbuf);

		g_cfg.PasvPortBase = 100;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "minport", textbuf, MAX_PATH))
			g_cfg.PasvPortBase = strtoul_a(textbuf);
		
		g_cfg.PasvPortMax = 65535;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "maxport", textbuf, MAX_PATH))
			g_cfg.PasvPortMax = strtoul_a(textbuf);

		g_LogHandle = INVALID_HANDLE_VALUE;
		RtlSecureZeroMemory(&textbuf, sizeof(textbuf));
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "logfilepath", textbuf, MAX_PATH))
		{
			GetSystemTimeAsFileTime(&t);
			UT.LowPart = t.dwLowDateTime;
			UT.HighPart = t.dwHighDateTime;
			_strcat_a(textbuf, "\\ftplog-");
			u64tostr_a(UT.QuadPart, _strend_a(textbuf));
			_strcat_a(textbuf, ".txt");
			g_LogHandle = CreateFileA(textbuf, GENERIC_WRITE | SYNCHRONIZE,
				FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		}
		else
		{
			writeconsolestr("Error: logfilepath section is not found in configuration\r\n");
			break;
		}

		if (g_LogHandle == INVALID_HANDLE_VALUE)
		{
			writeconsolestr("Error: Failed to open / create log file. Please check logfilepath\r\n");
			break;
		}

		writeconsolestr("Log file    : ");
		writeconsolestr(textbuf);
		writeconsolestr(CRLF);

		writeconsolestr("Config file : ");
		WideCharToMultiByte(CP_UTF8, 0, ConfigFilePath, MAX_PATH, textbuf, MAX_PATH, NULL, NULL);
		writeconsolestr(textbuf);
		writeconsolestr(CRLF);

		writeconsolestr("Interface   : ");
		ultostr_a(g_cfg.BindToInterface & 0xff, textbuf);
		_strcat_a(textbuf, ".");
		ultostr_a((g_cfg.BindToInterface >> 8) & 0xff, _strend_a(textbuf));
		_strcat_a(textbuf, ".");
		ultostr_a((g_cfg.BindToInterface >> 16) & 0xff, _strend_a(textbuf));
		_strcat_a(textbuf, ".");
		ultostr_a((g_cfg.BindToInterface >> 24) & 0xff, _strend_a(textbuf));
		_strcat_a(textbuf, CRLF);
		writeconsolestr(textbuf);

		writeconsolestr("Port        : ");
		ultostr_a(g_cfg.Port, textbuf);
		_strcat_a(textbuf, CRLF);
		writeconsolestr(textbuf);

        g_Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&ftpmain, NULL, 0, NULL);
		if (g_Thread == NULL)
		{
			writeconsolestr("Error: Failed to create main server thread\r\n");
			break;
		}

		/* common message loop for Windows application */
		do {
			rv = GetMessage(&msg1, NULL, 0, 0);

			if (rv == -1)
				break;

			TranslateMessage(&msg1);
			DispatchMessage(&msg1);
		} while (rv != 0);

		CloseHandle(g_Thread);

		if ((g_LogHandle != NULL) && (g_LogHandle != INVALID_HANDLE_VALUE))
			CloseHandle(g_LogHandle);

		OutputDebugString(TEXT("\r\nNormal exit\r\n"));
		break;
	}

	WSACleanup();
	ExitProcess(1);
}
