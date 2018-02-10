/*
* main.c
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

FTP_CONFIG	g_cfg;
int			g_log = -1;

gnutls_dh_params_t					dh_params = NULL;
gnutls_certificate_credentials_t	x509_cred = NULL;
gnutls_priority_t					priority_cache = NULL;

static	char	CAFILE[PATH_MAX],
				CERTFILE[PATH_MAX],
				KEYFILE[PATH_MAX],
				KEYFILE_PASS[256];

void TLSInit()
{
	while (gnutls_global_init() >= 0)
	{
		if (gnutls_certificate_allocate_credentials(&x509_cred) < 0)
    		break;

    	if (gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
    			GNUTLS_X509_FMT_PEM) < 0)
    		break;

    	if (gnutls_certificate_set_x509_key_file2(x509_cred, CERTFILE,
    			KEYFILE, GNUTLS_X509_FMT_PEM, KEYFILE_PASS, 0) < 0)
    		break;

    	if (gnutls_priority_init(&priority_cache, NULL, NULL) < 0)
    		break;

#if GNUTLS_VERSION_NUMBER >= 0x030506
    	gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_HIGH);
#else
    	gnutls_dh_params_init(&dh_params);
    	gnutls_dh_params_generate2(dh_params,
    			gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_HIGH));
    	gnutls_certificate_set_dh_params(x509_cred, dh_params);
    	gnutls_dh_params_deinit(dh_params);
#endif
    	break;
    }
}

void TLSCleanup()
{
#if GNUTLS_VERSION_NUMBER < 0x030506
	if ( dh_params != NULL)
		gnutls_dh_params_deinit(dh_params);
#endif

	if ( x509_cred != NULL )
		gnutls_certificate_free_credentials(x509_cred);

	if ( priority_cache != NULL )
		gnutls_priority_deinit(priority_cache);

	gnutls_global_deinit();
}

int main(int argc, char *argv[])
{
	char		*cfg = NULL, *textbuf = NULL;
	int			c;
	uint32_t	bufsize = 65536;
	pthread_t	thid;

	if (sizeof (off_t) != 8)
	{
		printf("off_t is not 64 bits long");
		return 0;
	}

	if (argc > 1)
		cfg = InitConfig(argv[1]);
	else
		cfg = InitConfig(CONFIG_FILE_NAME);

	while (cfg != NULL)
	{
		textbuf = x_malloc(bufsize);

		g_cfg.ConfigFile = cfg;

		g_cfg.BindToInterface = inet_addr("127.0.0.1");
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "interface", textbuf, bufsize))
			g_cfg.BindToInterface = inet_addr(textbuf);

		g_cfg.ExternalInterface = inet_addr("0.0.0.0");
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "external_ip", textbuf, bufsize))
			g_cfg.ExternalInterface = inet_addr(textbuf);

		g_cfg.LocalIPMask = inet_addr("255.255.255.0");
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "local_mask", textbuf, bufsize))
			g_cfg.LocalIPMask = inet_addr(textbuf);

		g_cfg.Port = DEFAULT_FTP_PORT;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "port", textbuf, bufsize))
			g_cfg.Port = strtoul(textbuf, NULL, 10);

		g_cfg.MaxUsers = 1;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "maxusers", textbuf, bufsize))
			g_cfg.MaxUsers = strtoul(textbuf, NULL, 10);

		g_cfg.PasvPortBase = 1024;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "minport", textbuf, bufsize))
			g_cfg.PasvPortBase = strtoul(textbuf, NULL, 10);

		g_cfg.PasvPortMax = 65535;
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "maxport", textbuf, bufsize))
			g_cfg.PasvPortMax = strtoul(textbuf, NULL, 10);

		ParseConfig(cfg, CONFIG_SECTION_NAME, "CATrustFile", CAFILE, sizeof(CAFILE));
		ParseConfig(cfg, CONFIG_SECTION_NAME, "ServerCertificate", CERTFILE, sizeof(CERTFILE));
		ParseConfig(cfg, CONFIG_SECTION_NAME, "Keyfile", KEYFILE, sizeof(KEYFILE));
		ParseConfig(cfg, CONFIG_SECTION_NAME, "KeyfilePassword", KEYFILE_PASS, sizeof(KEYFILE_PASS));

		memset(textbuf, 0, bufsize);
		if (ParseConfig(cfg, CONFIG_SECTION_NAME, "logfilepath", textbuf, bufsize))
		{
			g_log = open(textbuf, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR);
			if (g_log == -1)
			{
				printf("Error: Failed to open/create log file. Please check logfilepath: %s\r\n", textbuf);
				printf("Possible errors: 1) path is invalid; 2) file is read only; 3) file is directory; 4) insufficient permissions\r\n");
				break;
			}

		} else
			printf("WARNING: logfilepath section is not found in configuration. Logging to file disabled.\r\n");

        if (g_log != -1)
            lseek(g_log, 0L, SEEK_END);

		printf("\r\n    [ LightFTP server v2.0 ]\r\n\r\n");
		printf("Log file        : %s\r\n", textbuf);

		getcwd(textbuf, bufsize);
		printf("Working dir     : %s\r\n", textbuf);

		if (argc > 1)
			printf("Config file     : %s\r\n", argv[1]);
		else
			printf("Config file     : %s/%s\r\n", textbuf, CONFIG_FILE_NAME);

		printf("Interface ipv4  : %u.%u.%u.%u\r\n",
				g_cfg.BindToInterface & 0xff,
				(g_cfg.BindToInterface >> 8) & 0xff,
				(g_cfg.BindToInterface >> 16) & 0xff,
				(g_cfg.BindToInterface >> 24) & 0xff);

		printf("Interface mask  : %u.%u.%u.%u\r\n",
				g_cfg.LocalIPMask & 0xff,
				(g_cfg.LocalIPMask >> 8) & 0xff,
				(g_cfg.LocalIPMask >> 16) & 0xff,
				(g_cfg.LocalIPMask >> 24) & 0xff);

		printf("External ipv4   : %u.%u.%u.%u\r\n",
				g_cfg.ExternalInterface & 0xff,
				(g_cfg.ExternalInterface >> 8) & 0xff,
				(g_cfg.ExternalInterface >> 16) & 0xff,
				(g_cfg.ExternalInterface >> 24) & 0xff);

		printf("Port            : %u\r\n", g_cfg.Port);
		printf("Max users       : %u\r\n", g_cfg.MaxUsers);
		printf("PASV port range : %u..%u\r\n", g_cfg.PasvPortBase, g_cfg.PasvPortMax);

		printf("\r\n TYPE q or Ctrl+C to terminate >\r\n");

		TLSInit();

		thid = (pthread_t)0;
		if (pthread_create(&thid, NULL, &ftpmain, NULL) != 0)
		{
			printf("Error: Failed to create main server thread\r\n");
			break;
		}

		do {
			c = getc(stdin);
			sleep(1);
		} while ((c != 'q') && (c != 'Q'));

		break;
	}

    if (cfg == NULL)
		printf("Could not find configuration file\r\n\r\n Usage: fftp [CONFIGFILE]\r\n\r\n");

	if (g_log != -1) 
        close(g_log);

	if (cfg != NULL)
		free(cfg);

	if (textbuf != NULL)
		free(textbuf);

	TLSCleanup();

	exit(2);
}
