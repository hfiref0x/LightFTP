/*
 * main.c
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Jun 12, 2026
 *
 *      Author: lightftp
 */

#include "inc/ftpserv.h"
#include "inc/cfgparse.h"
#include "inc/x_malloc.h"
#include "inc/fcrypt.h"

ftp_config   g_cfg;
int          g_log = -1;

static char  CAFILE[PATH_MAX], CERTFILE[PATH_MAX], KEYFILE[PATH_MAX], KEYFILE_PASS[256];
char         GOODBYE_MSG[MSG_MAXLEN];

gnutls_dh_params_t					dh_params = NULL;
gnutls_certificate_credentials_t	x509_cred = NULL;
gnutls_priority_t					priority_cache = NULL;
gnutls_datum_t                      session_keys_storage = {0};

void ftp_tls_init();
void ftp_tls_cleanup();

static int read_password_stars(char *buffer, size_t buffer_size)
{
	struct termios	oldt, newt;
	int				ch;
	size_t			pos = 0;

	if ((buffer == NULL) || (buffer_size < 2))
		return 0;

	if (tcgetattr(STDIN_FILENO, &oldt) != 0)
		return 0;

	newt = oldt;
	newt.c_lflag &= ~(ECHO | ICANON);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
		return 0;

	memset(buffer, 0, buffer_size);

	while (1)
	{
		ch = getc(stdin);

		if ((ch == '\n') || (ch == '\r') || (ch == EOF))
			break;

		if ((ch == 0x08) || (ch == 0x7f))
		{
			if (pos > 0)
			{
				--pos;
				buffer[pos] = 0;
				printf("\b \b");
				fflush(stdout);
			}
			continue;
		}

		if ((ch >= 0x20) && (ch < 0x7f))
		{
			if (pos < (buffer_size - 1))
			{
				buffer[pos++] = (char)ch;
				printf("*");
				fflush(stdout);
			}
		}
	}

	printf("\r\n");
	fflush(stdout);

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return 1;
}

size_t get_salt(uint8_t *salt, size_t salt_size)
{
    int    file_fd, result;

    file_fd = open("/dev/urandom", O_RDONLY);
    if (file_fd == -1)
        return 0;
    result = read(file_fd, salt, salt_size);
    close(file_fd);
    return result;
}

/* Program entry point */
int main(int argc, char *argv[])
{
	char		*cfg = NULL, *textbuf = NULL,
			    *p, userpass[256], base64out[256];
	int			c, i, use_cli_password = 0;
	uint32_t	bufsize = 65536;
	pthread_t	thid;
	SHA256_CTX  shactx;
	uint8_t     salt[32], hash[32];

	struct in_addr na;

	if (sizeof (off_t) != 8)
	{
		printf("off_t is not 64 bits long");
		exit(1);
	}

	for (i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "-p") == 0)
		{
			use_cli_password = 1;
			continue;
		}

		if (cfg == NULL)
			cfg = config_init(argv[i]);
	}

	if (use_cli_password != 0)
	{
		memset(userpass, 0, sizeof(userpass));
		printf("Enter key password: ");
		if (!read_password_stars(userpass, sizeof(userpass)))
		{
			printf("Error: Failed to read password from keyboard\r\n");
			exit(1);
		}

        if (get_salt((uint8_t *)&salt, sizeof(salt)) < sizeof(salt))
		{
			printf("Error: Failed to get random salt value\r\n");
			exit(1);
		}

        sha256_init(&shactx);
        sha256_update(&shactx, (uint8_t *)&salt, sizeof(salt));
        sha256_update(&shactx, (uint8_t *)&userpass, strlen(userpass));
        sha256_final(&shactx, (uint8_t *)&hash);

        c = base64encode((uint8_t *)&salt, sizeof(salt), (char *)&base64out, sizeof(base64out));
        base64encode((uint8_t *)&hash, sizeof(hash), (char *)&base64out[c], sizeof(base64out)-c);

		printf("%s\r\n", base64out);
		exit(1);
	}

	if (cfg == NULL)
		cfg = config_init(CONFIG_FILE_NAME);

	while (cfg != NULL)
	{
		textbuf = x_malloc(bufsize);

		g_cfg.config_file = cfg;

		g_cfg.bind_to_interface = inet_addr("127.0.0.1");
		if (config_parse(cfg, CONFIG_SECTION_NAME, "interface", textbuf, bufsize))
			g_cfg.bind_to_interface = inet_addr(textbuf);

		g_cfg.external_interface = inet_addr("0.0.0.0");
		if (config_parse(cfg, CONFIG_SECTION_NAME, "external_ip", textbuf, bufsize))
			g_cfg.external_interface = inet_addr(textbuf);

		g_cfg.local_ip_mask = inet_addr("255.255.255.0");
		if (config_parse(cfg, CONFIG_SECTION_NAME, "local_mask", textbuf, bufsize))
			g_cfg.local_ip_mask = inet_addr(textbuf);

		g_cfg.port = DEFAULT_FTP_PORT;
		if (config_parse(cfg, CONFIG_SECTION_NAME, "port", textbuf, bufsize))
			g_cfg.port = (in_port_t)strtoul(textbuf, NULL, 10);

		g_cfg.max_users = 1;
		if (config_parse(cfg, CONFIG_SECTION_NAME, "maxusers", textbuf, bufsize))
			g_cfg.max_users = strtoul(textbuf, NULL, 10);

		g_cfg.enable_keepalive = 0;
		if (config_parse(cfg, CONFIG_SECTION_NAME, "keepalive", textbuf, bufsize))
			g_cfg.enable_keepalive = strtoul(textbuf, NULL, 10);

		g_cfg.file_open_flags = O_NOFOLLOW;
		if (config_parse(cfg, CONFIG_SECTION_NAME, "follow_symlinks", textbuf, bufsize))
        {
            if (strtoul(textbuf, NULL, 10) != 0)
                g_cfg.file_open_flags &= ~O_NOFOLLOW;
        }

		g_cfg.pasv_port_base = 1024;
		if (config_parse(cfg, CONFIG_SECTION_NAME, "minport", textbuf, bufsize))
			g_cfg.pasv_port_base = (in_port_t)strtoul(textbuf, NULL, 10);

		g_cfg.pasv_port_max = 65535;
		if (config_parse(cfg, CONFIG_SECTION_NAME, "maxport", textbuf, bufsize))
			g_cfg.pasv_port_max = (in_port_t)strtoul(textbuf, NULL, 10);

		config_parse(cfg, CONFIG_SECTION_NAME, "CATrustFile", CAFILE, sizeof(CAFILE));
		config_parse(cfg, CONFIG_SECTION_NAME, "ServerCertificate", CERTFILE, sizeof(CERTFILE));
		config_parse(cfg, CONFIG_SECTION_NAME, "Keyfile", KEYFILE, sizeof(KEYFILE));
		config_parse(cfg, CONFIG_SECTION_NAME, "KeyfilePassword", KEYFILE_PASS, sizeof(KEYFILE_PASS));
		config_parse(cfg, CONFIG_SECTION_NAME, "goodbyemsg", GOODBYE_MSG, sizeof(GOODBYE_MSG));

		memset(textbuf, 0, bufsize);
		if (config_parse(cfg, CONFIG_SECTION_NAME, "logfilepath", textbuf, bufsize))
		{
			g_log = open(textbuf, O_RDWR | O_CREAT | O_CLOEXEC, S_IWUSR | S_IRUSR);
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

		printf("\r\n    [ LightFTP server v%s ]\r\n\r\n", FTP_VERSION);
		printf("Log file        : %s\r\n", textbuf);

		p = getcwd(textbuf, bufsize);
		if (p != NULL )
			printf("Working dir     : %s\r\n", textbuf);

		if (argc > 1)
			printf("Config file     : %s\r\n", argv[1]);
		else
			printf("Config file     : %s/%s\r\n", textbuf, CONFIG_FILE_NAME);

		na.s_addr = g_cfg.bind_to_interface;
		printf("Interface ipv4  : %s\r\n", inet_ntoa(na));
		na.s_addr = g_cfg.local_ip_mask;
		printf("Interface mask  : %s\r\n", inet_ntoa(na));
		na.s_addr = g_cfg.external_interface;
		printf("External ipv4   : %s\r\n", inet_ntoa(na));

		printf("Port            : %u\r\n", g_cfg.port);
		printf("Max users       : %" PRIu64 "\r\n", g_cfg.max_users);
		printf("PASV port range : %u..%u\r\n", g_cfg.pasv_port_base, g_cfg.pasv_port_max);

		printf("\r\n Use with -p to generate encrypted password\r\n");
		printf("\r\n TYPE q or Ctrl+C to terminate >\r\n");

		ftp_tls_init();

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

	memset(KEYFILE_PASS, 0, sizeof(KEYFILE_PASS));

	if (cfg == NULL)
        printf("Could not find configuration file\r\n\r\n Usage: fftp [CONFIGFILE] [-p]\r\n\r\n");
    else
        free(cfg);

    if (g_log != -1)
        close(g_log);

    if (textbuf != NULL)
        free(textbuf);

    ftp_tls_cleanup();

	exit(0);
}

void ftp_tls_init()
{
	while (gnutls_global_init() >= 0)
	{
		if (gnutls_certificate_allocate_credentials(&x509_cred) < 0)
    		break;

    	if (gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM) < 0)
    		break;

    	if (gnutls_certificate_set_x509_key_file2(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM, KEYFILE_PASS, 0) < 0)
    		break;

    	if (gnutls_priority_init(&priority_cache, NULL, NULL) < 0)
    		break;

    	if (gnutls_session_ticket_key_generate(&session_keys_storage) != GNUTLS_E_SUCCESS)
    	    break;

#if GNUTLS_VERSION_NUMBER >= 0x030506
    	gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_HIGH);
#else
    	gnutls_dh_params_init(&dh_params);
    	gnutls_dh_params_generate2(dh_params, gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_HIGH));
    	gnutls_certificate_set_dh_params(x509_cred, dh_params);
#endif
    	break;
    }
}

void ftp_tls_cleanup()
{
#if GNUTLS_VERSION_NUMBER < 0x030506
	if ( dh_params != NULL)
		gnutls_dh_params_deinit(dh_params);
#endif

	if ( x509_cred != NULL )
		gnutls_certificate_free_credentials(x509_cred);

	if ( priority_cache != NULL )
		gnutls_priority_deinit(priority_cache);

	if (session_keys_storage.data)
	{
	    gnutls_memset(session_keys_storage.data, 0, session_keys_storage.size);
	    gnutls_free(session_keys_storage.data);
	}

	gnutls_global_deinit();
}
