/*
 * main.c
 *
 *  Created on: Aug 21, 2016
 *      Author: lightftp
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cfgparse.h"
#include "ftpserv.h"

FTP_CONFIG	g_cfg;
int			g_log = -1;

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
		textbuf = malloc(bufsize);
		if (textbuf == NULL)
			break;

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

		memset(textbuf, 0, bufsize);
		if (!ParseConfig(cfg, CONFIG_SECTION_NAME, "logfilepath", textbuf, bufsize))
			break;

		g_log = open(textbuf, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR);
		if (g_log == -1)
			break;

		lseek(g_log, 0L, SEEK_END);

		printf("\r\n    [ LightFTP server v1.1 ]\r\n\r\n");
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

		thid = (pthread_t)0;
		if (pthread_create(&thid, NULL, &ftpmain, NULL) != 0)
			break;

		do {
			c = getc(stdin);
		} while ((c != 'q') && (c != 'Q'));

		break;
	}

	close(g_log);

	if (cfg != NULL)
		free(cfg);

	if (textbuf != NULL)
		free(textbuf);

	exit(2);
}
