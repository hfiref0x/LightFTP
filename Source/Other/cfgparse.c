/*
 * cfgparse.c
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: July 06, 2017
 *
 *      Author: lightftp
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ParseConfig(const char *pcfg, const char *section_name, const char *key_name, char *value, unsigned long value_size_max)
{
	unsigned long	p = 0, sp;
	char			vname[256];

	if (value_size_max == 0)
		return 0;
	--value_size_max;

	while (pcfg[p] != 0)
	{
		/*
		 *  skip all characters before first '['
		 */
		while ((pcfg[p] != '[') && (pcfg[p] != 0))
			++p;

		/*
		 *  we got EOF so quit
		 */
		if (pcfg[p] == 0)
			break;

		/*
		 *  newline - start over again
		 */
		if ((pcfg[p] == '\r') || (pcfg[p] == '\n'))
			continue;

		/*
		 *  skip '[' that we found
		 */
		++p;

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

		/*
		 * newline - start over again
		 */
		if ((pcfg[p] == '\r') || (pcfg[p] == '\n'))
			continue;

		/*
		 * skip ']' that we found
		 */
		++p;

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
			/*
			 *  parse and skip all
			 */
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

char *InitConfig(char *cfg_filename)
{
	int		f_config;
	char	*buffer = NULL;
	off_t	fsz;

	f_config = open(cfg_filename, O_RDONLY);
	while (f_config != -1)
	{
		fsz = lseek(f_config, 0L, SEEK_END) + 1;
		lseek(f_config, 0L, SEEK_SET);

		buffer = malloc(fsz);
		if (buffer == NULL)
			break;

		fsz = read(f_config, buffer, fsz);
		buffer[fsz] = 0;
		break;
	}

	if (f_config != -1)
		close(f_config);

	return buffer;
}
