/*
* cfgparse.c
*
*  Created on: Aug 20, 2016
*
*  Modified on: Feb 09, 2018
*
*      Author: lightftp
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "x_malloc.h"

char *skip_comments_and_blanks(char *p)
{
	while (*p != 0) {

		while (
				(*p == ' ') ||
				(*p == '\n')
				)
			++p;

		if (*p == '#')
		{
			++p;

			while (
					(*p != 0) &&
					(*p != '\n')
					)
				++p;

			continue;
		}
		else
			break;

	}

	return p;
}

/* TODO: Rewrite this function */

int config_parse(
    const char      *pcfg,
    const char      *section_name,
    const char      *key_name,
    char            *value,
    unsigned long   value_size_max)
{
	unsigned long	sp;
	char			vname[256], *p = (char *)pcfg;

	if (value_size_max == 0)
		return 0;
	--value_size_max;

	while (*p != 0)
	{
		/*
		 *  skip all characters before first '['
		 */
		p = skip_comments_and_blanks(p);

		/*
		 *  if we got EOF so quit
		 */
		if (*p == 0)
			break;

		if (*p != '[')
		{
			++p;
			continue;
		}

		/*
		 *  skip '[' that we found
		 */
		++p;

		/*
		 * copy section name to vname
		 */
		sp = 0;
		while (
				(*p != ']') &&
				(*p != 0) &&
				(*p != '\n') &&
				(sp < 255)
				)
		{
			vname[sp] = *p;
			++sp;
			++p;
		}
		vname[sp] = 0;

		if (*p == 0)
			break;

		/*
		 * newline - start over again
		 */
		if (*p == '\n')
			continue;

		/*
		 * skip ']' that we found
		 */
		++p;

		if (strcmp(vname, section_name) == 0)
		{
			do {
				p = skip_comments_and_blanks(p);
				if ((*p == 0) || (*p == '['))
					break;

				sp = 0;
				while (
						(*p != '=') &&
						(*p != ' ') &&
						(*p != 0) &&
						(*p != '\n') &&
						(sp < 255)
						)
				{
					vname[sp] = *p;
					++sp;
					++p;
				}
				vname[sp] = 0;

				if (*p == 0)
					break;

				while (*p == ' ')
					++p;

				if (*p != '=')
					break;

				p++;

				if (strcmp(vname, key_name) == 0)
				{
					sp = 0;

					while (
							(*p != '\n') &&
							(*p != 0)
							)
					{
						if (sp < value_size_max)
							value[sp] = *p;
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
					while (
							(*p != '\n') &&
							(*p != 0)
							)
						++p;
				}

			} while (*p != 0);
		}
		else
		{
			do {
				p = skip_comments_and_blanks(p);

				if ((*p == 0) || (*p == '['))
					break;

				while (
						(*p != '\n') &&
						(*p != 0)
						)
					++p;

			} while (1);
		}
	}

	return 0;
}

char *config_init(char *cfg_filename)
{
	int		f_config;
	char	*buffer = NULL;
	off_t	fsz;

	f_config = open(cfg_filename, O_RDONLY);
	while (f_config != -1)
	{
		fsz = lseek(f_config, 0L, SEEK_END) + 1;
		lseek(f_config, 0L, SEEK_SET);

		buffer = x_malloc(fsz);

		fsz = read(f_config, buffer, fsz);
		buffer[fsz] = 0;
		break;
	}

	if (f_config != -1)
		close(f_config);

	return buffer;
}
