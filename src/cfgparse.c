/*
 * cfgparse.c
 *
 *  Created on: Aug 20, 2016
 *
 *  Modified on: Feb 14, 2026
 *
 *      Author: lightftp
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "inc/x_malloc.h"

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

int config_parse(
    const char      *pcfg,
    const char      *section_name,
    const char      *key_name,
    char            *value,
    unsigned long   value_size_max)
{
    unsigned long   sp;
    char            section[256];
    char            current_key[256];
    const char      *p;
    int             in_target_section = 0;
    
    if (!pcfg || !section_name || !key_name || !value || value_size_max == 0)
        return 0;
    
    /* Ensure room for null terminator */
    --value_size_max;
    
    p = pcfg;
    
    while (*p) {
        /* Skip whitespace and comments */
        p = skip_comments_and_blanks((char *)p);
        
        /* End of config reached */
        if (*p == 0)
            break;
            
        /* Section header start */
        if (*p == '[') {
            in_target_section = 0;
            ++p;
            
            /* Extract section name */
            sp = 0;
            while (*p != ']' && *p != 0 && *p != '\n' && sp < 255) {
                section[sp++] = *p++;
            }
            section[sp] = 0;
            
            if (*p != ']') {
                /* Malformed section header */
                if (*p == 0)
                    break;
                continue;
            }
            
            /* Skip the closing bracket */
            ++p;
            
            /* Check if this is our target section */
            if (strcmp(section, section_name) == 0) {
                in_target_section = 1;
            }
        }
        /* We're in the target section, look for our key */
        else if (in_target_section) {
            /* Start of a new section means we're done */
            if (*p == '[')
                break;
                
            /* Extract key */
            sp = 0;
            while (*p != '=' && *p != ' ' && *p != 0 && *p != '\n' && sp < 255) {
                current_key[sp++] = *p++;
            }
            current_key[sp] = 0;
            
            /* Skip spaces before equals sign */
            while (*p == ' ')
                ++p;
                
            /* If not a valid key-value pair, move to next line */
            if (*p != '=') {
                while (*p != 0 && *p != '\n')
                    ++p;
                continue;
            }
            
            /* Skip equals sign */
            ++p;
            
            /* If this is our target key, extract the value */
            if (strcmp(current_key, key_name) == 0) {
                sp = 0;
                while (*p != '\n' && *p != 0) {
                    if (sp < value_size_max)
                        value[sp++] = *p;
                    else
                        return 0; /* Value too long for buffer */
                    ++p;
                }
                value[sp] = 0;
                return 1;
            }
            /* Otherwise skip to end of line */
            else {
                while (*p != '\n' && *p != 0)
                    ++p;
            }
        }
        /* Not in our target section, skip to next line or section */
        else {
            while (*p != 0 && *p != '\n' && *p != '[')
                ++p;
        }
    }
    
    return 0;
}

char *config_init(char *cfg_filename)
{
	int		f_config;
	char	*buffer = NULL;
	off_t	fsz;
    ssize_t rd;

	f_config = open(cfg_filename, O_RDONLY | O_CLOEXEC);
	while (f_config != -1)
	{
		fsz = lseek(f_config, 0L, SEEK_END);
        if (fsz == (off_t)-1 || fsz == 0)
			break;

        lseek(f_config, 0L, SEEK_SET);
        buffer = x_malloc(fsz + 1);

        rd = read(f_config, buffer, fsz);
        if (rd <= 0)
        {
            free(buffer);
            buffer = NULL;
            break;
        }

		buffer[rd] = 0;
		break;
	}

	if (f_config != -1)
		close(f_config);

	return buffer;
}
