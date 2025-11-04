/*
 * fspathtools.h
 *
 *  Created on: May 17, 2020
 *
 *  Modified on: Jul 25, 2025
 *
 *      Author: lightftp
 */

#ifndef FSPATHTOOLS_H_
#define FSPATHTOOLS_H_ 1

char *filepath(char *s);
int ftp_normalize_path(char* path, size_t npath_len, char* npath);
int ftp_effective_path(char *root_path, char *current_path,
        const char *file_path, size_t result_size, char *result);

#endif /* FSPATHTOOLS_H_ */
