/*
 *  fcrypt.h
 *
 *  Created on: Jun 12, 2026
 *
 *  Modified on: Sep 19, 2026
 *
 *      Author: lightftp
 */

#ifndef FCRYPT_H_
#define FCRYPT_H_ 1

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define FTP_PASSWORD_SALT_SIZE          32
#define FTP_PASSWORD_HASH_SIZE          32
#define FTP_PASSWORD_PBKDF2_ITERATIONS  200000U
#define FTP_PASSWORD_RECORD_SIZE        128

int password_generate_hash_record(const char *password, char *record, size_t record_size);
int password_verify_hash_record(const char *record, const char *password);

#endif /* FCRYPT_H_ */
