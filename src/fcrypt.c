/*
 *  fcrypt.c
 *
 *  Created on: Jun 12, 2026
 *
 *  Modified on: Sep 19, 2026
 *
 *      Author: lightftp
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include "inc/fcrypt.h"

#define FTP_PASSWORD_SCHEME "pbkdf2-sha256"
#define FTP_PASSWORD_SCHEME_SEPARATOR '$'
#define FTP_PASSWORD_BASE64_SIZE 45

static int password_derive_key(const char *password, const uint8_t *salt,
                               unsigned int iterations, uint8_t *hash)
{
    gnutls_datum_t password_data;
    gnutls_datum_t salt_data;
    int result;

    if ((password == NULL) || (salt == NULL) || (hash == NULL) || (iterations == 0))
        return 0;

    password_data.data = (unsigned char *)password;
    password_data.size = strlen(password);

    salt_data.data = (unsigned char *)salt;
    salt_data.size = FTP_PASSWORD_SALT_SIZE;

    result = gnutls_pbkdf2(GNUTLS_MAC_SHA256, &password_data, &salt_data,
                           iterations, hash, FTP_PASSWORD_HASH_SIZE);

    return (result >= 0);
}

static int password_base64_encode(const uint8_t *data, size_t data_size,
                                  char *result, size_t result_size)
{
    gnutls_datum_t data_datum;
    gnutls_datum_t encoded = {0};
    int status = 0;
    int ret;

    if ((data == NULL) || (result == NULL) || (result_size == 0))
        return 0;

    data_datum.data = (unsigned char *)data;
    data_datum.size = data_size;

    ret = gnutls_base64_encode2(&data_datum, &encoded);
    if ((ret >= 0) && (encoded.size < result_size))
    {
        memcpy(result, encoded.data, encoded.size);
        result[encoded.size] = 0;
        status = 1;
    }

    if (encoded.data != NULL)
        gnutls_free(encoded.data);

    return status;
}

static int password_base64_decode(const char *data, size_t data_size,
                                  uint8_t *result, size_t result_size)
{
    gnutls_datum_t data_datum;
    gnutls_datum_t decoded = {0};
    int status = 0;
    int ret;

    if ((data == NULL) || (result == NULL) || (data_size == 0))
        return 0;

    data_datum.data = (unsigned char *)data;
    data_datum.size = data_size;

    ret = gnutls_base64_decode2(&data_datum, &decoded);
    if ((ret >= 0) && (decoded.size == result_size))
    {
        memcpy(result, decoded.data, result_size);
        status = 1;
    }

    if (decoded.data != NULL)
        gnutls_free(decoded.data);

    return status;
}

static int password_parse_iterations(const char *text, size_t text_size,
                                     unsigned int *iterations)
{
    char value[16];
    char *end;
    unsigned long parsed;

    if ((text == NULL) || (iterations == NULL) ||
        (text_size == 0) || (text_size >= sizeof(value)))
    {
        return 0;
    }

    memcpy(value, text, text_size);
    value[text_size] = 0;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if ((errno != 0) || (*end != 0) || (parsed == 0) || (parsed > UINT_MAX))
        return 0;

    *iterations = (unsigned int)parsed;
    return 1;
}

int password_generate_hash_record(const char *password, char *record, size_t record_size)
{
    char salt_base64[FTP_PASSWORD_BASE64_SIZE];
    char hash_base64[FTP_PASSWORD_BASE64_SIZE];
    uint8_t salt[FTP_PASSWORD_SALT_SIZE];
    uint8_t hash[FTP_PASSWORD_HASH_SIZE];
    int length;
    int status = 0;

    if ((password == NULL) || (record == NULL) || (record_size == 0))
        return 0;

    do {

        if (gnutls_rnd(GNUTLS_RND_KEY, salt, sizeof(salt)) < 0)
            break;

        if (!password_derive_key(password, salt, FTP_PASSWORD_PBKDF2_ITERATIONS, hash))
            break;

        if (!password_base64_encode(salt, sizeof(salt), salt_base64, sizeof(salt_base64)))
            break;

        if (!password_base64_encode(hash, sizeof(hash), hash_base64, sizeof(hash_base64)))
            break;

        length = snprintf(record, record_size, "%s$%u$%s$%s",
                          FTP_PASSWORD_SCHEME, FTP_PASSWORD_PBKDF2_ITERATIONS,
                          salt_base64, hash_base64);

        if ((length >= 0) && ((size_t)length < record_size))
            status = 1;

    } while (0);

    // Cleanup.
    gnutls_memset(hash, 0, sizeof(hash));
    gnutls_memset(salt, 0, sizeof(salt));
    return status;
}

int password_verify_hash_record(const char *record, const char *password)
{
    const char *field_begin;
    const char *field_end;
    const char *salt_base64;
    const char *hash_base64;
    size_t field_size;
    size_t salt_base64_size;
    size_t hash_base64_size;
    unsigned int iterations;
    uint8_t salt[FTP_PASSWORD_SALT_SIZE];
    uint8_t expected_hash[FTP_PASSWORD_HASH_SIZE];
    uint8_t actual_hash[FTP_PASSWORD_HASH_SIZE];
    int status = 0;

    if ((record == NULL) || (password == NULL))
        return 0;

    do {
        
        field_begin = record;
        field_end = strchr(field_begin, FTP_PASSWORD_SCHEME_SEPARATOR);
        if ((field_end == NULL) ||
            ((size_t)(field_end - field_begin) != strlen(FTP_PASSWORD_SCHEME)) ||
            (memcmp(field_begin, FTP_PASSWORD_SCHEME, strlen(FTP_PASSWORD_SCHEME)) != 0))
        {
            break;
        }

        field_begin = field_end + 1;
        field_end = strchr(field_begin, FTP_PASSWORD_SCHEME_SEPARATOR);
        if (field_end == NULL)
            break;

        field_size = (size_t)(field_end - field_begin);
        if (!password_parse_iterations(field_begin, field_size, &iterations))
            break;

        salt_base64 = field_end + 1;
        field_end = strchr(salt_base64, FTP_PASSWORD_SCHEME_SEPARATOR);
        if (field_end == NULL)
            break;

        salt_base64_size = (size_t)(field_end - salt_base64);
        hash_base64 = field_end + 1;
        hash_base64_size = strlen(hash_base64);

        if (!password_base64_decode(salt_base64, salt_base64_size,
                                    salt, sizeof(salt)))
        {
            break;
        }

        if (!password_base64_decode(hash_base64, hash_base64_size,
                                    expected_hash, sizeof(expected_hash)))
        {
            break;
        }

        if (!password_derive_key(password, salt, iterations, actual_hash))
            break;

        if (gnutls_memcmp(expected_hash, actual_hash, sizeof(actual_hash)) == 0)
            status = 1;

    } while (0);

    // Cleanup.
    gnutls_memset(actual_hash, 0, sizeof(actual_hash));
    gnutls_memset(expected_hash, 0, sizeof(expected_hash));
    gnutls_memset(salt, 0, sizeof(salt));
    return status;
}
