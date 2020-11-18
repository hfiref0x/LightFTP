/*
 * fspathtools.c
 *
 *  Created on: May 17, 2020
 *      Author: lightftp
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>

#include "x_malloc.h"

char *filepath(char *s)
{
    char    *p = s;

    if (*s == 0)
        return s;
/*
 * leave root directory sign untouched
 */
    if (*s == '/')
    {
        ++s;
        ++p;
    }

    while (*s != 0) {
        if (*s == '/')
            p = s;
        ++s;
    }

    *p = 0;

    return p;
}

typedef struct _ftp_path_node {
    char                    *value;
    size_t                  length;
    struct _ftp_path_node   *next;
    struct _ftp_path_node   *prev;
} ftp_path_node, *pftp_path_node;

/*
    Path normalization routine:
    Removes garbage like "/", "///" or "." etc. and correctly resolves ".."
*/

int ftp_normalize_path(char* path, size_t npath_len, char* npath)
{
    char* p0;
    size_t          node_len;
    int             status = 1;
    pftp_path_node  nodes = NULL, newnode;

    if ((path == NULL) || (npath == NULL) || (npath_len < 2))
        return 0;

    if (*path == '/')
    {
        *npath = '/';
        ++path;
        ++npath;
        --npath_len;
    }

    p0 = path;

    while (*path != 0)
    {
        while ((*path != '/') && (*path != '\0'))
            ++path;

        node_len = path - p0;

        while (node_len > 0)
        {
            /* we have a "this dir" sign: just skip it */
            if (strncmp(p0, ".", node_len) == 0)
                break;

            if (strncmp(p0, "..", node_len) == 0)
            {
                /* we have a "dir-up" sign: unlink and free prev node */
                if (nodes)
                {
                    newnode = nodes->prev;
                    free(nodes);
                    if (newnode)
                        newnode->next = NULL;
                    nodes = newnode;
                }
            }
            else
            {
                newnode = x_malloc(sizeof(ftp_path_node));
                newnode->value = p0;
                newnode->length = node_len;
                newnode->next = NULL;
                newnode->prev = nodes;

                if (nodes)
                    nodes->next = newnode;

                nodes = newnode;
            }

            break;
        }

        if (*path != 0)
            ++path;

        p0 = path;
    }

    /* return to head */
    newnode = nodes;
    while (newnode)
    {
        nodes = newnode;
        newnode = newnode->prev;
    }

    while (nodes)
    {
        if (npath_len < nodes->length + 1)
        {
            status = 0;
            break;
        }

        strncpy(npath, nodes->value, nodes->length);
        npath += nodes->length;
        *npath = '/';
        ++npath;
        npath_len -= nodes->length + 1;

        newnode = nodes;
        nodes = newnode->next;
        free(newnode);
    }

    /* free the remaining nodes in case of break */
    while (nodes)
    {
        newnode = nodes;
        nodes = newnode->next;
        free(newnode);
    }

    if ((npath_len == 0) || (status == 0))
        return 0;

    *npath = '\0';
    return 1;
}

int ftp_effective_path(char *root_path, char *current_path,
        char *file_path, size_t result_size, char *result)
{
    char    path[PATH_MAX], npath[PATH_MAX];
    int     status;
    size_t  len;

    memset(result, 0, result_size);

    if (file_path == NULL)
        file_path = "";

    if (*file_path == '/')
    {
        status = ftp_normalize_path(file_path, PATH_MAX, npath);
    }
    else
    {
        snprintf(path, PATH_MAX, "%s/%s", current_path, file_path);
        status = ftp_normalize_path(path, PATH_MAX, npath);
    }

    if (status == 0)
        return 0;

    snprintf(path, PATH_MAX, "%s/%s", root_path, npath);
    status = ftp_normalize_path(path, result_size, result);

    /* delete last slash */
    len = strlen(result);
    if (len >= 2)
    {
        if (result[len-1] == '/')
            result[len-1] = '\0';
    }

    return status;
}
