/*
 * x_malloc.h
 *
 *  Created on: Feb 3, 2018
 *
 *  Modified on: Nov 08, 2025
 *
 *      Author: lightftp
 */

#ifndef X_MALLOC_H_
#define X_MALLOC_H_ 1

#include <stdlib.h>

#define x_malloc(size) x_malloc_impl(size)

static inline void *x_malloc_impl(size_t size) {
    void *ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    } else {
        abort();
    }
    return ptr;
}

#endif /* X_MALLOC_H_ */
