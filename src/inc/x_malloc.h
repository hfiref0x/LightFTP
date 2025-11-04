/*
 * x_malloc.h
 *
 *  Created on: Feb 3, 2018
 *
 *  Modified on: Jul 25, 2025
 *
 *      Author: lightftp
 */

#ifndef X_MALLOC_H_
#define X_MALLOC_H_ 1

#include <stdlib.h>

#define x_malloc(size) ({ void *ptr = malloc(size); if (ptr) {memset(ptr, 0, size);} else {abort();} ptr; })

#endif /* X_MALLOC_H_ */
