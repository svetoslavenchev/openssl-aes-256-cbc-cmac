#ifndef HEADER_CRYPTO_H
#define HEADER_CRYPTO_H

#include <stddef.h> // size_t 
#include "opensslconf.h"

void *CRYPTO_malloc(size_t num, const char *file, int line);
void *CRYPTO_zalloc(size_t num, const char *file, int line);
void CRYPTO_free(void *ptr, const char *file, int line);
void OPENSSL_cleanse(void *ptr, size_t len);

# define OPENSSL_malloc(num) \
        CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)

# define OPENSSL_zalloc(num) \
        CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)

# define OPENSSL_free(addr) \
        CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)

                
#endif /* HEADER_CRYPTO_H */
