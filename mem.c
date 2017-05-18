#include <stdlib.h>
#include <string.h>
#include "crypto.h"

# define osslargused(x)      (void)x // from e_os.h

/*
 * the following pointers may be changed as long as 'allow_customize' is set
 */
static int allow_customize = 1;

static void *(*malloc_impl)(size_t, const char *, int)
    = CRYPTO_malloc;
    
static void (*free_impl)(void *, const char *, int)
    = CRYPTO_free;

static int call_malloc_debug = 0;
    
void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    void *ret = NULL;

    if (malloc_impl != NULL && malloc_impl != CRYPTO_malloc)
        return malloc_impl(num, file, line);

    if (num <= 0)
        return NULL;

    allow_customize = 0;
    osslargused(file); osslargused(line);
    ret = malloc(num);
    return ret;
}

void CRYPTO_free(void *str, const char *file, int line)
{
    if (free_impl != NULL && free_impl != &CRYPTO_free) {
        free_impl(str, file, line);
        return;
    }

    free(str);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc(num, file, line);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}
