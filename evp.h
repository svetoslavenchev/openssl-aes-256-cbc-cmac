#ifndef HEADER_EVP_H
#define HEADER_EVP_H

#define EVP_MAX_IV_LENGTH               16
#define EVP_MAX_BLOCK_LENGTH            32

# define         EVP_CIPH_MODE                   0xF0007

# define         EVP_CIPH_STREAM_CIPHER          0x0

# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_CBC_MODE               0x2
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_OFB_MODE               0x4
# define         EVP_CIPH_CTR_MODE               0x5

# define         EVP_CIPH_FLAG_DEFAULT_ASN1      0x1000

# define         EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1

# define         EVP_CTRL_INIT                   0x0
# define         EVP_CTRL_SET_KEY_LENGTH         0x1

/* Call ctrl() to init cipher parameters */
# define         EVP_CIPH_CTRL_INIT              0x40


/* Set if variable length cipher */
# define         EVP_CIPH_VARIABLE_LENGTH        0x8

/* Don't use standard key length function */
# define         EVP_CIPH_CUSTOM_KEY_LENGTH      0x80

# define         EVP_CIPH_WRAP_MODE              0x10002

/* Set if the iv handling should be done by the cipher itself */
# define         EVP_CIPH_CUSTOM_IV              0x10

/* Set if the cipher's init() function should be called if key is NULL */
# define         EVP_CIPH_ALWAYS_CALL_INIT       0x20

# define EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH              122

# define EVP_R_INVALID_KEY_LENGTH                         130

#include "evp_int.h"
#include "evp_locl.h"

const EVP_CIPHER *EVP_aes_256_cbc(void);

void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);

unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);

int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);

unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);

int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);

int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);

int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

/*__owur*/ int EVP_Cipher(EVP_CIPHER_CTX *c,
                          unsigned char *out,
                          const unsigned char *in, unsigned int inl);

/*__owur*/ int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                                 const EVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);


# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))


#endif /* HEADER_EVP_H */
