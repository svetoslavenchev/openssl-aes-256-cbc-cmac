#include "evp_int.h"
#include "ossl_typ.h"
#include "aes.h"
#include "modes.h"
#include "obj_mac.h"
#include "evp.h"


typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_AES_KEY;

/*

  BLOCK_CIPHER_generic(0 NID_aes,1 256,2 16,3 16,4 cbc,5 cbc,6 CBC,7 EVP_CIPH_FLAG_DEFAULT_ASN1);
# define BLOCK_CIPHER_generic(0 nid,1 keylen,2 blocksize,3 ivlen,4 nmode,5 mode,6 MODE,7 flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,     \
        keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_init_key,                   \
        aes_##mode##_cipher,            \
        NULL,                           \
        sizeof(EVP_AES_KEY),            \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }
*/


static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    int ret, mode;
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    mode = EVP_CIPHER_CTX_mode(ctx);
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc) {
        {
            ret = AES_set_decrypt_key(key,
                                      EVP_CIPHER_CTX_key_length(ctx) * 8,
                                      &dat->ks.ks);
            dat->block = (block128_f) AES_decrypt;
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) AES_cbc_encrypt : NULL;
        }
    } else
    {
        ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                  &dat->ks.ks);
        dat->block = (block128_f) AES_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) AES_cbc_encrypt : NULL;

    }
    if (ret < 0) {
        // EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }
    return 1;
}

static int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_AES_KEY *dat = EVP_C_DATA(EVP_AES_KEY,ctx);

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks,
                            EVP_CIPHER_CTX_iv_noconst(ctx),
                            EVP_CIPHER_CTX_encrypting(ctx));
    else if (EVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);

    return 1;
}


static const EVP_CIPHER aes_256_cbc = {
        NID_aes_256_cbc, 16, 
        256/8, 16, 
        EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE,
        aes_init_key, 
        aes_cbc_cipher,
        NULL, 
        sizeof(EVP_AES_KEY),
        NULL, NULL, NULL, NULL };
const EVP_CIPHER *EVP_aes_256_cbc(void) 
{ return &aes_256_cbc; }





