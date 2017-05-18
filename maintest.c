#include <stdio.h>
#include "cmac.h"

// https://tools.ietf.org/html/rfc4493
// K, M and T from 
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
// D.3 AES-256
// Example 11 Mlen = 320


void printBytes(unsigned char *buf, size_t len) {
  for(int i=0; i<len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

// K: 603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4                         
unsigned char key[] = {
  0x60, 0x3d, 0xeb, 0x10,
  0x15, 0xca, 0x71, 0xbe,
  0x2b, 0x73, 0xae, 0xf0,
  0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07,
  0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3,
  0x09, 0x14, 0xdf, 0xf4
};

// M: 6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411 
unsigned char message[] = {
  0x6b, 0xc1, 0xbe, 0xe2,
  0x2e, 0x40, 0x9f, 0x96, 
  0xe9, 0x3d, 0x7e, 0x11,
  0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57,
  0x1e, 0x03, 0xac, 0x9c,
  0x9e, 0xb7, 0x6f, 0xac,
  0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46,
  0xa3, 0x5c, 0xe4, 0x11 
};


int main(int argc, char *argv[])
{
  unsigned char mact[16] = {0}; 
  size_t mactlen;

  CMAC_CTX *ctx = CMAC_CTX_new();
  CMAC_Init(ctx, key, sizeof(key), EVP_aes_256_cbc(), NULL);
  printf("message length = %lu bytes (%lu bits)\n",sizeof(message), sizeof(message)*8);
 
  CMAC_Update(ctx, message, sizeof(message));
  CMAC_Final(ctx, mact, &mactlen);

  printBytes(mact, mactlen);
  /* expected result T: aaf3d8f1 de5640c2 32f5b169 b9c911e6 */
  CMAC_CTX_free(ctx);
  return 0;
}
