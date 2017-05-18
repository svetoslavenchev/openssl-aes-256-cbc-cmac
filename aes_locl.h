#ifndef HEADER_AES_LOCL_H
#define HEADER_AES_LOCL_H

# ifdef AES_LONG
typedef unsigned long u32;
# else
typedef unsigned int u32;
# endif

typedef unsigned char u8;

#  define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#  define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

#endif /* HEADER_AES_LOCL_H */
