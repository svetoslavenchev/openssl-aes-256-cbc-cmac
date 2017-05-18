# openssl-aes-256-cbc-cmac
CMAC AES-256-CBC 

This code is taken from OpenSSL v1.1.0e. It contains only the datapath for CMAC AES-256-CBC. 

See maintest.c for example usage. 

Build with 
`gcc maintest.c e_aes.c evp_lib.c aes_core.c aes_cbc.c cbc128.c cmac.c mem.c evp_enc.c mem_clr.c -o maintest`
