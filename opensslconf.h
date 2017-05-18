#ifndef HEADER_OPENSSLCONF_H
#define HEADER_OPENSSLCONF_H

#ifndef OPENSSL_FILE
# ifdef OPENSSL_NO_FILENAMES
#  define OPENSSL_FILE ""
#  define OPENSSL_LINE 0
# else
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif
#endif

#endif /* HEADER_OPENSSLCONF_H */
