#ifndef U3_OPENSSL_OWNED_START_H
#define U3_OPENSSL_OWNED_START_H
/* Called before the first OpenSSL use, on the process's startup path. */
int u3_openssl_owned_start(void);
/* Finalization is terminal; disallow a false successful reinit after cleanup. */
int u3_openssl_owned_seal(void);
#endif
