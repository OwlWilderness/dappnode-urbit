/* Local replacement for pinned urcrypt/sha.c (6c93535d46adffcd1495f904bac91d43b2d6d555).
 * Keep the pre-OpenSSL-3 stack-context digest path: OpenSSL 3's one-shot
 * SHA functions fetch providers and allocate EVP contexts. These void
 * wrappers cannot return an allocation failure to their noun callers.
 * Low-level SHA is deliberately used only with pinned OpenSSL 3.5.9.
 * It performs no provider fetch or heap allocation. An unexpected low-level
 * failure is process-fatal, never an uninitialized digest presented as success.
 */
#define OPENSSL_SUPPRESS_DEPRECATED /* Deliberate pinned, nonallocating API. */
#include "urcrypt.h"
#include "util.h"
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <stdlib.h>

void
urcrypt_sha1(uint8_t *message, size_t length, uint8_t out[20])
{
  SHA_CTX ctx;
  urcrypt__reverse(length, message);
  if ( 1 != SHA1_Init(&ctx) ||
       1 != SHA1_Update(&ctx, message, length) ||
       1 != SHA1_Final(out, &ctx) ) {
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    exit(1);
  }
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  urcrypt__reverse(20, out);
}

void
urcrypt_shay(const uint8_t *message, size_t length, uint8_t out[32])
{
  SHA256_CTX ctx;
  if ( 1 != SHA256_Init(&ctx) ||
       1 != SHA256_Update(&ctx, message, length) ||
       1 != SHA256_Final(out, &ctx) ) {
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    exit(1);
  }
  OPENSSL_cleanse(&ctx, sizeof(ctx));
}

void
urcrypt_shal(const uint8_t *message, size_t length, uint8_t out[64])
{
  SHA512_CTX ctx;
  if ( 1 != SHA512_Init(&ctx) ||
       1 != SHA512_Update(&ctx, message, length) ||
       1 != SHA512_Final(out, &ctx) ) {
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    exit(1);
  }
  OPENSSL_cleanse(&ctx, sizeof(ctx));
}

void
urcrypt_shas(uint8_t *salt, size_t salt_length,
             const uint8_t *message, size_t message_length,
             uint8_t out[32])
{
  size_t i;
  uint8_t mid[32];

  /* Preserve overlapping input/output and both original salt branches. */
  urcrypt_shay(message, message_length, mid);
  if ( salt_length > 32 ) {
    for ( i = 0; i < 32; i++ ) {
      salt[i] ^= mid[i];
    }
    urcrypt_shay(salt, salt_length, out);
  }
  else {
    for ( i = 0; i < salt_length; i++ ) {
      mid[i] ^= salt[i];
    }
    urcrypt_shay(mid, 32, out);
  }
}
