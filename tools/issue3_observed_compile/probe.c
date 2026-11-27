/* Real retained-library probe PREPARATION, never invoked by prepare.py/tests.
 * Link only a reviewed explicit libssl/libcrypto/libaes_siv set, no -l fallback.
 * Not an Urbit executable, final-link attestation, H2O/curl test or ship test.
 * Each mode/fault is a fresh process; no OPENSSL_cleanup/re-init cycle.
 */
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <aes_siv.h>
#include "openssl_owned_arena.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARENA_BYTES ((size_t)134217728)
#define STEPS 4096
#define CHECK(x) do { if (!(x)) { failed_line = __LINE__; goto out; } } while (0)
static int failed_line, injected, armed;
static size_t allocations;
static const char *fault = "none";

/* Deliberately instrumented wrappers, not the unchanged b04 callback addresses.
 * Allocation accounting/ownership remains in the exact staged arena source.
 * One injected nonzero malloc/realloc fails, retaining the old realloc object.
 */
static int refuse(size_t n) {
  if (n) {
    ++allocations;
    if (armed && !injected) { injected = 1; armed = 0; return 1; }
  }
  return 0;
}
static void *probe_malloc(size_t n, const char *f, int l) {
  return refuse(n) ? NULL : u3_openssl_arena_malloc(n, f, l);
}
static void *probe_realloc(void *p, size_t n, const char *f, int l) {
  return refuse(n) ? NULL : u3_openssl_arena_realloc(p, n, f, l);
}
static void probe_free(void *p, const char *f, int l) {
  u3_openssl_arena_free(p, f, l);
}
static void at(const char *stage) {
  if (!injected && !strcmp(stage, fault)) armed = 1;
}
static int unhex(const char *s, unsigned char *out, size_t cap) {
  size_t n = strlen(s);
  if (n % 2 || n / 2 > cap) return -1;
  for (size_t i = 0; i < n / 2; ++i) {
    unsigned int byte;
    if (sscanf(s + 2 * i, "%2x", &byte) != 1) return -1;
    out[i] = (unsigned char)byte;
  }
  return (int)(n / 2);
}
static int equals_hex(const unsigned char *out, size_t n, const char *hex) {
  unsigned char expected[128];
  int len = unhex(hex, expected, sizeof(expected));
  return len >= 0 && (size_t)len == n && !CRYPTO_memcmp(out, expected, n);
}

/* RFC 5297 Appendix A.1/A.2; actual Akamai libaes_siv API, NOT a Python mock
 * or a replacement EVP implementation. All output is withheld on auth failure.
 */
static int siv_vector(int second) {
  static const char *keys[] = {
    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"};
  static const char *ads[] = {
    "101112131415161718191a1b1c1d1e1f2021222324252627",
    "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"};
  static const char *plains[] = {"112233445566778899aabbccddee",
    "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"};
  static const char *tags[] = {"85632d07c6e8f37f950acd320a2ecc93", "7bdb6e3b432667eb06f4d14bff2fbd0f"};
  static const char *cts[] = {"40c02b9690c4dc04daef7f6afe5c",
    "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"};
  unsigned char key[32], ad[64], plain[64], tag[16], ct[64], output[64];
  unsigned char ad2[10], nonce[16];
  AES_SIV_CTX *ctx = NULL;
  int ok = 0, len, adlen;
  CHECK(unhex(keys[second], key, sizeof(key)) == 32);
  adlen = unhex(ads[second], ad, sizeof(ad));
  len = unhex(plains[second], plain, sizeof(plain));
  CHECK(adlen > 0 && len > 0);
  CHECK(unhex("102030405060708090a0", ad2, sizeof(ad2)) == 10);
  CHECK(unhex("09f911029d74e35bd84156c5635688c0", nonce, sizeof(nonce)) == 16);
  at("siv");
  CHECK((ctx = AES_SIV_CTX_new()) != NULL);
  CHECK(AES_SIV_Init(ctx, key, sizeof(key)) == 1);
  CHECK(AES_SIV_AssociateData(ctx, ad, (size_t)adlen) == 1);
  if (second) {
    CHECK(AES_SIV_AssociateData(ctx, ad2, sizeof(ad2)) == 1);
    CHECK(AES_SIV_AssociateData(ctx, nonce, sizeof(nonce)) == 1);
  }
  CHECK(AES_SIV_EncryptFinal(ctx, tag, ct, plain, (size_t)len) == 1);
  CHECK(equals_hex(tag, sizeof(tag), tags[second]));
  CHECK(equals_hex(ct, (size_t)len, cts[second]));
  /* Fresh initialization on each attempt, four independent tamper dimensions.
   * Successful plaintext is compared only after authentication returned 1.
   */
  for (int change = 0; change <= 4; ++change) {
    unsigned char k[32], a[64], t[16], c[64];
    memcpy(k,key,sizeof(k)); memcpy(a,ad,(size_t)adlen);
    memcpy(t,tag,sizeof(t)); memcpy(c,ct,(size_t)len);
    if (change == 1) t[0] ^= 1;
    if (change == 2) c[len-1] ^= 1;
    if (change == 3) a[0] ^= 1;
    if (change == 4) k[0] ^= 1;
    CHECK(AES_SIV_Init(ctx,k,sizeof(k)) == 1);
    CHECK(AES_SIV_AssociateData(ctx,a,(size_t)adlen) == 1);
    if (second) {
      CHECK(AES_SIV_AssociateData(ctx,ad2,sizeof(ad2)) == 1);
      CHECK(AES_SIV_AssociateData(ctx,nonce,sizeof(nonce)) == 1);
    }
    memset(output,0xa5,sizeof(output));
    int result = AES_SIV_DecryptFinal(ctx,output,t,c,(size_t)len);
    if (!change) CHECK(result == 1 && !CRYPTO_memcmp(output,plain,(size_t)len));
    else CHECK(result == 0);
    OPENSSL_cleanse(output,sizeof(output));
    OPENSSL_cleanse(k,sizeof(k));
  }
  ok = 1;
out:
  AES_SIV_CTX_free(ctx);
  OPENSSL_cleanse(key,sizeof(key));
  OPENSSL_cleanse(output,sizeof(output));
  return ok;
}

static int crypto_case(void) {
  unsigned char out[64], key[20];
  unsigned int len = 0;
  size_t qlen = 0;
  int ok = 0;
  at("sha");
  CHECK(SHA256((const unsigned char *)"abc",3,out) != NULL);
  CHECK(equals_hex(out,32,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK(SHA512((const unsigned char *)"abc",3,out) != NULL);
  CHECK(equals_hex(out,64,"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
  CHECK(EVP_Q_digest(NULL,"SHA256",NULL,"",0,out,&qlen) == 1);
  CHECK(equals_hex(out,qlen,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  memset(key,0x0b,sizeof(key)); /* RFC 4231 test case 1 */
  CHECK(HMAC(EVP_sha256(),key,(int)sizeof(key),(const unsigned char *)"Hi There",8,out,&len) != NULL);
  CHECK(equals_hex(out,len,"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
  CHECK(siv_vector(0) && siv_vector(1));
  ok = 1;
out:
  OPENSSL_cleanse(out,sizeof(out));
  OPENSSL_cleanse(key,sizeof(key));
  return ok;
}

static EVP_PKEY *key_new(void) {
  /* No user key, credential file or disk output. Random synthetic test keys. */
  return EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
}
static int extension(X509 *cert, X509 *issuer, int nid, const char *value) {
  X509V3_CTX context;
  X509_EXTENSION *ext;
  X509V3_set_ctx(&context,issuer,cert,NULL,NULL,0);
  ext = X509V3_EXT_conf_nid(NULL,&context,nid,value);
  if (!ext) return 0;
  int result = X509_add_ext(cert,ext,-1);
  X509_EXTENSION_free(ext); /* add_ext copies; original always remains ours */
  return result == 1;
}
static X509 *cert_new(EVP_PKEY *key, X509 *issuer, EVP_PKEY *signer, int serial, const char *name) {
  X509 *cert = NULL;
  X509_NAME *subject;
  CHECK((cert = X509_new()) != NULL);
  CHECK(X509_set_version(cert,2) == 1);
  CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert),serial) == 1);
  /* Fixed verification time below: no dependency on wall-clock expiry. */
  CHECK(ASN1_TIME_set_string(X509_getm_notBefore(cert),"20200101000000Z") == 1);
  CHECK(ASN1_TIME_set_string(X509_getm_notAfter(cert),"20400101000000Z") == 1);
  CHECK(X509_set_pubkey(cert,key) == 1);
  subject = X509_get_subject_name(cert); /* borrowed */
  CHECK(subject && X509_NAME_add_entry_by_txt(subject,"CN",MBSTRING_ASC,
      (const unsigned char *)name,-1,-1,0) == 1);
  CHECK(X509_set_issuer_name(cert,issuer ? X509_get_subject_name(issuer) : subject) == 1);
  CHECK(extension(cert,issuer ? issuer : cert,NID_basic_constraints,
      issuer ? "critical,CA:FALSE" : "critical,CA:TRUE,pathlen:0"));
  CHECK(extension(cert,issuer ? issuer : cert,NID_key_usage,
      issuer ? "critical,digitalSignature" : "critical,keyCertSign,cRLSign"));
  if (issuer) {
    CHECK(extension(cert,issuer,NID_ext_key_usage,"serverAuth"));
    CHECK(extension(cert,issuer,NID_subject_alt_name,"DNS:probe.invalid"));
  }
  CHECK(X509_sign(cert,signer ? signer : key,EVP_sha256()) > 0);
  return cert;
out:
  X509_free(cert);
  return NULL;
}

/* SSL_get_error immediately follows its operation on the same thread; never
 * treat arbitrary handshake/constructor failure as a successful trust refusal.
 */
static int handshake_step(SSL *ssl) {
  if (SSL_is_init_finished(ssl)) return 1;
  ERR_clear_error();
  int result = SSL_do_handshake(ssl);
  if (result == 1) return 1;
  int error = SSL_get_error(ssl,result);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return 0;
  return error == SSL_ERROR_SSL ? -1 : -2;
}
static int exchange(SSL *from, SSL *to, const char *message) {
  unsigned char buffer[64];
  size_t sent = 0, received = 0, n = strlen(message);
  int wrote = 0;
  for (int i = 0; i < STEPS; ++i) {
    if (!wrote) {
      ERR_clear_error();
      int r = SSL_write_ex(from,message,n,&sent);
      if (r == 1) { if (sent != n) return 0; wrote = 1; }
      else {
        int e = SSL_get_error(from,r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return 0;
      }
    }
    ERR_clear_error();
    int r = SSL_read_ex(to,buffer,sizeof(buffer),&received);
    if (r == 1) return wrote && received == n && !memcmp(buffer,message,n);
    int e = SSL_get_error(to,r);
    if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return 0;
  }
  return 0;
}
static int shutdown_step(SSL *ssl) {
  ERR_clear_error();
  int r = SSL_shutdown(ssl);
  if (r >= 0) return r;
  int e = SSL_get_error(ssl,r);
  return (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) ? 0 : -1;
}

static int tls_case(int version, int wronghost, int untrusted) {
  EVP_PKEY *root_key = NULL, *leaf_key = NULL, *other_key = NULL;
  X509 *root = NULL, *leaf = NULL, *other = NULL;
  SSL_CTX *client_ctx = NULL, *server_ctx = NULL;
  X509_STORE *store = NULL; /* borrowed from client_ctx, never separately freed */
  SSL *client = NULL, *server = NULL;
  BIO *cbio = NULL, *sbio = NULL;
  int ok = 0, complete = 0;
  at("cert");
  CHECK((root_key = key_new()) && (leaf_key = key_new()));
  CHECK((root = cert_new(root_key,NULL,NULL,1,"probe root")) != NULL);
  CHECK((leaf = cert_new(leaf_key,root,root_key,2,"probe.invalid")) != NULL);
  if (untrusted) {
    CHECK((other_key = key_new()) != NULL);
    CHECK((other = cert_new(other_key,NULL,NULL,3,"other root")) != NULL);
  }
  at("ctx");
  CHECK((client_ctx = SSL_CTX_new(TLS_client_method())) != NULL);
  CHECK((server_ctx = SSL_CTX_new(TLS_server_method())) != NULL);
  CHECK(SSL_CTX_set_min_proto_version(client_ctx,version) == 1);
  CHECK(SSL_CTX_set_max_proto_version(client_ctx,version) == 1);
  CHECK(SSL_CTX_set_min_proto_version(server_ctx,version) == 1);
  CHECK(SSL_CTX_set_max_proto_version(server_ctx,version) == 1);
  SSL_CTX_set_verify(client_ctx,SSL_VERIFY_PEER,NULL);
  /* Neither default verify paths nor environment CA trust are loaded. The store
   * is borrowed; add_cert increments its reference, NOT ownership transfer. */
  CHECK((store = SSL_CTX_get_cert_store(client_ctx)) != NULL);
  at("ca");
  CHECK(X509_STORE_add_cert(store,untrusted ? other : root) == 1);
  CHECK(SSL_CTX_use_certificate(server_ctx,leaf) == 1);
  CHECK(SSL_CTX_use_PrivateKey(server_ctx,leaf_key) == 1);
  CHECK(SSL_CTX_check_private_key(server_ctx) == 1);
  at("ssl");
  CHECK((client = SSL_new(client_ctx)) != NULL);
  CHECK((server = SSL_new(server_ctx)) != NULL);
  CHECK(SSL_set1_host(client,wronghost ? "wrong.invalid" : "probe.invalid") == 1);
  CHECK(SSL_set_tlsext_host_name(client,"probe.invalid") == 1);
  X509_VERIFY_PARAM_set_time(SSL_get0_param(client),(time_t)1767225600); /* 2026-01-01 UTC */
  at("bio");
  CHECK(BIO_new_bio_pair(&cbio,16384,&sbio,16384) == 1);
  /* Fresh BIOs: rbio==wbio consumes ONE reference on each SSL. Null local
   * pointers immediately; partial-construction out path only frees unowned BIOs. */
  SSL_set_bio(client,cbio,cbio); cbio = NULL;
  SSL_set_bio(server,sbio,sbio); sbio = NULL;
  SSL_set_connect_state(client);
  SSL_set_accept_state(server);
  for (int i = 0; i < STEPS; ++i) {
    int c = handshake_step(client);
    if (c < 0) {
      long verify = SSL_get_verify_result(client);
      if (wronghost || untrusted) {
        CHECK(c == -1 && verify == (wronghost ? X509_V_ERR_HOSTNAME_MISMATCH :
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
        CHECK(!SSL_is_init_finished(client));
        ok = 1;
        goto out; /* failed sessions are freed, never quiet-shutdown as success */
      }
      CHECK(0);
    }
    int s = handshake_step(server);
    CHECK(s >= 0);
    if (c == 1 && s == 1) { complete = 1; break; }
  }
  CHECK(complete && !wronghost && !untrusted);
  CHECK(SSL_get_verify_result(client) == X509_V_OK);
  CHECK(SSL_version(client) == version && SSL_version(server) == version);
  CHECK(exchange(client,server,"client to server"));
  CHECK(exchange(server,client,"server to client"));
  complete = 0;
  int cdone = 0, sdone = 0;
  for (int i = 0; i < STEPS; ++i) {
    if (!cdone) { int r = shutdown_step(client); CHECK(r >= 0); cdone = r; }
    if (!sdone) { int r = shutdown_step(server); CHECK(r >= 0); sdone = r; }
    if (cdone && sdone) { complete = 1; break; }
  }
  CHECK(complete);
  ok = 1;
out:
  /* Free sessions/BIOs before contexts, then our own certificate/key refs.
   * Client context owns store; context's certificate/key refs are independent. */
  BIO_free(cbio); BIO_free(sbio);
  SSL_free(client); SSL_free(server);
  SSL_CTX_free(client_ctx); SSL_CTX_free(server_ctx);
  X509_free(leaf); X509_free(root); X509_free(other);
  EVP_PKEY_free(leaf_key); EVP_PKEY_free(root_key); EVP_PKEY_free(other_key);
  return ok;
}

int main(int argc, char **argv) {
  const char *modes[] = {"crypto","tls12","tls13","tls12-wronghost","tls13-wronghost",
                        "tls12-untrusted","tls13-untrusted"};
  const char *faults[] = {"none","init","sha","siv","cert","ctx","ca","ssl","bio"};
  int mode = -1, valid_fault = 0, ok = 0, registered = 0, destroyed;
  if (argc != 2 && argc != 3) return 64;
  for (int i = 0; i < 7; ++i) if (!strcmp(argv[1],modes[i])) mode = i;
  if (argc == 3) fault = argv[2];
  for (int i = 0; i < 9; ++i) if (!strcmp(fault,faults[i])) valid_fault = 1;
  if (mode < 0 || !valid_fault || (mode == 0 && strcmp(fault,"none") &&
      strcmp(fault,"init") && strcmp(fault,"sha") && strcmp(fault,"siv")) ||
      (mode != 0 && (!strcmp(fault,"sha") || !strcmp(fault,"siv")))) return 64;
  if (!u3_openssl_arena_init(ARENA_BYTES)) return 70;
  /* This must be the first OpenSSL operation, before any versions/errors/RNG. */
  registered = CRYPTO_set_mem_functions(probe_malloc,probe_realloc,probe_free);
  if (registered) {
    at("init");
    if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG,NULL) == 1) {
      if (!mode) ok = crypto_case();
      else ok = tls_case((mode == 1 || mode == 3 || mode == 5) ? TLS1_2_VERSION :
                        TLS1_3_VERSION,mode == 3 || mode == 4,mode == 5 || mode == 6);
    }
    /* All local consumers have unwound; no other threads, callbacks or sockets.
     * Stop fault injection before global cleanup, then count BEFORE destruction. */
    armed = 0;
    OPENSSL_thread_stop();
    OPENSSL_cleanup();
  }
  size_t live = u3_openssl_arena_live_blocks();
  u3_openssl_arena_metrics metrics = {0};
  int snap = u3_openssl_arena_snapshot(&metrics);
  destroyed = !live && u3_openssl_arena_destroy();
  const char *status = !registered || live || !destroyed || !snap ? "CLEANUP_FAIL" :
      strcmp(fault,"none") ? (injected ? "FAULT_OBSERVED" : "FAULT_NOT_REACHED") :
      ok ? "CASE_PASS" : "CASE_FAIL";
  printf("{\"schema\":\"issue3-b04-probe-result-v1\",\"mode\":\"%s\","
      "\"fault\":\"%s\",\"status\":\"%s\",\"case_ok\":%d,\"injected\":%d,"
      "\"live_blocks\":%zu,\"destroyed\":%d,\"allocations\":%zu,"
      "\"peak_charged_bytes\":%zu,\"failed_line\":%d}\n",
      modes[mode],fault,status,ok,injected,live,destroyed,allocations,
      metrics.peak_charged_bytes,failed_line);
  return !strcmp(status,"CASE_PASS") || !strcmp(status,"FAULT_OBSERVED") ? 0 : 1;
}
