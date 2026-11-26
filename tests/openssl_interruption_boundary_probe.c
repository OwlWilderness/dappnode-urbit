/* Host-only composition: actual extracted Vere handlers / urcrypt SIV bodies,
 * real host signals and pthread lock; AES_SIV/OpenSSL and noun state are mocks.
 * This deliberately demonstrates skipped native cleanup, NOT safe recovery.
 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned int c3_l;
typedef unsigned int u3_noun;
enum { c3__over=10, c3__intr=11, c3__term=12, c3__alrm=13 };
typedef struct { int kid_p; } road;
typedef struct { road rod_u; } home_t;
static home_t home;
static road child;
static road *u3R = &child;
static home_t *u3H = &home;
static sigjmp_buf u3_Signal;
#define NO_OVERFLOW 1
#define rsignal_longjmp siglongjmp
static void _cm_emergency(const char *message, c3_l tag) {
    (void)message; (void)tag; _Exit(79);
}
#include "manage-extracted.h"

typedef struct { int marker; } AES_SIV_CTX;
typedef struct { size_t length; uint8_t *bytes; } urcrypt_aes_siv_data;
static pthread_mutex_t native_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t live, completed, selected_stage, selected_signal;
static AES_SIV_CTX *allocation;

static void boundary(int stage) {
    assert(!pthread_mutex_lock(&native_lock));
    if (selected_stage == stage) assert(!raise(selected_signal));
    assert(!pthread_mutex_unlock(&native_lock));
}
static AES_SIV_CTX *AES_SIV_CTX_new(void) {
    allocation = malloc(sizeof(*allocation)); assert(allocation); live=1;
    boundary(1); return allocation;
}
static int AES_SIV_Init(AES_SIV_CTX *ctx, uint8_t *key, size_t size) {
    assert(ctx && key && size); boundary(2); return 1;
}
static int AES_SIV_AssociateData(AES_SIV_CTX *ctx, uint8_t *data, size_t size) {
    assert(ctx && data && size); boundary(3); return 1;
}
static int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, uint8_t *iv, uint8_t *out,
                               uint8_t *message, size_t length) {
    assert(ctx && iv && out && message && length); boundary(4); return 1;
}
static int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, uint8_t *out, uint8_t *iv,
                               uint8_t *message, size_t length) {
    return AES_SIV_EncryptFinal(ctx,iv,out,message,length);
}
static void AES_SIV_CTX_free(AES_SIV_CTX *ctx) {
    assert(ctx == allocation); boundary(5); free(ctx); allocation=NULL; live=0;
}
static void urcrypt__reverse(size_t size, uint8_t *bytes) {
    assert(size && bytes);
    /* Included preprocessing while a native context is already live. */
    if (live && selected_stage == 6) assert(!raise(selected_signal));
}
#include "siv-extracted.h"

int main(int argc, char **argv) {
    assert(argc == 4);
    selected_stage=atoi(argv[1]);
    int which=atoi(argv[2]), decrypt=atoi(argv[3]);
    int signals[]={SIGINT,SIGTERM,SIGVTALRM};
    void (*handlers[])(int)={_cm_signal_handle_intr,_cm_signal_handle_term,_cm_signal_handle_alrm};
    int tags[]={c3__intr,c3__term,c3__alrm};
    assert(which>=0 && which<3); selected_signal=signals[which];
    assert(signal(selected_signal,handlers[which]) != SIG_ERR);
    int jump=sigsetjmp(u3_Signal,1);
    if (!jump) {
        if (selected_stage==8) assert(!raise(selected_signal));
        uint8_t key[32]={0}, message[16]={0}, iv[16]={0}, out[16]={0}, ad[1]={0};
        urcrypt_aes_siv_data data={1,ad};
        int ret = decrypt
            ? urcrypt__aes_siv_de(key,32,message,16,&data,1,iv,out)
            : urcrypt__aes_siv_en(key,32,message,16,&data,1,iv,out);
        assert(!ret); completed=1;
        if (selected_stage==7) assert(!raise(selected_signal));
    }
    assert(jump == (selected_stage ? tags[which] : 0));
    int busy = pthread_mutex_trylock(&native_lock);
    assert(busy == ((selected_stage>=1 && selected_stage<=5) ? EBUSY : 0));
    assert(live == (selected_stage>=1 && selected_stage<=6));
    assert(completed == (selected_stage==0 || selected_stage==7));
    /* Test-owned mock resource only: release it for clean subprocess exit.
     * This is NOT a proposal to unlock unknown abandoned OpenSSL locks. */
    assert(!pthread_mutex_unlock(&native_lock));
    free(allocation);
    puts("observed bounded signal/cleanup disposition");
    return 0;
}
