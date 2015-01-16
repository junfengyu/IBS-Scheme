#ifndef JOSEPH_IBS_SCHEME_H
#define JOSEPH_IBS_SCHEME_H

#include <sys/types.h>

#include <openssl/bn.h>

struct modp_group {
    BIGNUM *p, *q, *g;
};

#define KEY_LENGTH_BITS 160

BIGNUM *bn_rand_range_gt_one(const BIGNUM *high);
int hash_buffer(const u_char *, u_int, const EVP_MD *, u_char **, u_int *);
void debug3_bn(const BIGNUM *, const char *, ...)
    __attribute__((__nonnull__ (2)))
    __attribute__((format(printf, 2, 3)));
void debug3_buf(const u_char *, u_int, const char *, ...)
    __attribute__((__nonnull__ (3)))
    __attribute__((format(printf, 3, 4)));
struct modp_group *modp_group_from_g_p_and_q(const char *, const char *, const char *);
void modp_group_free(struct modp_group *);


///////////////////////////////////////////////////////////////////////////
//Public API for Joseph IBS scheme

/* System parameter setup */

int joseph_ibs_setup(void);


/* Signature and verification functions */
int
joseph_ibs_extract(const BIGNUM *grp_p, const BIGNUM *grp_q, const BIGNUM *grp_g,
    const BIGNUM *x, const u_char *id, const u_int idlen,
    u_char **sig, u_int *siglen);
int joseph_ibs_offline_sign(const BIGNUM *grp_p, const BIGNUM *grp_g,const char path[]);

int joseph_ibs_online_sign(const BIGNUM *grp_p, const BIGNUM *grp_q, const BIGNUM *grp_g, BIGNUM *R, const BIGNUM *s,
                   const u_char *msg, const u_int msglen, const char path[], u_char **sig, u_int *siglen);

int
joseph_ibs_verify_buf(const BIGNUM *grp_p, const BIGNUM *grp_q,
    const BIGNUM *grp_g,
    const BIGNUM *g_x, const u_char *id, u_int idlen,
    const u_char *sig, u_int siglen, const u_char *msg, u_int msglen);
//////////////////////////////////////////////////////////////////////////////

#endif // JOSEPH_IBS_SCHEME_H
