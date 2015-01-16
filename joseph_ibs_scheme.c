#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "buffer.h"
#include "joseph_ibs_scheme.h"

/*1024-bit MODP Group with 160-bit Prime Order Subgroup*/

#define _GROUP_P \
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6" \
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0" \
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70" \
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0" \
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708" \
    "DF1FB2BC2E4A4371"
#define _GROUP_G \
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F" \
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213" \
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1" \
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A" \
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24" \
    "855E6EEB22B3B2E5"
#define _GROUP_Q \
    "F518AA8781A8DF278ABA4E7D64B7CB9D49462353"

// Globle variables
/* x random [0, q) */
// g_x g^x;
BIGNUM *_x,*_msk, *_g_x;
struct modp_group *_grp;

int joseph_ibs_setup(void)
{


    BN_CTX *bn_ctx;
    struct modp_group *group;
    int success = 1;


    bn_ctx = BN_CTX_new();

    group = modp_group_from_g_p_and_q(_GROUP_G, _GROUP_P, _GROUP_Q);


    _grp=group;


    BIGNUM *v,*g_v;
    v =BN_new();
    g_v = BN_new();
    /*
     * v must be a random element of Zq, so 1 <= v < q
     * we also exclude v = 1, since g^1 looks dangerous
     */
    if ((v = bn_rand_range_gt_one(group->q)) == NULL) {

        goto out;
    }


    /* g_v = g^v mod p */
    if (BN_mod_exp(g_v, group->g, v, group->p, bn_ctx) == -1) {

        goto out;
    }

    _g_x=g_v;
    _msk=_x = v;
    success = 0;

out:
    return success;

}


/*
 * Calculate hash component of extract  H(g^v ||  id)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
extract_do_hash(const EVP_MD *evp_md, const BIGNUM *g_v, const u_char *id, u_int idlen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
        return NULL;
    }

    buffer_init(&b);
    /*h =H(g^v||ID)*/

    buffer_put_bignum2(&b, g_v);

    buffer_put_string(&b, id, idlen);


    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}

/*
 do extract work
 */
int
do_extract(const BIGNUM *grp_p, const BIGNUM *grp_q, const BIGNUM *grp_g,
    const EVP_MD *evp_md, const BIGNUM *x,
    const u_char *id, u_int idlen, BIGNUM **s_p, BIGNUM **g_r_p)
{
    int success = -1;
    BIGNUM *h, *tmp, *v, *g_v, *r;
    BN_CTX *bn_ctx;


    h = g_v = r = tmp = v = NULL;
    if ((bn_ctx = BN_CTX_new()) == NULL) {

        goto out;
    }
    if ((g_v = BN_new()) == NULL ||
        (r = BN_new()) == NULL ||
        (tmp = BN_new()) == NULL) {

        goto out;
    }

    /*
     * v must be a random element of Zq, so 1 <= v < q
     * we also exclude v = 1, since g^1 looks dangerous
     */
    if ((v = bn_rand_range_gt_one(grp_q)) == NULL) {

        goto out;
    }


    /* g_v = g^v mod p */
    if (BN_mod_exp(g_v, grp_g, v, grp_p, bn_ctx) == -1) {

        goto out;
    }

    /* h = H(g^v || id) */
    if ((h = extract_do_hash(evp_md, g_v, id, idlen)) == NULL) {

        goto out;
    }

    /* r = v + xh mod q */
    if (BN_mod_mul(tmp, x, h, grp_q, bn_ctx) == -1) {

        goto out;
    }
    if (BN_mod_add(r, v, tmp, grp_q, bn_ctx) == -1) {

        goto out;
    }

    *g_r_p = g_v;
    *s_p = r;

//**********************************************************************************test:g^s=RX^H(R,ID)
   //equation (1) in joseph paper
    /*
    BIGNUM *g_s,*tmp_tmp,*tmp2;
    BN_CTX *bn_ctx_tmp;

    g_s= NULL;
    if ((bn_ctx_tmp = BN_CTX_new()) == NULL) {
        error("%s: BN_CTX_new", __func__);
    }
    if ((g_s = BN_new()) == NULL ||
       (tmp_tmp = BN_new()) == NULL ||
       (tmp2 =BN_new()) ==NULL) {
        error("%s: BN_new", __func__);
    }

    // g_s = g^s mod p
    if (BN_mod_exp(g_s, grp_g, r, grp_p, bn_ctx_tmp) == -1) {
        error("%s: BN_mod_exp (g^v mod p)", __func__);

    }

    BIGNUM *Bigx;
    BN_CTX *bn_ctx_tmp1,*bn_ctx_tmp2;

    Bigx= NULL;
    if ((bn_ctx_tmp1 = BN_CTX_new()) == NULL||
        (bn_ctx_tmp2 = BN_CTX_new()) == NULL) {
        error("%s: BN_CTX_new", __func__);
    }
    if ((Bigx = BN_new()) == NULL) {
         error("%s: BN_new", __func__);
    }
    if (BN_mod_exp(Bigx, grp_g, x, grp_p, bn_ctx_tmp1) == -1) {
        error("%s: BN_mod_exp (g^v mod p)", __func__);
    }
    if(BN_mod_exp(tmp2, Bigx, h, grp_p, bn_ctx_tmp2) == -1)
    {
            error("%s: BN_mod_exp (g^v mod p)", __func__);
    }
    //g_v*X^H(R,id)

    if (BN_mod_mul(tmp_tmp, g_v, tmp2, grp_p, bn_ctx) == -1) {
        error("%s: BN_mod_mul (tmp = xv mod q)", __func__);
        goto out;
    }
*/
//************************************************************************Test


    success = 0;
 out:
    BN_CTX_free(bn_ctx);
    if (h != NULL)
        BN_clear_free(h);
    if (v != NULL)
        BN_clear_free(v);
    BN_clear_free(tmp);

    return success;
}

/*
 * Generate a secret key for identity ID
 * On success, 0 is returned and *siglen bytes of signature are returned in
 * *sig (caller to free). Returns -1 on failure.
 */
int
joseph_ibs_extract(const BIGNUM *grp_p, const BIGNUM *grp_q, const BIGNUM *grp_g, const BIGNUM *x,
    const u_char *id, const u_int idlen, u_char **sig, u_int *siglen)
{
    BIGNUM *g_x, *g_r, *s;
    BN_CTX *bn_ctx;

    int success = 1;

    if ((bn_ctx = BN_CTX_new()) == NULL)
       goto out;
    if ((g_x = BN_new()) == NULL|| (g_r = BN_new()) == NULL || (s = BN_new()) == NULL)
       goto out;
    if (BN_mod_exp(g_x, grp_g, x, grp_p, bn_ctx) == -1)
       goto out;

    Buffer b;

    if (do_extract(grp_p, grp_q, grp_g, EVP_sha1(),
        x, id, idlen, &s, &g_r) != 0)
        goto out;

    /* Signature is (g_r, s) */
    buffer_init(&b);
    /* XXX sigtype-hash as string? */
    buffer_put_bignum2(&b, g_r);
    buffer_put_bignum2(&b, s);
    *siglen = buffer_len(&b);

    if(*siglen == 0)
        goto out;
    *sig = malloc(*siglen);
    if (sig == NULL)
        goto out;

    memcpy(*sig, buffer_ptr(&b), *siglen);
    success = 0;
    buffer_free(&b);
out:

    BN_CTX_free(bn_ctx);
    if (g_x!= NULL)
        BN_clear_free(g_x);
    if (g_r != NULL)
        BN_clear_free(g_r);
    if (s != NULL)
        BN_clear_free(s);

    return success;
}


/*
 *
 */

int joseph_ibs_offline_sign(const BIGNUM *grp_p,const BIGNUM *grp_g,const char path[])
{
// generate a binary file which will be distributed to each nodes
    int i;
    int success = 1;
    BIGNUM *exp_i,*g_exp;
    BN_CTX *bn_ctx,*bn_ctx2;
    BIGNUM *big_2 = NULL;
    BIGNUM *big_i = NULL;
    BN_dec2bn(&big_2, "2");
    if ((bn_ctx = BN_CTX_new()) == NULL||
            (bn_ctx2 = BN_CTX_new())== NULL)
        goto out;

    if ((g_exp = BN_new()) == NULL || (exp_i = BN_new()) == NULL ||(big_i = BN_new()) == NULL) {
        goto out;
    }

    Buffer b;
    buffer_init(&b);

    for(i=0;i<160;i++)
    {
        BN_set_word(big_i, i);
        if (BN_exp(exp_i, big_2, big_i, bn_ctx) == -1)
           goto out;
        if (BN_mod_exp(g_exp, grp_g, exp_i, grp_p, bn_ctx2) == -1)
           goto out;
        buffer_put_bignum(&b, g_exp);
        g_exp = BN_new();

    }

    FILE* data;
    if ( (data = fopen("data.bin", "wb")) == NULL )
    {
        goto out;
    }
    fwrite(b.buf, sizeof(u_char), b.end, data);
    fclose(data);
    success = 0;

out:

    buffer_free(&b);
    BN_CTX_free(bn_ctx);
    BN_CTX_free(bn_ctx2);
    if (g_exp!= NULL)
        BN_clear_free(g_exp);
    if (exp_i != NULL)
        BN_clear_free(exp_i);
    if (big_2 != NULL)
        BN_clear_free(big_2);
    if (big_i != NULL)
        BN_clear_free(big_i);

    return success;
}


/*
 * Calculate hash component of  H(Y || R || msg)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
online_do_hash(const EVP_MD *evp_md, const BIGNUM *Y, const BIGNUM *R,
    const u_char *msg, u_int msglen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
       return NULL;
    }

    buffer_init(&b);
    /*h =H(Y||R||msg)*/
    buffer_put_bignum2(&b, Y);
    buffer_put_bignum2(&b, R);
    buffer_put_string(&b, msg, msglen);
    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}

/*
 *
 */

int
joseph_ibs_online_sign(const BIGNUM *grp_p, const BIGNUM *grp_q, const BIGNUM *grp_g, BIGNUM *R,const BIGNUM *s,
                   const u_char *msg, const u_int msglen, const char path[],
                   u_char **sig, u_int *siglen)
{
    int success = 1;
    BIGNUM *tmp;
    FILE *file;
    u_char *buffer;
    Buffer Y_buffer;
    buffer_init(&Y_buffer);
    tmp=BN_new();
    unsigned long fileLen;
    file=fopen("data.bin","rb");
    if(!file){
        return -1;
    }

    //Get file length
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);

    if(fileLen==0)
        goto out;
    //Allocate memory
    buffer=(u_char *)malloc(fileLen+1);
    if (!buffer)
    {

        fclose(file);
        return -1;
    }

    //Read file contents into buffer
    fread(buffer, fileLen, 1, file);
    fclose(file);

    buffer_append(&Y_buffer, buffer, fileLen);
    free(buffer);

    BIGNUM *BN_Array[160];
    int i;
    for(i=0;i<160;i++)
    {
        buffer_get_bignum(&Y_buffer,tmp);
        BN_Array[i]=tmp;
        tmp=BN_new();
    }
    buffer_free(&Y_buffer);
    //retrieve offline signature
    //////////////////////////////////////////////////

    BIGNUM *y_random;
    y_random=BN_new();
    if ((y_random = bn_rand_range_gt_one(grp_q)) == NULL) {
       goto out;
    }
    BIGNUM *continued_mul;
    BN_CTX *bn_ctx;
    BIGNUM *tmp_Y;
    bn_ctx = BN_CTX_new();
    continued_mul = BN_new();
    tmp_Y = BN_new();

    BN_one(continued_mul);
    for (i=0;i<160;i++)
    {
        tmp_Y = BN_Array[i];
        int result=BN_is_bit_set(y_random,i);
        if(result==1)
        {
           if(BN_mod_mul(continued_mul, continued_mul, tmp_Y, grp_p, bn_ctx) == -1)
           {
               goto out;
           }
        }
    }
    //compute Y
    //////////////////////////////////////////////////////

    BIGNUM *h, *z;
    BN_CTX *bn_ctx1;
    z=h=NULL;
    z=BN_new();
    bn_ctx1=BN_CTX_new();

    h=online_do_hash(EVP_sha1(), continued_mul, R, msg, msglen);


    /* z = y+ hs mod q */
    if (BN_mod_mul(tmp, h, s, grp_q, bn_ctx1) == -1) {

        goto out;
    }
    if (BN_mod_add(z, y_random, tmp, grp_q, bn_ctx1) == -1) {

        goto out;
    }

    Buffer b;
    /* Signature is (Y, R,z) */
    buffer_init(&b);
        /* XXX sigtype-hash as string? */
    buffer_put_bignum2(&b, continued_mul);
    buffer_put_bignum2(&b, R);
    buffer_put_bignum2(&b, z);
    *siglen = buffer_len(&b);

    if(*siglen == 0)
        goto out;
    *sig = malloc(*siglen);
    if (sig == NULL)
        goto out;

    memcpy(*sig, buffer_ptr(&b), *siglen);

    buffer_free(&b);


    success = 0;
out:
    BN_CTX_free(bn_ctx);
    BN_CTX_free(bn_ctx1);
    if (h != NULL)
        BN_clear_free(h);
    if (z!= NULL)
        BN_clear_free(z);
    if(y_random!=NULL)
        BN_clear_free(y_random);
    if(continued_mul!=NULL)
        BN_clear_free(continued_mul);
    if(tmp!=NULL)
        BN_clear_free(tmp);

    for(i=0;i<160;i++)
    {
        if(BN_Array[i]!=NULL)
            BN_clear_free(BN_Array[i]);

    }
    return success;

}


/*
 * Calculate hash component of  H(Y || R || msg)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
verify_do_hash(const EVP_MD *evp_md, const BIGNUM *Y, const BIGNUM *R,
    const u_char *msg, u_int msglen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
       return NULL;
    }

    buffer_init(&b);
    /*h =H(Y||R||msg)*/
    buffer_put_bignum2(&b, Y);
    buffer_put_bignum2(&b, R);
    buffer_put_string(&b, msg, msglen);
    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}

/*
 * Calculate hash component of  H(R || id)
 * using the hash function defined by "evp_md". Returns signature as
 * bignum or NULL on error.
 */

static BIGNUM *
verify_do_hash_RID(const EVP_MD *evp_md, const BIGNUM *R, const u_char *id, u_int idlen)
{
    u_char *digest;
    u_int digest_len;
    BIGNUM *h;
    Buffer b;
    int success = -1;

    if ((h = BN_new()) == NULL) {
        return NULL;
    }

    buffer_init(&b);
    /*h =H(g^v||ID)*/

    buffer_put_bignum2(&b, R);

    buffer_put_string(&b, id, idlen);


    if (hash_buffer(buffer_ptr(&b), buffer_len(&b), evp_md,
        &digest, &digest_len) != 0) {

        goto out;
    }
    if (BN_bin2bn(digest, (int)digest_len, h) == NULL) {

        goto out;
    }
    success = 0;

 out:
    buffer_free(&b);
    bzero(digest, digest_len);
    xfree(digest);
    digest_len = 0;
    if (success == 0)
        return h;
    BN_clear_free(h);
    return NULL;
}

/*
 * do verify signature
 * Returns -1 on failure, 0 on incorrect signature or 1 on matching signature.
 */
int
do_verify(const BIGNUM *grp_p, const BIGNUM *grp_q, const BIGNUM *grp_g,
    const EVP_MD *evp_md, const BIGNUM *g_x, const u_char *id, u_int idlen, const u_char *msg, u_int msglen,
    const BIGNUM *Y, const BIGNUM *R, const BIGNUM *z)
{
    int success = -1;
    BIGNUM *h, *h_RID, *g_xhh, *g_z, *hh, *R_h;
    BIGNUM *expected = NULL;
    BN_CTX *bn_ctx;

    /* Avoid degenerate cases: g^0 yields a spoofable signature */
    if (BN_cmp(g_x, BN_value_one()) <= 0) {

        return -1;
    }
    if (BN_cmp(g_x, grp_p) >= 0) {

        return -1;
    }

    hh = h = h_RID = g_xhh = R_h = g_z = expected = NULL;
    if ((bn_ctx = BN_CTX_new()) == NULL) {
        goto out;
    }
    if ((g_xhh = BN_new()) == NULL ||
        (g_z = BN_new()) == NULL ||
        (hh = BN_new()) == NULL ||
        (R_h =BN_new()) == NULL ||
        (expected = BN_new()) == NULL){
        goto out;
    }


    /* h = H(Y|| R || m) */
    if ((h = verify_do_hash(EVP_sha1(), Y, R, msg, msglen)) == NULL) {

        goto out;
    }
    /* h_RID = H(R || ID) */
    if ((h_RID = verify_do_hash_RID(EVP_sha1(), R, id, idlen)) == NULL) {

        goto out;
    }

    if(BN_mod_mul(hh, h, h_RID, grp_p, bn_ctx) == -1)
    {
        goto out;

    }


    /* g_xhh = (g^x)^hh p*/
    if (BN_mod_exp(g_xhh, g_x, hh, grp_p, bn_ctx) == -1) {

        goto out;
    }


    /* R_h = R^h */
    if (BN_mod_exp(R_h, R, h, grp_p, bn_ctx) == -1) {
        goto out;
    }


    /* expected = g^r * R^h * g_xhh */
    if (BN_mod_mul(expected, Y, R_h, grp_p, bn_ctx) == -1) {
        goto out;
    }

    if (BN_mod_mul(expected, expected, g_xhh, grp_p, bn_ctx) == -1) {
        goto out;
    }

    /* g_z = g^z */
    if (BN_mod_exp(g_z, grp_g, z, grp_p, bn_ctx) == -1) {
        error("%s: BN_mod_exp (g_x^h mod p)", __func__);
        goto out;
    }


    /* Check g_z == expected */
    success = (BN_cmp(expected, g_z) == 0);



 out:
    BN_CTX_free(bn_ctx);
    if (h != NULL)
        BN_clear_free(h);
    if (g_xhh!= NULL)
        BN_clear_free(g_xhh);
    if (g_z != NULL)
        BN_clear_free(g_z);
    if (hh != NULL)
        BN_clear_free(hh);
    if (R_h != NULL)
        BN_clear_free(R_h);
    if (h_RID != NULL)
        BN_clear_free(h_RID);
    if (expected != NULL)
        BN_clear_free(expected);
    return success;
}

/*
 * Verify signature 'sig' of length 'siglen'
 * Returns -1 on failure, 0 on incorrect signature or 1 on matching signature.
 */
int
joseph_ibs_verify_buf(const BIGNUM *grp_p, const BIGNUM *grp_q,
    const BIGNUM *grp_g,
    const BIGNUM *g_x, const u_char *id, u_int idlen,
    const u_char *sig, u_int siglen, const u_char *msg, u_int msglen)
{
    Buffer b;
    int ret = -1;
    u_int rlen;
    BIGNUM *Y, *R, *z;
    BN_CTX *bn_ctx;

    Y = R = z = NULL;
    if ((Y = BN_new()) == NULL ||
        (R = BN_new()) == NULL ||
        (z = BN_new()) == NULL)
    {
        goto out;
    }

    if ((bn_ctx = BN_CTX_new()) == NULL) {
        goto out;
    }

    /* Extract Y, R and z from signature */
    buffer_init(&b);
    buffer_append(&b, sig, siglen);

    buffer_get_bignum2(&b, Y);
    buffer_get_bignum2(&b, R);
    buffer_get_bignum2(&b, z);
    rlen = buffer_len(&b);
    buffer_free(&b);
    if (rlen != 0) {
        goto out;
    }


    ret = do_verify(grp_p, grp_q, grp_g, EVP_sha1(),
        g_x, id, idlen, msg, msglen, Y, R, z);
 out:
    if(Y != NULL)
        BN_clear_free(Y);
    if(R != NULL)
        BN_clear_free(R);
    if(z !=NULL)
        BN_clear_free(z);

    return ret;
}

/* Helper functions */

/*
 * Generate uniformly distributed random number in range (1, high).
 * Return number on success, NULL on failure.
 */
BIGNUM *
bn_rand_range_gt_one(const BIGNUM *high)
{
    BIGNUM *r, *tmp;
    int success = -1;

    if ((tmp = BN_new()) == NULL) {

        return NULL;
    }
    if ((r = BN_new()) == NULL) {

        goto out;
    }
    if (BN_set_word(tmp, 2) != 1) {

        goto out;
    }
    if (BN_sub(tmp, high, tmp) == -1) {

        goto out;
    }
    if (BN_rand_range(r, tmp) == -1) {

        goto out;
    }
    if (BN_set_word(tmp, 2) != 1) {

        goto out;
    }
    if (BN_add(r, r, tmp) == -1) {

        goto out;
    }
    success = 0;
 out:
    BN_clear_free(tmp);
    if (success == 0)
        return r;
    BN_clear_free(r);
    return NULL;
}

/*
 * Hash contents of buffer 'b' with hash 'md'. Returns 0 on success,
 * with digest via 'digestp' (caller to free) and length via 'lenp'.
 * Returns -1 on failure.
 */
int
hash_buffer(const u_char *buf, u_int len, const EVP_MD *md,
    u_char **digestp, u_int *lenp)
{
    u_char digest[EVP_MAX_MD_SIZE];
    u_int digest_len;
    EVP_MD_CTX evp_md_ctx;
    int success = -1;

    EVP_MD_CTX_init(&evp_md_ctx);

    if (EVP_DigestInit_ex(&evp_md_ctx, md, NULL) != 1) {

        goto out;
    }
    if (EVP_DigestUpdate(&evp_md_ctx, buf, len) != 1) {

        goto out;
    }
    if (EVP_DigestFinal_ex(&evp_md_ctx, digest, &digest_len) != 1) {

        goto out;
    }

    if(digest_len == 0)
        goto out;
    *digestp = malloc(digest_len);
    if (digestp == NULL)
        goto out;
    *lenp = digest_len;
    memcpy(*digestp, digest, *lenp);
    success = 0;
 out:
    EVP_MD_CTX_cleanup(&evp_md_ctx);
    bzero(digest, sizeof(digest));
    digest_len = 0;
    return success;
}

/*
 * Construct a MODP group from hex strings p (which must be a safe
 * prime) and g, q
 */
struct modp_group *
modp_group_from_g_p_and_q(const char *grp_g, const char *grp_p, const char *grp_q)
{
    struct modp_group *ret;

    ret = malloc(sizeof(*ret));
    if(ret==NULL)
        return ret;
    ret->p = ret->q = ret->g = NULL;
    if (BN_hex2bn(&ret->p, grp_p) == 0 ||BN_hex2bn(&ret->g, grp_g) == 0 || BN_hex2bn(&ret->q, grp_q) == 0)
        fatal("%s: BN_hex2bn", __func__);

    return ret;
}

void
modp_group_free(struct modp_group *grp)
{
    if (grp->g != NULL)
        BN_clear_free(grp->g);
    if (grp->p != NULL)
        BN_clear_free(grp->p);
    if (grp->q != NULL)
        BN_clear_free(grp->q);
    bzero(grp, sizeof(*grp));
    xfree(grp);
}
