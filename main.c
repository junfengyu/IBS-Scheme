#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include "schnorr.h"
#include "log.h"
#include "buffer.h"

extern BIGNUM *_x, *_msk, *_g_x;

extern struct modp_group *_grp;

int
main(int argc, char **argv)
{
    u_char *secretkey,*sig;
    u_int secretkey_len, siglen;

    int sizeofulong=sizeof(BN_ULONG);
    printf("size of ulong is %d in your device.\n",sizeofulong);

//////////////////////////////////////////////////////////////////////////////////////////////////
    //  //PKG: PKG  generate secret key and offline signature for every node
    joseph_ibs_setup();
    joseph_ibs_extract(_grp->p, _grp->q, _grp->g, _x,"10.0.0.1", 8, &secretkey, &secretkey_len);

    joseph_ibs_offline_sign(_grp->p, _grp->g,"data.bin");



//////////////////////////////////////////////////////////////////////////////////////////////////
   // Signer
    BIGNUM *R, *s;
    R = s = NULL;
    R = BN_new();
    s = BN_new();
    Buffer b;
    int rlen=0;

    /* Extract g^v and s from offline signature */
    buffer_init(&b);
    buffer_append(&b, secretkey, secretkey_len);
    buffer_get_bignum2(&b, R);
    buffer_get_bignum2(&b, s);
    rlen = buffer_len(&b);
    buffer_free(&b);

    if (rlen != 0)
        return -1;

    joseph_ibs_online_sign(_grp->p, _grp->q, _grp->g, R, s, "hello world!", 12 ,"data.bin",
                       &sig, &siglen);
//////////////////////////////////////////////////////////////////////////////////////////////////




    int ret=joseph_ibs_verify_buf(_grp->p, _grp->q, _grp->g, _g_x, "10.0.0.1", 8, sig, siglen,
                          "hello world!", 12);
    if(ret==1)
        printf("verification result correct!\n");

    ret=joseph_ibs_verify_buf(_grp->p, _grp->q, _grp->g, _g_x, "10.0.0.2", 8, sig, siglen,
                              "hello world!", 12);
    if(ret==0)
        printf("verification result correct!\n");
    ret=joseph_ibs_verify_buf(_grp->p, _grp->q, _grp->g, _g_x, "10.0.0.1", 8, sig, siglen,
                              "hello1world!", 12);
    if(ret==0)
        printf("verification result correct!\n");
    return 0;
}


