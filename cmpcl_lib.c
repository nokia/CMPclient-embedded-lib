/*
 *  Copyright (c) 2016-2017, Nokia, All rights reserved.
 *
 *  The CMP client contains code derived from examples and documentation for
 *  mbedTLS by ARM
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "cmpcl_int.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#define mbedtls_snprintf   snprintf
#endif

/* **************************************************************** */
/* HELPERS */
/* **************************************************************** */

int setStr( unsigned char **dst, const unsigned char *src, const size_t len)
{
    if( !src) return 0;
    if( *dst)
        mbedtls_free( *dst);
    if( (*dst = (unsigned char*) mbedtls_calloc(1, len)) == NULL) {
        printf("Error allocating space\n");
        exit(1); /* TODO: handle better */
    }
    memcpy( *dst, src, len); /* TODO: catch error */
    return 0;
}

/* **************************************************************** */
void cmp_ctx_set_rndm_str( unsigned char **str,
                          size_t *str_len,
                          mbedtls_ctr_drbg_context *ctr_drbg,
                          size_t len )
{
    int ret;

    if( *str )
        mbedtls_free( *str);
    *str = (unsigned char*) mbedtls_calloc(1, len);
    *str_len = len;

    if( (ret = mbedtls_ctr_drbg_random( ctr_drbg, *str, len )) != 0 )
        printf("Error generating random string: %d\n", ret);

    return; /* TODO Errorhandling */
}

/* **************************************************************** */
/* PBM */
/* **************************************************************** */

void cmp_PBMParameter_init( cmp_PBMParameter *pbmp,
                                mbedtls_ctr_drbg_context *ctr_drbg,
                                size_t salt_len,
                                mbedtls_md_type_t owf,
                                int iterationCount,
                                mbedtls_md_type_t mac )
{
    memset( pbmp, 0, sizeof(cmp_PBMParameter) );

    cmp_ctx_set_rndm_str(&pbmp->salt,
                        &pbmp->salt_len,
                        ctr_drbg,
                        salt_len);

    pbmp->owf = owf;
    pbmp->iterationCount = iterationCount;
    pbmp->mac = mac;
}

void cmp_PBMParameter_free( cmp_PBMParameter *pbmp )
{
    if( pbmp->salt)
        mbedtls_free( pbmp->salt);
}

int cmp_PBM_new( const cmp_PBMParameter *pbmp,
                     const unsigned char *secret, size_t secret_len,
                     const unsigned char *msg, size_t msg_len,
                     unsigned char *mac, size_t *mac_len)
{
    unsigned char *basekey;
    unsigned int bk_len;
    int iter;
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info;

    basekey = (unsigned char*) mbedtls_calloc(1, MBEDTLS_MD_MAX_SIZE);

    if (!mac)
        goto err;

    if (!pbmp)
        goto err;
    if (!msg)
        goto err;
    if (!secret)
        goto err;

    mbedtls_md_init( &md_ctx );

    /*
     * owf identifies the hash algorithm and associated parameters used to
     * compute the key used in the MAC process.  All implementations MUST
     * support SHA-1.
     */

    if (!(md_info = mbedtls_md_info_from_type( pbmp->owf )))
        goto err;

    bk_len = mbedtls_md_get_size (md_info);

    if (mbedtls_md_setup( &md_ctx, md_info, 0) != 0)
        goto err;

    if (mbedtls_md_starts( &md_ctx) != 0)
        goto err;

    if (mbedtls_md_update( &md_ctx, secret, secret_len) != 0)
        goto err;

    if (mbedtls_md_update( &md_ctx, pbmp->salt, pbmp->salt_len) != 0)
        goto err;

    if (mbedtls_md_finish( &md_ctx, basekey) != 0)
        goto err;

    iter = pbmp->iterationCount-1; /* first iteration already done above */
    while (iter-- > 0) {
        /* maybe this could be done with mbedtls_md - but *input=*ouput... */
        if (mbedtls_md_starts( &md_ctx) != 0)
            goto err;
        if (mbedtls_md_update( &md_ctx, basekey, bk_len) != 0)
            goto err;
        if (mbedtls_md_finish( &md_ctx, basekey) != 0)
            goto err;
    }
    mbedtls_md_free(&md_ctx);

    /*
     * mac identifies the algorithm and associated parameters of the MAC
     * function to be used.  All implementations MUST support HMAC-SHA1
     * [HMAC].      All implementations SHOULD support DES-MAC and Triple-
     * DES-MAC [PKCS11].
     */
    mbedtls_md_init( &md_ctx );

    if (!(md_info = mbedtls_md_info_from_type( pbmp->mac )))
        goto err;

    *mac_len = mbedtls_md_get_size (md_info);

    if (mbedtls_md_setup( &md_ctx, md_info, 1) != 0)
        goto err;

    if (mbedtls_md_hmac_starts( &md_ctx, basekey, bk_len) != 0)
        goto err;

    if (mbedtls_md_hmac_update( &md_ctx, msg, msg_len) != 0)
        goto err;

    if (mbedtls_md_hmac_finish( &md_ctx, mac) != 0)
        goto err;

    /* cleanup */
    mbedtls_free(basekey);
    mbedtls_md_free(&md_ctx);

    return 0;
err:
    mbedtls_md_free(&md_ctx); /* TODO: do I need to check anything before? */
    mbedtls_free(basekey);
    return 1;
}

