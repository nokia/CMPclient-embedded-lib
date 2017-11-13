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

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/sha1.h"

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

/* Implementation that should never be optimized out by the compiler */
static void zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/* **************************************************************** */
/* CMP CTX-setting functions */
/* **************************************************************** */
void cmp_ctx_init( cmp_ctx *ctx, mbedtls_ctr_drbg_context *ctr_drbg)
{
    memset( ctx, 0, sizeof(cmp_ctx) );

    cmp_ctx_set_transactionID( ctx, ctr_drbg, 16);
    cmp_ctx_set_senderNonce( ctx, ctr_drbg, 16);
    cmp_ctx_set_popo_method( ctx, CMP_CTX_POPO_SIGNATURE);

    /* TODO: certConf not supported yet */
    cmp_ctx_set_implicit_confirm( ctx, 1);

    cmp_ctx_set_prot_md_alg( ctx, MBEDTLS_MD_SHA256);
    cmp_ctx_set_popo_md_alg( ctx, MBEDTLS_MD_SHA256);

    ctx->send_receive_cb = (cmp_send_receive_cb) send_receive;

    ctx->sport = 8080;
    ctx->spath = "pkix/";

    /* If there's a timesource ... */
    // cmp_ctx_set_messageTime( ctx, messageTime);

    /* That's implicitly anyway set
     * hardcoded, but we anyway only do one
    ctx->certReqId   = 0;
     */
}

/* **************************************************************** */
void cmp_ctx_set_server_host( cmp_ctx *ctx, const char *shost)
{
    ctx->shost = strdup(shost);
}

/* **************************************************************** */
void cmp_ctx_set_pbm_secret( cmp_ctx *ctx, const unsigned char *sec,
                                           size_t len )
{
    setStr(&ctx->secret, sec, len);
    ctx->secret_len = len;
}

/* **************************************************************** */
void cmp_ctx_set_pbm_reference( cmp_ctx *ctx, const unsigned char *ref,
                                              size_t len )
{
    setStr(&ctx->reference, ref, len);
    ctx->reference_len = len;
}

/* **************************************************************** */
int cmp_ctx_set_messageTime( cmp_ctx *ctx, const char *msgTime)
{
    if( strlen( msgTime ) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 )
    {
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA ); /* TODO this should be changed?  */
    }
    if( !ctx->messageTime)
        ctx->messageTime = mbedtls_calloc(1, MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1);
    if( !ctx->messageTime)
        goto err;

    strncpy( ctx->messageTime, msgTime, MBEDTLS_X509_RFC5280_UTC_TIME_LEN );
    ctx->messageTime[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->messageTime[MBEDTLS_X509_RFC5280_UTC_TIME_LEN] = '\0';

    return( 1 );
err:
    return( 0 );
}

/* **************************************************************** */
void cmp_ctx_set_transactionID( cmp_ctx *ctx,
                                mbedtls_ctr_drbg_context *ctr_drbg,
                                size_t len )
{
    cmp_ctx_set_rndm_str(&ctx->transactionID, &ctx->transactionID_len,
                         ctr_drbg, len);
    return;
}

/* **************************************************************** */
void cmp_ctx_set_senderNonce( cmp_ctx *ctx,
                              mbedtls_ctr_drbg_context *ctr_drbg,
                              size_t len )
{
    cmp_ctx_set_rndm_str(&ctx->senderNonce, &ctx->senderNonce_len,
                         ctr_drbg, len);
    return;
}


/* **************************************************************** */
void cmp_ctx_set_recipNonce( cmp_ctx *ctx, unsigned char *nonce, size_t len )
{
    setStr(&ctx->recipNonce, nonce, len);
}

/* **************************************************************** */
void cmp_ctx_set_prot_key( cmp_ctx *ctx, mbedtls_pk_context *key )
{
    ctx->prot_key = key;
}

/* **************************************************************** */
void cmp_ctx_set_cl_crt( cmp_ctx *ctx, mbedtls_x509_crt *crt)
{
    ctx->clCert = crt;
}

/* **************************************************************** */
void cmp_ctx_set_cl_crt_chain( cmp_ctx *ctx, mbedtls_x509_crt *crt)
{
    ctx->clCaCert = crt;
}

/* **************************************************************** */
int cmp_ctx_set_sender_name( cmp_ctx *ctx, const char *sender_name )
{
    return mbedtls_x509_string_to_names( &ctx->sender, sender_name );
}

/* **************************************************************** */
int cmp_ctx_set_recipient_name( cmp_ctx *ctx, const char *recipient_name )
{
  return mbedtls_x509_string_to_names( &ctx->recipient, recipient_name );
}

/* **************************************************************** */
void cmp_ctx_set_prot_md_alg( cmp_ctx *ctx, mbedtls_md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

/* **************************************************************** */
/* body CTX-setting functions */
/* **************************************************************** */

/* **************************************************************** */
int cmp_ctx_set_subject_name( cmp_ctx *ctx, const char *subject_name )
{
    return mbedtls_x509_string_to_names( &ctx->subject, subject_name );
}

/* **************************************************************** */
void cmp_ctx_set_new_key( cmp_ctx *ctx, mbedtls_pk_context *new_key )
{
    ctx->new_key = new_key;
}

/* **************************************************************** */
void cmp_ctx_set_popo_method( cmp_ctx *ctx, int popo_method )
{
    ctx->popo_method = popo_method;
}

/* **************************************************************** */
void cmp_ctx_set_popo_md_alg( cmp_ctx *ctx, mbedtls_md_type_t md_alg )
{
    ctx->popo_md_alg = md_alg;
}

/* **************************************************************** */
void cmp_ctx_set_pbmp( cmp_ctx *ctx, cmp_PBMParameter *pbmp)
{
    ctx->pbmp = pbmp;
}

/* **************************************************************** */
void cmp_ctx_set_next_body( cmp_ctx *ctx, int next_body)
{
    ctx->next_body = next_body;
}

/* **************************************************************** */
void cmp_ctx_set_implicit_confirm( cmp_ctx *ctx, int ic)
{
    ctx->implicitConfirm = ic;
}


/* **************************************************************** */
void cmp_ctx_free( cmp_ctx *ctx )
{
    mbedtls_asn1_free_named_data_list(&ctx->sender);
    mbedtls_asn1_free_named_data_list(&ctx->recipient);

    if( ctx->messageTime)
        mbedtls_free( ctx->messageTime);
    if( ctx->transactionID)
        mbedtls_free( ctx->transactionID);
    if( ctx->senderNonce)
        mbedtls_free( ctx->senderNonce);
    if( ctx->recipNonce)
        mbedtls_free( ctx->recipNonce);

    mbedtls_asn1_free_named_data_list(&ctx->subject);

    if( ctx->pbmp) {
        cmp_PBMParameter_free( ctx->pbmp);
        mbedtls_free( ctx->pbmp);
    }

    zeroize( ctx, sizeof(mbedtls_x509write_cert) );
}
