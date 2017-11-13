/*
 *  Copyright (c) 2016-2017, Nokia, All rights reserved.
 *
 *  The CMP client contains code derived from examples and documentation for
 *  mbedTLS by ARM
 *
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
#include "mbedtls/ecdsa.h" /* for MBEDTLS_ECDSA_MAX_LEN */

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

int cmpcl_CRMFwrite_CertReqMsg_der( unsigned char **p, unsigned char *start,
                                      cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;

    unsigned char *popo_input_buf;
    unsigned char *popo_input_p;
    int popo_input_len = 0;
    unsigned char *hash;

    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *sig;
    size_t sig_and_oid_len = 0, sig_len;
    mbedtls_pk_type_t pk_alg;

#define POPO_INPUT_BUF_SIZE 1024 /* TODO: that is not overly effective, but what to do? */
    popo_input_buf = mbedtls_calloc(1, POPO_INPUT_BUF_SIZE);
    sig = mbedtls_calloc(1, MBEDTLS_MPI_MAX_SIZE);
    hash = mbedtls_calloc(1, MBEDTLS_MD_MAX_SIZE);


    /* regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL */


    /* Popo */


    switch (ctx->popo_method) {
      case CMP_CTX_POPO_RAVERIFIED:
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_null( p, start ) );
        len--; /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
        (*p)++;       /* +1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );
        break;
      case CMP_CTX_POPO_SIGNATURE:
        /* TODO
           poposkInput contains the data to be signed, when present.  This
           field MUST be present when the certificate template does not
           contain both the public key value and a subject name value.
         */
        popo_input_p = popo_input_buf+POPO_INPUT_BUF_SIZE;
        MBEDTLS_ASN1_CHK_ADD( popo_input_len, cmpcl_CRMFwrite_CertRequest_der( &popo_input_p, popo_input_buf, ctx ) );

        mbedtls_md( mbedtls_md_info_from_type( ctx->popo_md_alg ), popo_input_p, popo_input_len, hash );

        /* TODO the last parapeters f_rng and p_rng need to come from outside for EC keys... */

        if( ( ret = mbedtls_pk_sign( ctx->new_key, ctx->popo_md_alg, hash, 0, sig, &sig_len, NULL, NULL ) ) != 0 )
          printf("ERROR creating hash, ret=%d\n", ret);

        /*
         * Write data to output buffer
         */
        pk_alg = mbedtls_pk_get_type( ctx->new_key);
        if( pk_alg == MBEDTLS_PK_ECKEY )
          pk_alg = MBEDTLS_PK_ECDSA;
        if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->popo_md_alg, &sig_oid, &sig_oid_len ) ) != 0 )
          printf("ERROR getting OID\n");

        MBEDTLS_ASN1_CHK_ADD( sig_and_oid_len, mbedtls_x509_write_sig( p, start, sig_oid, sig_oid_len, sig, sig_len ) );

        len += sig_and_oid_len;
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sig_and_oid_len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );

        break;
      default:
        printf("POPO method %d not supported", ctx->popo_method);
    }

    /* Cert Request */
    MBEDTLS_ASN1_CHK_ADD( len, cmpcl_CRMFwrite_CertRequest_der( p, start, ctx ) );

    /*
     * CertReqMsg ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    /* cleanup */
    mbedtls_free(popo_input_buf);
    mbedtls_free(sig);
    mbedtls_free(hash);
    return( (int) len );
}


/* **************************************************************** */

int cmpcl_CRMFwrite_CertRequest_der( unsigned char **p, unsigned char *start,
                                       cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;
    size_t sub_len = 0; /* actually only needed if Controls were added */
    size_t sub2_len = 0;
    size_t pub_len = 0; /* TODO that can potentially be substituted with sub_len */


    /* Controls */


    /* certTemplate */
    /*
       certTemplate  CertTemplate,  -- Selected fields of cert to be issued
     */

    /* extensions   [9] Extensions            OPTIONAL */
    /* subjectUID   [8] UniqueIdentifier      OPTIONAL */
    /* issuerUID    [7] UniqueIdentifier      OPTIONAL */


    /* publicKey    [6] SubjectPublicKeyInfo  OPTIONAL */
    if (ctx->new_key) {
      MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_pk_write_pubkey_der( ctx->new_key, start, *p - start ) );
      *p -= pub_len -1;      /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */
      sub_len += pub_len -1; /* -1 is as we're intentionally overwriting the SEQUENCE TAG from the function for IMPLICIT */

      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 6 ) );
    }

    /* subject      [5] Name                  OPTIONAL */
    if (ctx->subject) {
      sub2_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub2_len, mbedtls_x509_write_names( p, start, ctx->subject ) );
      sub_len += sub2_len;

      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub2_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 5 ) );
    }

    /* validity     [4] OptionalValidity      OPTIONAL */
    /* issuer       [3] Name                  OPTIONAL */
    /* signingAlg   [2] AlgorithmIdentifier   OPTIONAL */
    /* serialNumber [1] INTEGER               OPTIONAL */
    /* version      [0] Version               OPTIONAL */


    /*
       CertTemplate ::= SEQUENCE
     */
    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    /*
       certReqId     INTEGER,          -- ID for matching request and reply
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, ctx->certReqId ) );

    /*
     * CertRequest ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    return( (int) len );
}


/* **************************************************************** */
/* DER-writing functions */
/* **************************************************************** */

static int msg_sig_alg_prot( mbedtls_pk_context *key,
                             mbedtls_md_type_t md,
                             const unsigned char* input,
                             size_t in_len,
                             unsigned char *sig,
                             size_t *sig_len)
{
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

    mbedtls_md( mbedtls_md_info_from_type( md ), input, in_len, hash );

    /* TODO the last parameters f_rng and p_rng need to come from outside for EC keys... */

    return mbedtls_pk_sign( key, md, hash, 0, sig, sig_len, NULL, NULL );
}

/* **************************************************************** */
int cmpcl_CMPwrite_PKIMessage_protection_der( unsigned char **p,
                                              unsigned char *start,
                                              cmp_ctx *ctx,
                                              const unsigned char* input,
                                              const size_t in_len) /* TODO that random stuff for ECDSA... */
{
    int ret;
    size_t len = 0;
    unsigned char *prot;
    size_t prot_len = 0;

    prot = mbedtls_calloc(1, MBEDTLS_MPI_MAX_SIZE);

    if (ctx->secret && ctx->reference && ctx->pbmp) { /* MSG_MAC_ALG */
       if ( (ret = cmp_PBM_new( ctx->pbmp,
                          ctx->secret,
                          ctx->secret_len,
                          input,
                          in_len,
                          prot,
                          &prot_len)) != 0)
           goto err;
    } else if (ctx->prot_key && ctx->md_alg) {/* MSG_SIG_ALG */
        if ( (ret = msg_sig_alg_prot( ctx->prot_key,
                          ctx->md_alg,
                          input,
                          in_len,
                          prot,
                          &prot_len)) != 0)
            goto err;
    } else {
        printf( "WARN: no protection\n");
        return 0;
    }

    if (*p < start || (size_t)( *p - start ) < prot_len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = prot_len;
    (*p) -= len;
    memcpy( *p, prot, len );

    if (*p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );

    mbedtls_free(prot);
    return( (int) len );
err:
    mbedtls_free(prot);
    return 0;
}

static size_t cmpcl_CMPwrite_ExtraCerts_der( unsigned char **p,
                                            unsigned char *start,
                                            cmp_ctx *ctx)
{
    int ret;
    size_t len = 0;
    /* for now, only write max one "client CaCert" and the client Cert */
    /* TODO: work on a stack */
    if(ctx->clCaCert)
    {
        size_t sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->clCaCert->raw.p, ctx->clCaCert->raw.len ));
        len += sub_len;
    }
    if(ctx->clCert)
    {
        size_t sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->clCert->raw.p, ctx->clCert->raw.len ));
        len += sub_len;
    }
    if(len) {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    }
    return len;
}


/* **************************************************************** */
int cmpcl_CMPwrite_PKIMessage_der( cmp_ctx *ctx,
                                     unsigned char *start, size_t size, unsigned char **myp)  /* TODO that random stuff for ECDSA... */
{
    int ret;
    unsigned char *x;
    unsigned char **p;
    size_t len = 0;
    size_t extraCerts_len = 0;
    size_t body_len = 0;
    size_t cr_len = 0; /* needed for length of CertReqest sequence */
    unsigned char *prot_end_p;
    size_t prot_len = 0;
    size_t protPart_len = 0;
    unsigned char *protPart_p;

    /* the end of the buffer */
    x = start + size;
    /* helps to keep all the same variable names in the ASN1 writer functs */
    p = &x;

    MBEDTLS_ASN1_CHK_ADD( extraCerts_len, cmpcl_CMPwrite_ExtraCerts_der( p, start, ctx));

    prot_end_p = *p; /* from this point the real signature will need to be written later */
    /* MBEDTLS_ECDSA_MAX_LEN is max ECDSA len, ECDSA signatures have variable size */
    if( ctx->prot_key && (mbedtls_pk_get_type( ctx->prot_key) == MBEDTLS_PK_ECKEY) ) {
        *p -= MBEDTLS_ECDSA_MAX_LEN;
        prot_len = MBEDTLS_ECDSA_MAX_LEN;
    } else {
        /* figure out sig length - and write there. TODO TODO TODO: doing that two times is highly inefficient, but how to figure out the length otherwise? */
        MBEDTLS_ASN1_CHK_ADD( prot_len, cmpcl_CMPwrite_PKIMessage_protection_der( p, start, ctx, (const unsigned char*) "", 0) );
    }

    switch (ctx->next_body) {
      case MBEDTLS_CMP_PKIBODY_IR:
      case MBEDTLS_CMP_PKIBODY_CR:
      case MBEDTLS_CMP_PKIBODY_KUR:
          /* Adding one *single* CertReqest here */
          MBEDTLS_ASN1_CHK_ADD( cr_len, cmpcl_CRMFwrite_CertReqMsg_der( p, start, ctx ) );
          body_len += cr_len;
          /* CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg */
          MBEDTLS_ASN1_CHK_ADD( body_len, mbedtls_asn1_write_len( p, start, cr_len ) );
          MBEDTLS_ASN1_CHK_ADD( body_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );
          break;
      case MBEDTLS_CMP_PKIBODY_PKICONF: /* the client does not need to send that - but easiest for first testing ;-) */
        MBEDTLS_ASN1_CHK_ADD( body_len, mbedtls_asn1_write_null( p, start ) );
        break;
      default:
        printf("NOT SUPPORTED PKIBody_type %d\n", ctx->next_body); /* TODO */
    }
    protPart_len += body_len;

    /* [x] */
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_len( p, start, body_len ) );
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | ctx->next_body ) );

    /*
     *   header           PKIHeader
     */
    MBEDTLS_ASN1_CHK_ADD( protPart_len, cmpcl_CMPwrite_PKIHeader_der( p, start, ctx ) );

    /* temporary sequence TL for calculating the protection
        ProtectedPart ::= SEQUENCE {
            header    PKIHeader,
            body      PKIBody
        }
     */
    protPart_p = *p;
    size_t content_len = protPart_len;
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_len( &protPart_p, start, protPart_len ) );
    MBEDTLS_ASN1_CHK_ADD( protPart_len, mbedtls_asn1_write_tag( &protPart_p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    /* ECDSA has variable signature length */
    if( ctx->prot_key && (mbedtls_pk_get_type( ctx->prot_key) == MBEDTLS_PK_ECKEY) ) {
        size_t real_prot_len = 0;
        /* TODO: done twice, highly inefficient */
        unsigned char *real_prot_end_p = prot_end_p;
        real_prot_len = cmpcl_CMPwrite_PKIMessage_protection_der( &real_prot_end_p, start, ctx, protPart_p, protPart_len);
        real_prot_end_p = prot_end_p - (prot_len - real_prot_len);
        cmpcl_CMPwrite_PKIMessage_protection_der( &real_prot_end_p, start, ctx, protPart_p, protPart_len);
        /* rewrite ExtraCerts at right position */
        unsigned char *real_extra_end_p = prot_end_p - (prot_len - real_prot_len) + extraCerts_len;
        cmpcl_CMPwrite_ExtraCerts_der( &real_extra_end_p, start, ctx);
        prot_len = real_prot_len;
    } else {
        /* write the real protection over the mock one */
        cmpcl_CMPwrite_PKIMessage_protection_der( &prot_end_p, start, ctx, protPart_p, protPart_len);
    }

    /* total message length */
    len = content_len + prot_len + extraCerts_len;

    /* write over the temporary sequence TL
     * PKIMessage ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    *myp = *p;
    return( (int) len );
}

#if 0
/* FIND THE KEY IDENTIFIER EXTENSION NEEDED FOR senderKID */
/* TODO doesn't work as I don't find the key identifier from extensions :-/ */
static int getExtension( mbedtls_x509_buf *v3_ext)
{
CMPDBG
    int ret;
    size_t len;
    unsigned char *end_ext_data, *end_ext_octet;
    unsigned char *c, *end;
    unsigned char **p;

    p = &c;
    *p = v3_ext->p;
    end = *p + v3_ext->len;

    /* the outermost sequence needs to be taken away ... */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
      printf("ERROR with extension\n");;

    while( *p < end )
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        int ext_type = 0;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_data = *p + len;

        /* Get extension ID */
        extn_oid.tag = **p;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &extn_oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
        {
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
            }

        extn_oid.p = *p;
        *p += extn_oid.len;

        if( ( end - *p ) < 1 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_OUT_OF_DATA );

        /* Get optional critical */
        if( ( ret = mbedtls_asn1_get_bool( p, end_ext_data, &is_critical ) ) != 0 &&
            ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        /* Data should be octet string type */
        if( ( ret = mbedtls_asn1_get_tag( p, end_ext_data, &len,
                MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_octet = *p + len;

        if( end_ext_octet != end_ext_data )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

        /*
         * Detect supported extensions
         */
        ret = mbedtls_oid_get_x509_ext_type( &extn_oid, &ext_type ); /* TODO This does NOT give the ID if the extension is not supported :-/ */

CMPDBGV("Ext type %d, ret %d\n", ext_type, ret);

        switch( ext_type )
        {
        case MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER:
            break;

        default:
            *p = end_ext_octet;
        }
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

CMPDBG
    return( 0 );
}
#endif /* 0 */

/* **************************************************************** */
static int cmpcl_CMPwrite_PBMParameter_der( unsigned char **p, unsigned char *start,
                                       cmp_PBMParameter *pbmp)
{
    /*
      PBMParameter ::= SEQUENCE {
         salt                OCTET STRING,
         owf                 AlgorithmIdentifier,
         iterationCount      INTEGER,
         mac                 AlgorithmIdentifier
         )
         */

    int ret;
    size_t len = 0;
    size_t sub_len = 0;
    const char *sig_oid;
    size_t sig_oid_len = 0;

    /* mac                 AlgorithmIdentifier */
/* TODO: HARDCODED - that's not in mbedtls/include/mbedtls/oid.h - MBEDTLS_OID_HMAC_SHA1 is not correct*/
/* RFC 4210: HMAC-SHA1 {1 3 6 1 5 5 8 1 2} */
#define HMAC_SHA1_OID "\x2b\x06\x01\x05\x05\x08\x01\x02"
    /* RFC 4231:
       rsadsi OBJECT IDENTIFIER ::=
       {iso(1) member-body(2) us(840) rsadsi(113549)}

       digestAlgorithm   OBJECT IDENTIFIER ::= {rsadsi 2}

       id-hmacWithSHA224 OBJECT IDENTIFIER ::= {digestAlgorithm 8}
       id-hmacWithSHA256 OBJECT IDENTIFIER ::= {digestAlgorithm 9}
       id-hmacWithSHA384 OBJECT IDENTIFIER ::= {digestAlgorithm 10}
       id-hmacWithSHA512 OBJECT IDENTIFIER ::= {digestAlgorithm 11}
     */
#define HMAC_SHA256_OID "\x2A\x86\x48\x86\xF7\x0D\x02\x09"
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, HMAC_SHA1_OID, strlen( HMAC_SHA1_OID), 0 ) );
    //MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, HMAC_SHA256_OID, strlen( HMAC_SHA256_OID), 0 ) );

    /* iterationCount      INTEGER, */
    /* TODO: PROBLEM: mbedtls_asn1_write_int does only support up to 128... */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, pbmp->iterationCount ) );

    /* owf                 AlgorithmIdentifier, */
    if( ( ret = mbedtls_oid_get_oid_by_md( pbmp->owf, &sig_oid, &sig_oid_len ) ) != 0 )
        return( ret );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, sig_oid, strlen( sig_oid ), 0 ) );

    /* salt                OCTET STRING, */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, pbmp->salt, pbmp->salt_len ) );
    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );

    /* PBMParameter ::= SEQUENCE { */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    return len;
}


/* **************************************************************** */

int cmpcl_CMPwrite_PKIHeader_der( unsigned char **p, unsigned char *start,
                                  cmp_ctx *ctx)
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    size_t len = 0;
    size_t sub_len = 0;

    /*
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue     OPTIONAL
     */

    if (ctx->implicitConfirm )
    {
        sub_len = 0;
/* TODO: HARDCODED - that's not in mbedtls/include/mbedtls/oid.h */
#define IMPLICITCONFIRM_OID "\x2b\x06\x01\x05\x05\x07\x04\x0d"
        size_t par_len = 0;
        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_null( p, start ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_algorithm_identifier(
                    p, start, IMPLICITCONFIRM_OID,
                    strlen( IMPLICITCONFIRM_OID ), par_len ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 8 ) );
        len += sub_len;
    }
    /*
         freeText        [7] PKIFreeText             OPTIONAL,
         PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */

    /*
         recipNonce      [6] OCTET STRING            OPTIONAL,
     */
    if (ctx->recipNonce )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->recipNonce, ctx->recipNonce_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 6 ) );
    }
    /*
         senderNonce     [5] OCTET STRING            OPTIONAL,
     */
    if (ctx->senderNonce )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->senderNonce, ctx->senderNonce_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 5 ) );
    }

    /*
         transactionID   [4] OCTET STRING            OPTIONAL,
     */
    if (ctx->transactionID )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->transactionID, ctx->transactionID_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 4 ) );
    }
    /*
         recipKID        [3] KeyIdentifier           OPTIONAL,
     */

    /*
         senderKID       [2] KeyIdentifier           OPTIONAL,
     */
/* doesn't work as I don't find the key identifier from extensions :-/ */
#if 0
    if (ctx->clCert)
    {
      sub_len = 0;
     // MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER
      getExtension( &ctx->clCert->v3_ext);
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2 ) );
    }
#endif
    if (ctx->reference )
    {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, ctx->reference, ctx->reference_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2 ) );
    }

    /*
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
     */
    if (ctx->secret && ctx->reference && ctx->pbmp) {
        /* PBM */
        /*
      id-PasswordBasedMAC OBJECT IDENTIFIER ::= { 1 2 840 113533 7 66 13} */
        size_t par_len = 0;
        MBEDTLS_ASN1_CHK_ADD( par_len, cmpcl_CMPwrite_PBMParameter_der( p, start, ctx->pbmp) );

        sub_len = 0;
/* TODO: HARDCODED - that's not in mbedtls/include/mbedtls/oid.h */
#define PBM_OID "\x2a\x86\x48\x86\xf6\x7d\x07\x42\x0d"
        MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_algorithm_identifier( p, start, PBM_OID, strlen( PBM_OID ), par_len ) );
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    } else if (ctx->prot_key && ctx->md_alg) {/* TODO: is it best to distinguish like this? */
      mbedtls_pk_type_t pk_alg;
      pk_alg = mbedtls_pk_get_type( ctx->prot_key);
      if( pk_alg == MBEDTLS_PK_ECKEY )
          pk_alg = MBEDTLS_PK_ECDSA;

      if( ( ret = mbedtls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg, &sig_oid, &sig_oid_len ) ) != 0 )
          return( ret );

      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_algorithm_identifier( p, start, sig_oid, strlen( sig_oid ), 0 ) );
      len += sub_len;
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
    } else {
        printf( "WARN: no protection\n");
    }

    /*
         messageTime     [0] GeneralizedTime         OPTIONAL,
     */
    if (ctx->messageTime) {
      sub_len = 0;
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_raw_buffer( p, start, (const unsigned char *) ctx->messageTime, MBEDTLS_X509_RFC5280_UTC_TIME_LEN ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_GENERALIZED_TIME ) );
      len += sub_len;
      /* [0] */
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
      MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );
    }

    /*
         recipient           GeneralName,
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_x509_write_names( p, start, ctx->recipient ) );
    len += sub_len;
    /* Explicit */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_OCTET_STRING ) );

    /*
         sender              GeneralName,
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD( sub_len, mbedtls_x509_write_names( p, start, ctx->sender ) );
    len += sub_len;
    /* Explicit */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, sub_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_OCTET_STRING ) );

    /*
     *   pvno                INTEGER     { cmp1999(1), cmp2000(2) },
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( p, start, MBEDTLS_CMP_VERSION_2 ) );

    /*
     * PKIHeader ::= SEQUENCE
     */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    return( (int) len );
}

