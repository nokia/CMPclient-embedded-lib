/*
 *  Copyright (c) 2016-2017, Nokia, All rights reserved.
 *
 *  This CMP client contains code derived from examples and documentation for
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

#ifndef CMPCL_H
#define CMPCL_H

#include "mbedtls/asn1.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* **************************************************************** */
/* PasswordBasedMac PBM */
/* **************************************************************** */
typedef struct cmp_PBMParameter
{
    unsigned char *salt;
    size_t salt_len;
    mbedtls_md_type_t owf;
    int iterationCount;
    mbedtls_md_type_t mac; /* TODO TODO TODO this is wrong as HMAC-SHA1 is not
    covered by this mbedtls_md_type_t */
}
cmp_PBMParameter;

/**
 * \brief          Initialize PBMParameter
 *
 * \param ctx      PBMParameter to initialize
 * \param pkibodytype      PKIBody type to set
 * \param clCert      client certificate used to protect the msg
 * \param clKey       client key used to protect the msg matching the cert
 */
void cmp_PBMParameter_init( cmp_PBMParameter *pbmp,
                                mbedtls_ctr_drbg_context *ctr_drbg,
                                size_t salt_len,
                                mbedtls_md_type_t owf,
                                int iterationCount,
                                mbedtls_md_type_t mac );

/**
 * \brief          Unallocate all PBMParameter data
 *
 * \param ctx      PBMParameter to free
 */
void cmp_PBMParameter_free( cmp_PBMParameter *pbmp );



/* **************************************************************** */
/* Transfer */
/* **************************************************************** */

typedef int (*cmp_send_receive_cb) (const char *shost,
                                    const int sport,
                                    const char *spath,
                                    const char *outbuf,
                                    const size_t len,
                                    char **inbuf, size_t *inlen);

#ifdef __MBED__
int send_receive( const char *shost, const int sport, const char *spath,
                  const char *outbuf, const size_t len,
                  char **inbuf, size_t *inlen);
#else
int send_receive( const unsigned char *shost, const int sport,
                  const unsigned char *spath, const unsigned char *outbuf,
                  const size_t len, unsigned char **inbuf, size_t *inlen);
#endif /* __MBED__ */

/* **************************************************************** */
/* Context */
/* **************************************************************** */

typedef struct cmp_ctx
{
    /* server */
    const char *shost;
    int sport;
    const char *spath;

    /* transfer */
    cmp_send_receive_cb send_receive_cb;

    /* header */

    mbedtls_x509_name   *sender;
    mbedtls_x509_name   *recipient;

    char *messageTime;

    mbedtls_md_type_t md_alg; /*  hashing algoritm */

    mbedtls_pk_context *prot_key;
    mbedtls_x509_crt *clCert;
    mbedtls_x509_crt *clCaCert;

    cmp_PBMParameter *pbmp;
    unsigned char *reference; /* shared secret */
    size_t reference_len;
    unsigned char *secret; /* shared secret */
    size_t secret_len;

    unsigned char *transactionID;
    size_t transactionID_len;

    unsigned char *senderNonce;
    size_t senderNonce_len;

    unsigned char *recipNonce;
    size_t recipNonce_len;

    int implicitConfirm;

    /* body */
    int certReqId;
    int next_body;
    /* old: int PKIBody_type; */

    mbedtls_pk_context *new_key;
    mbedtls_x509_name  *subject;

    int popo_method;
    mbedtls_md_type_t popo_md_alg;
    /* footer */
    // struct mbedtls_x509_crt *extraCerts;     /**< First certificate in the extraCertChain */ /* TODO: verify that that's the correct type */

    mbedtls_x509_crt *new_cert;

} cmp_ctx;

/**
 * \brief           Initialize a CMP context to default values
 *                  Must not be have content
 *
 * \param ctx       cmpctx context to free
 */
void cmp_ctx_init( cmp_ctx *ctx, mbedtls_ctr_drbg_context *ctr_drbg);

/**
 * \brief           Free the contents of a cmpctx write context
 *
 * \param ctx       cmpctx context to free
 */
void cmp_ctx_free( cmp_ctx *ctx );

/**
 * \brief           Set the MD algorithm used to protect the PKIMessage
 *
 * \param ctx       PKIHeader context
 * \param md_alg    MD algorithm to use
 */
void cmp_ctx_set_prot_md_alg( cmp_ctx *ctx, mbedtls_md_type_t md_alg );

/**
 * \brief           Set the key used to protect the PKIMessage
 *
 * \param ctx       PKIHeader context
 * \param key       key to use
 */
void cmp_ctx_set_prot_key( cmp_ctx *ctx, mbedtls_pk_context *key );

/**
 * \brief           Set the certificate used to protect the PKIMessage,
 *                  will be included in extraCerts
 *
 * \param ctx       CMP context
 * \param crt       certificate to use
 */
void cmp_ctx_set_cl_crt( cmp_ctx *ctx, mbedtls_x509_crt *crt);

/**
 * \brief           Set the chain of the certificate used to protect the
 *                  PKIMessage, will be included in extraCerts
 *
 * \param ctx       CMP context
 * \param crt       certificate (chain) to use
 */
void cmp_ctx_set_cl_crt_chain( cmp_ctx *ctx, mbedtls_x509_crt *crt);

/**
 * \brief           Set the secret to use for PBM
 *
 * \param ctx       CMP context
 * \param sec       secret, gets copied
 * \param len       length in bytes
 */
void cmp_ctx_set_pbm_secret( cmp_ctx *ctx, const unsigned char *sec,
                                           size_t len );

/**
 * \brief           Set the reference to use for PBM
 *
 * \param ctx       CMP context
 * \param ref       reference, gets copied
 * \param len       length in bytes
 */
void cmp_ctx_set_pbm_reference( cmp_ctx *ctx, const unsigned char *ref,
                                              size_t len );

/**
 * \brief           Set the messageTime
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CMP context to use
 * \param msgTime   messageTime timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_messageTime( cmp_ctx *ctx, const char *msgTime);

/**
 * \brief           Set the transactionID to be included
 *
 * \param ctx       CMP context
 * \param ctr_drbg  CTR DRBG context
 * \param len       length in bytes (typically 16 bytes)
 */
void cmp_ctx_set_transactionID( cmp_ctx *ctx,
                                mbedtls_ctr_drbg_context *ctr_drbg,
                                size_t len );

/**
 * \brief           Set the SenderNonce to be included
 *
 * \param ctx       CMP context
 * \param ctr_drbg  CTR DRBG context
 * \param len       length in bytes (typically 16 bytes)
 */
void cmp_ctx_set_senderNonce( cmp_ctx *ctx,
                              mbedtls_ctr_drbg_context *ctr_drbg,
                              size_t len );

/**
 * \brief           Set the recipNonce to be included
 *
 * \param ctx       PKIHeader context
 * \param nonce     recip nonce
 * \param len       length in bytes (typically 16 bytes)
 */
void cmp_ctx_set_recipNonce( cmp_ctx *ctx, unsigned char *nonce, size_t len );

/**
 * \brief           Set the sender name for a PKIMessage
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=IoT Device 1"
 *
 * \param ctx           CMP context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_sender_name( cmp_ctx *ctx, const char *sender_name );

/**
 * \brief           Set the recipient name for a PKIMessage
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=CMP Server 1"
 *
 * \param ctx           CMP context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_recipient_name( cmp_ctx *ctx, const char *recipient_name );

/**
 * \brief           Set the subject name for the requested certificate
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=FI,O=Nokia,CN=CMP EE"
 *
 * \param ctx           CMP context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int cmp_ctx_set_subject_name( cmp_ctx *ctx, const char *subject_name );
/**
 * \brief           Set the key to create a CertReqMsg for
 *
 * \param ctx       PKIHeader context
 * \param key       key to use
 */
void cmp_ctx_set_new_key( cmp_ctx *ctx, mbedtls_pk_context *new_key );

/**
 * \brief           Set the POPO Method to use
 *
 * \param ctx       PKIHeader context
 * \param popo_method popo_method to use
 */
void cmp_ctx_set_popo_method( cmp_ctx *ctx, int popo_method );
#define CMP_CTX_POPO_RAVERIFIED       0
#define CMP_CTX_POPO_SIGNATURE        1
#define CMP_CTX_POPO_KEYENCIPHERMENT  2
#define CMP_CTX_POPO_KEYAGREEMENT     3

/**
 * \brief           Set the hash algorith for POPO
 *
 * \param ctx       PKIHeader context
 * \param popo_method popo_method to use
 */
void cmp_ctx_set_popo_md_alg( cmp_ctx *ctx, mbedtls_md_type_t md_alg );

/**
 * \brief           Set the PBM parameter
 *                  Consumes the pointer
 *
 * \param ctx       PKIHeader context
 * \param pbmp      PBM Parameter to use
 */
void cmp_ctx_set_pbmp( cmp_ctx *ctx, cmp_PBMParameter *pbmp);

/**
 * \brief           Set the next bodytype to send (e.g. IR)
 *
 * \param ctx       CMP context
 * \param next_body bodytype to use for next written msg
 */
void cmp_ctx_set_next_body( cmp_ctx *ctx, int next_body);

/**
 * \brief           Set whether to use implicitConfirm
 *
 * \param ctx       CMP context
 * \param ic        0=false, 1=true
 */
void cmp_ctx_set_implicit_confirm( cmp_ctx *ctx, int ic);

/**
 * \brief           Set the hostname of the CMP server
 *
 * \param ctx       CMP context
 * \param shost     hostname, pointer does not get consumed
 */
void cmp_ctx_set_server_host( cmp_ctx *ctx, const char *shost);

/* **************************************************************** */
/* CMP transactions */
/* **************************************************************** */

int cmpcl_ir( cmp_ctx *ctx);


/* helpers */
void cmp_ctx_set_rndm_str( unsigned char **str, size_t *str_len,
                          mbedtls_ctr_drbg_context *ctr_drbg, size_t len );

/* Macros for Development */
#ifdef __MBED__
#define NEWLINE "\r\n"
#define SIZEFMT "%d"
#else
#define NEWLINE "\r\n"
#define SIZEFMT "%lu"
#endif
#define CMPDBG \
  do { \
    printf("DEBUG: %s:%d %s" NEWLINE,__FILE__,__LINE__, __func__); \
  } while(0);
#define CMPDBGS(str) \
  do { \
    printf("DEBUG: %s:%d %s " str NEWLINE,__FILE__,__LINE__, __func__); \
  } while(0);
#define CMPDBGV(fmt, ...) \
  do { \
    printf("DEBUG: %s:%d %s " fmt NEWLINE,__FILE__,__LINE__, __func__, \
           ##__VA_ARGS__); \
  } while(0);
#define CMPERRS(str) \
  do { \
    printf("ERROR: %s:%d %s " str NEWLINE,__FILE__,__LINE__, __func__); \
  } while(0);
#define CMPERRV(fmt, ...) \
  do { \
    printf("ERROR: %s:%d %s " fmt NEWLINE,__FILE__,__LINE__, __func__, \
           ##__VA_ARGS__); \
  } while(0);
#define CMPHEX(p) \
  do { \
    printf("DEBUG: first 5 byte are = %#1x %#1x %#1x %#1x %#1x" NEWLINE, \
            (unsigned)(unsigned char)p[0], (unsigned)(unsigned char)p[1], \
            (unsigned)(unsigned char)p[2], (unsigned)(unsigned char)p[3], \
            (unsigned)(unsigned char)p[4]); \
  } while(0);

#ifdef __cplusplus
}
#endif

#endif /* cmpcl.h */
