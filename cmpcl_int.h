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

#ifndef CMPCL_INT_H
#define CMPCL_INT_H
#ifdef __cplusplus
extern "C" {
#endif

#include "cmpcl.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"


/* **************************************************************** */
/* PasswordBasedMac PBM */
/* **************************************************************** */
/**
 * \brief          calculate PBM
 *
 * \param pbmp      initialized PBMParameter
 * \param msg
 * \param msg_len
 * \param secret
 * \param secret_len
 * \param mac
 * \param mac_len
 */
int cmp_PBM_new( const cmp_PBMParameter *pbmp,
        const unsigned char *secret, size_t secret_len,
        const unsigned char *msg, size_t msg_len,
        unsigned char *mac, size_t *mac_len);

/* **************************************************************** */
/* CRMF */
/* **************************************************************** */

/*
 * Container for writing a CertReqMsg

CertReqMsg ::= SEQUENCE {
 certReq   CertRequest,
 popo       ProofOfPossession  OPTIONAL,
 -- content depends upon key type
 regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }

CertRequest ::= SEQUENCE {
 certReqId     INTEGER,          -- ID for matching request and reply
 certTemplate  CertTemplate,  -- Selected fields of cert to be issued
 controls      Controls OPTIONAL }   -- Attributes affecting issuance

CertTemplate ::= SEQUENCE {
 version      [0] Version               OPTIONAL,
 serialNumber [1] INTEGER               OPTIONAL,
 signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 issuer       [3] Name                  OPTIONAL,
 validity     [4] OptionalValidity      OPTIONAL,
 subject      [5] Name                  OPTIONAL,
 publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
 issuerUID    [7] UniqueIdentifier      OPTIONAL,
 subjectUID   [8] UniqueIdentifier      OPTIONAL,
 extensions   [9] Extensions            OPTIONAL }

ProofOfPossession ::= CHOICE {
 raVerified        [0] NULL,
 -- used if the RA has already verified that the requester is in
 -- possession of the private key
 signature         [1] POPOSigningKey,
 keyEncipherment   [2] POPOPrivKey,
 keyAgreement      [3] POPOPrivKey }
*/

/**
 * \brief           Write a built up CertReqMsg to a DER structure
 */
int cmpcl_CRMFwrite_CertReqMsg_der( unsigned char **p,unsigned char *start,
                                      cmp_ctx *ctx);

/**
 * \brief           Write a built up CertRequest to a DER structure
 */
int cmpcl_CRMFwrite_CertRequest_der( unsigned char **p, unsigned char *start,
                                       cmp_ctx *ctx);



/* **************************************************************** */
/* CMP */
/* **************************************************************** */

#define MBEDTLS_CMP_VERSION_1             1
#define MBEDTLS_CMP_VERSION_2             2


/* PKIBODY TYPES */
#define MBEDTLS_CMP_PKIBODY_IR                0
#define MBEDTLS_CMP_PKIBODY_IP                1
#define MBEDTLS_CMP_PKIBODY_CR                2
#define MBEDTLS_CMP_PKIBODY_CP                3
#define MBEDTLS_CMP_PKIBODY_P10CR             4
#define MBEDTLS_CMP_PKIBODY_POPDECC           5
#define MBEDTLS_CMP_PKIBODY_POPDECR           6
#define MBEDTLS_CMP_PKIBODY_KUR               7
#define MBEDTLS_CMP_PKIBODY_KUP               8
#define MBEDTLS_CMP_PKIBODY_KRR               9
#define MBEDTLS_CMP_PKIBODY_KRP              10
#define MBEDTLS_CMP_PKIBODY_RR               11
#define MBEDTLS_CMP_PKIBODY_RP               12
#define MBEDTLS_CMP_PKIBODY_CCR              13
#define MBEDTLS_CMP_PKIBODY_CCP              14
#define MBEDTLS_CMP_PKIBODY_CKUANN           15
#define MBEDTLS_CMP_PKIBODY_CANN             16
#define MBEDTLS_CMP_PKIBODY_RANN             17
#define MBEDTLS_CMP_PKIBODY_CRLANN           18
#define MBEDTLS_CMP_PKIBODY_PKICONF          19
#define MBEDTLS_CMP_PKIBODY_NESTED           20
#define MBEDTLS_CMP_PKIBODY_GENM             21
#define MBEDTLS_CMP_PKIBODY_GENP             22
#define MBEDTLS_CMP_PKIBODY_ERROR            23
#define MBEDTLS_CMP_PKIBODY_CERTCONF         24
#define MBEDTLS_CMP_PKIBODY_POLLREQ          25
#define MBEDTLS_CMP_PKIBODY_POLLREP          26


/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef mbedtls_asn1_buf cmp_buf;


/**
 * CMP PKIStatusInfo
 */
typedef struct cmp_PKIStatusInfo
{
    int PKIStatus;
    mbedtls_asn1_sequence *statusString; /* PKIFreetext = Sequence of UTF8String */
    mbedtls_asn1_bitstring PKIFailureInfo;
} cmp_PKIStatusInfo;

/**
 * CMP CertResponse
 */
typedef struct cmp_CertifiedKeyPair
{
    mbedtls_x509_crt *cert;
    cmp_buf cert_d;          /**< The raw CSR data (DER). */
    /* TODOenccert? */
} cmp_CertifiedKeyPair;


/**
 * CMP ErrorMsgContent
 */
typedef struct cmp_ErrorMsgContent
{
    cmp_PKIStatusInfo pKIStatusInfo;
    int *errorCode; /* OPTIONAL */
    mbedtls_asn1_sequence *errorDetails; /* OPTIONAL PKIFreetext */
} cmp_ErrorMsgContent;

/**
 * CMP CertResponse
 */
typedef struct cmp_CertResponse
{
    int certReqId;
    cmp_PKIStatusInfo status;
    cmp_CertifiedKeyPair *certifiedKeyPair;
} cmp_CertResponse;

/**
 * CMP certRepmessage
 */
typedef struct cmp_CertRepMessage
{
    cmp_CertResponse *response; /* TODO how to best handle more than one? */
}
cmp_CertRepMessage;

/**
 * CMP PKIMessage structure
 */
typedef struct cmp_pkimessage
{
    cmp_buf raw;           /**< The raw CSR data (DER). */

    cmp_buf body;          /**< The raw CSR data (DER). */
    cmp_buf header;          /**< The raw CSR data (DER). */
    cmp_CertRepMessage *crep; /* The CertRepMessage in case of IP/CP/KUP */
    cmp_ErrorMsgContent *error; /* An Error */

    cmp_buf protection;    /**< The raw CSR data (DER). */
    cmp_buf extraCerts;    /**< The raw CSR data (DER). */

    cmp_buf   sender_raw;  /**< The raw sender data (DER). */
    mbedtls_x509_name sender;      /**< The parsed sender data (named information object). */

    cmp_buf   recipient_raw;  /**< The raw recipient data (DER). */
    mbedtls_x509_name recipient;      /**< The parsed recipient data (named information object). */

#if 0
    mbedtls_x509_buf sig_oid;
    mbedtls_x509_buf sig;
    mbedtls_md_type_t sig_md;       /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t sig_pk;       /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
#endif
}
cmp_pkimessage;

/* TODO describe */
void cmp_CertifiedKeyPair_free( cmp_CertifiedKeyPair *certifiedKeyPair);
void cmp_CertResponse_free( cmp_CertResponse *response);
void cmp_CertRepMessage_free( cmp_CertRepMessage *crep);

int cmp_pkimessage_parse_der( cmp_pkimessage *cmp,
                              unsigned char *buf, size_t buflen );
void cmp_pkimessage_init( cmp_pkimessage *cmp );
void cmp_pkimessage_free( cmp_pkimessage *csr );


/**
 * \brief           Write a built up PKIMessage to a DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 */
int cmpcl_CMPwrite_PKIMessage_der( cmp_ctx *ctx, unsigned char *buf,
                                   size_t size, unsigned char **myp);
                                   /* TODO that random stuff for ECDSA... */

/**
 * \brief           Write a message protection for a given range
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 */
int cmpcl_CMPwrite_PKIMessage_protection_der( unsigned char **p,
                                              unsigned char *start,
                                              cmp_ctx *ctx,
                                              const unsigned char* input,
                                              const size_t in_len);
                                              /* TODO that random stuff for ECDSA... */

/**
 * \brief           Write a built up PKIHeader to a DER structure
 */
int cmpcl_CMPwrite_PKIHeader_der( unsigned char **p,
                                  unsigned char *start,
                                  cmp_ctx *ctx);

int setStr( unsigned char **dst, const unsigned char *src, const size_t len);

#ifdef __cplusplus
}
#endif

#endif /* cmpcl_int.h */
