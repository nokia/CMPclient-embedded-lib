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

/* #if defined(MBEDTLS_CMP_PARSE_C) */

#include "cmpcl_int.h"
#include "mbedtls/oid.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

/* Implementation that should never be optimized out by the compiler */
static void zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Parse CMP PKIHeader in DER format
 */
static int cmp_parse_der( cmp_pkimessage *cmp,
                        unsigned char *p, unsigned char *end )
{
    int ret;
    size_t len;

    /*
     *   pvno                INTEGER     { cmp1999(1), cmp2000(2) },
     */
    int pvno;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &pvno ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );
    }

    /*
     *   sender              GeneralName,
     *   -- identifies the sender
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    cmp->sender_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = mbedtls_x509_get_name( &p, p + len, &cmp->sender ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( ret );
    }

    cmp->sender_raw.len = p - cmp->sender_raw.p;

    /*
     *   recipient           GeneralName,
     *   -- identifies the intended recipient
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    cmp->recipient_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = mbedtls_x509_get_name( &p, p + len, &cmp->recipient ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( ret );
    }

    cmp->recipient_raw.len = p - cmp->recipient_raw.p;

/*
         messageTime     [0] GeneralizedTime         OPTIONAL,
         -- time of production of this message (used when sender
         -- believes that the transport will be "suitable"; i.e.,
         -- that the time will still be meaningful upon receipt)
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         -- algorithm used for calculation of protection bits
         senderKID       [2] KeyIdentifier           OPTIONAL,
         recipKID        [3] KeyIdentifier           OPTIONAL,
         -- to identify specific keys used for protection
         transactionID   [4] OCTET STRING            OPTIONAL,
         -- identifies the transaction; i.e., this will be the same in
         -- corresponding request, response, certConf, and PKIConf
         -- messages
         senderNonce     [5] OCTET STRING            OPTIONAL,
         recipNonce      [6] OCTET STRING            OPTIONAL,
         -- nonces used to provide replay protection, senderNonce
         -- is inserted by the creator of this message; recipNonce
         -- is a nonce previously inserted in a related message by
         -- the intended recipient of this message
         freeText        [7] PKIFreeText             OPTIONAL,
         -- this may be used to indicate context-specific instructions
         -- (this field is intended for human consumption)
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                InfoTypeAndValue     OPTIONAL
         -- this may be used to convey context-specific information
         -- (this field not primarily intended for human consumption)
     }
     */

    /*
    TODO: check whether implicitConfirm was granted

         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                InfoTypeAndValue     OPTIONAL
         -- this may be used to convey context-specific information
         -- (this field not primarily intended for human consumption)
     */
    return 0;
}


/*
 * Parse CMP PKIStatusInfo in DER format
 */
static int cmp_pkibody_PKIStatusInfo_parse_der( cmp_PKIStatusInfo *sinfo,
                        unsigned char *p, unsigned char *end )
{
    int ret;
    size_t len;

    /*
     PKIStatusInfo ::= SEQUENCE {
         status        PKIStatus,
         statusString  PKIFreeText     OPTIONAL,
         failInfo      PKIFailureInfo  OPTIONAL
     }
     */

    /*
         status        PKIStatus,

     PKIStatus ::= INTEGER {
         accepted                (0),
         -- you got exactly what you asked for
         grantedWithMods        (1),
         -- you got something like what you asked for; the
         -- requester is responsible for ascertaining the differences
         rejection              (2),
         -- you don't get it, more information elsewhere in the message
         waiting                (3),
         -- the request body part has not yet been processed; expect to
         -- hear more later (note: proper handling of this status
         -- response MAY use the polling req/rep PKIMessages specified
         -- in Section 5.3.22; alternatively, polling in the underlying
         -- transport layer MAY have some utility in this regard)
         revocationWarning      (4),
         -- this message contains a warning that a revocation is
         -- imminent
         revocationNotification (5),
         -- notification that a revocation has occurred
         keyUpdateWarning       (6)
         -- update already done for the oldCertId specified in
         -- CertReqMsg
     }
     */

    /* not accepted ? */
    if( ( ret = mbedtls_asn1_get_int( &p, end, &sinfo->PKIStatus ) ) != 0 )
        return( ret ); /* TODO: improve */

    if( p == end )
        return( 0 );

    /*
         statusString  PKIFreeText     OPTIONAL,
            PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
     */
    unsigned char *tmpp = p;
    if( ( ret = mbedtls_asn1_get_tag( &tmpp, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) == 0 )
    {
        len += tmpp-p;
        sinfo->statusString = (mbedtls_asn1_sequence *) mbedtls_calloc(1,
                                                 sizeof(mbedtls_asn1_sequence));
        if ( ( ret = mbedtls_asn1_get_sequence_of( &p, p+len,
                        sinfo->statusString,
                        MBEDTLS_ASN1_UTF8_STRING)))
            return( ret ); /* TODO: improve */
        /* TODO: that length thing doesn't really work */
        CMPDBGV("Error Msg with first statusSTring: %*s",
                (int) sinfo->statusString->buf.len,
                sinfo->statusString->buf.p);
    }

    if( p == end )
        return( 0 );

    /*
         failInfo      PKIFailureInfo  OPTIONAL
         PKIFailureInfo ::= BIT STRING
     */
    if( ( ret = mbedtls_asn1_get_bitstring( &p, end, &sinfo->PKIFailureInfo ) ) == 0 )
    {
        /* TODO so far not analyzed */
        CMPDBGV("PKIFailureInfo %#1x %#1x %#1x %#1x",
                (unsigned char)sinfo->PKIFailureInfo.p[0],
                (unsigned char)sinfo->PKIFailureInfo.p[1],
                (unsigned char)sinfo->PKIFailureInfo.p[2],
                (unsigned char)sinfo->PKIFailureInfo.p[3]);
    } else {
        return( ret ); /* TODO: improve */
    }

    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    return 0;
}

/*
 * Parse CMP CertifiedKeyPair in DER format
 */
static int cmp_pkibody_CertifiedKeyPair_parse_der(
                                        cmp_CertifiedKeyPair *ckp,
                                        unsigned char *p, unsigned char *end )
{
    int ret;
    size_t len;

    /*
     CertifiedKeyPair ::= SEQUENCE {
         certOrEncCert       CertOrEncCert,
         privateKey      [0] EncryptedValue      OPTIONAL,
         -- see [CRMF] for comment on encoding
         publicationInfo [1] PKIPublicationInfo  OPTIONAL
     }
     */
    /*
     CertOrEncCert ::= CHOICE {
         certificate     [0] CMPCertificate,
         encryptedCert   [1] EncryptedValue
     }
     */

    int certChoice = *p ^ MBEDTLS_ASN1_CONTEXT_SPECIFIC ^ MBEDTLS_ASN1_CONSTRUCTED;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | certChoice ) ) != 0 )
    {
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret ); /* TODO */
    }

    switch( certChoice ) {
    case 0:
        ckp->cert_d.p = p;
        ckp->cert = mbedtls_calloc(1, sizeof(struct mbedtls_x509_crt));
        if ((ret = mbedtls_x509_crt_parse_der( ckp->cert, p, len)))
        {
    /* TODO: free ckp->cert */
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret ); /* TODO */
        }
        p += len;
    /*
         certificate     [0] CMPCertificate,
     */
        break;
    case 1:
    /*
TODO         encryptedCert   [1] EncryptedValue
     */
        break;
    default:
        printf("Error, unsupported CertOrEncCert choice %d\n", certChoice);
        ret = -1; /* TODO - better value */
        break;
    }

    /*
TODO         privateKey      [0] EncryptedValue      OPTIONAL,
     */

    /*
TODO         publicationInfo [1] PKIPublicationInfo  OPTIONAL
     */


    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    return 0;
}


/*
 * Parse CMP CertResponse in DER format
 */
static int cmp_pkibody_certrep_parse_der( cmp_CertResponse *response,
                        unsigned char *p, unsigned char *end )
{
    int ret;
    size_t len;

    /*
     CertResponse ::= SEQUENCE {
         certReqId           INTEGER,
         status              PKIStatusInfo,
         certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
         rspInfo             OCTET STRING        OPTIONAL
         -- analogous to the id-regInfo-utf8Pairs string defined
         -- for regInfo in CertReqMsg [CRMF]
     }
     */
    /*
     CertResponse ::= SEQUENCE {
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    /*
         certReqId           INTEGER,
     */
    if( ( ret = mbedtls_asn1_get_int( &p, end, &response->certReqId ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret ); /* TODO: improve */

    /*
       status              PKIStatusInfo,
     */

    /*
     PKIStatusInfo ::= SEQUENCE
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    if ( ( ret = cmp_pkibody_PKIStatusInfo_parse_der( &response->status, p, p+len)) != 0)
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret ); /* TODO: improve */
    p += len;

    /* optional elements? */
    if (p == end)
        return 0; /* TODO: improve logic */
        /*
           certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
         */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    response->certifiedKeyPair = mbedtls_calloc(1, sizeof(struct cmp_CertifiedKeyPair));
    if ( ( ret = cmp_pkibody_CertifiedKeyPair_parse_der( response->certifiedKeyPair, p, p+len)) != 0)
        /* TODO: Free the allocated memory? */
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret ); /* TODO: improve */
    p += len;



        /*
TODO           rspInfo             OCTET STRING        OPTIONAL
         */

    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    return 0;
}

/*
 * Parse CMP CertRepMessage in DER format
 */
static int cmp_pkibody_crepmsg_parse_der( cmp_CertRepMessage *crep,
                        unsigned char *p, unsigned char *end )
{
    int ret;
    size_t len;

    /*
     CertRepMessage ::= SEQUENCE {
         caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL,
         response         SEQUENCE OF CertResponse
     }
     */

    /*
     *     caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL,
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
    {
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_FORMAT );
        /* caPubs seen = len */
        /* TODO copy the certs (pointer?) */
        /* until then */ p += len;
    }

    /*      response         SEQUENCE OF CertResponse */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    /* TODO: needs to be chained for multiple... */
    /* TODO TODO: that only gets one and fails then... */
    crep->response = mbedtls_calloc(1, sizeof(struct cmp_CertResponse));
    if( (ret = cmp_pkibody_certrep_parse_der( crep->response, p, p+len )) != 0)
        return -1; /* TODO: improve error handling */
    p += len;


    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    return 0;
}


/*
 * Parse CMP Error Message Content in DER format
 */
static int cmp_pkibody_errmsgcnt_parse_der( cmp_ErrorMsgContent *emc,
                        unsigned char *p, unsigned char *end )
{
    int ret;
    size_t len;

    /*
       ErrorMsgContent ::= SEQUENCE {
       pKIStatusInfo          PKIStatusInfo,
       errorCode              INTEGER           OPTIONAL,
       -- implementation-specific error codes
       errorDetails           PKIFreeText       OPTIONAL
       -- implementation-specific error details
       }
     */
    /*
       PKIStatusInfo ::= SEQUENCE
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    if ((ret = cmp_pkibody_PKIStatusInfo_parse_der( &emc->pKIStatusInfo, p, p+len)))
        return(ret); /* TODO improve */


    if( p != end )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    return 0;
}

/*
 * Parse CMP PKIMessage in DER format
 */
int cmp_pkimessage_parse_der( cmp_pkimessage *cmp,
                                  unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;

    /*
     * Check for valid input
     */
    if( cmp == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    cmp_pkimessage_init( cmp );

    p = buf;
    end = p + buflen;

    /*
     * consume the raw DER data
     */
    cmp->raw.p = buf;
    cmp->raw.len = buflen;

    /*
     * PKIMessage ::= SEQUENCE {
     *    header           PKIHeader,
     *    body             PKIBody,
     *    protection   [0] PKIProtection OPTIONAL,
     *    extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                     OPTIONAL
     * }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     * PKIHeader ::= SEQUENCE {
     */
    cmp->header.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( (ret = cmp_parse_der( cmp, p, p+len )) != 0)
        return ret;

    cmp->header.len = p + len - cmp->header.p;
    p += len;

    /*
     * PKIBody ::= CHOICE {       -- message-specific body elements
     */
    cmp->body.p = p;

    int bodytype = *p ^ MBEDTLS_ASN1_CONTEXT_SPECIFIC ^ MBEDTLS_ASN1_CONSTRUCTED;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | bodytype ) ) != 0 )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    switch( bodytype ) {
    case MBEDTLS_CMP_PKIBODY_IP:
    case MBEDTLS_CMP_PKIBODY_CP:
    case MBEDTLS_CMP_PKIBODY_KUP:
        /* Within the bodytype, there's always an extra TL block */
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_FORMAT );
        cmp->crep = mbedtls_calloc(1, sizeof(struct cmp_CertRepMessage)); /* TODO: catch error */
        ret = cmp_pkibody_crepmsg_parse_der( cmp->crep, p, p+len );
        break;
    case MBEDTLS_CMP_PKIBODY_ERROR:
    /* TODO: make it get an error message */
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_FORMAT );
        cmp->error = mbedtls_calloc( 1, sizeof (cmp_ErrorMsgContent));
        ret = cmp_pkibody_errmsgcnt_parse_der( cmp->error, p, p+len );
        break;
    default:
CMPDBGV("Error, unsupported bodytype %d", bodytype)

        ret = -1; /* TODO - better value */
        break;
    }

    if( ret != 0) {
        cmp_pkimessage_free( cmp );
        return( ret );
    }

    cmp->body.len = p + len - cmp->body.p;
    p += len;

    /*
     *    protection   [0] PKIProtection OPTIONAL,
     */

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) == 0 )
    {
        /* TODO: is it needed to remember this? */
        cmp->protection.p = p;
        cmp->protection.len = len;

        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_BIT_STRING ) ) != 0 )
        {
            cmp_pkimessage_free( cmp );
            return( MBEDTLS_ERR_X509_INVALID_FORMAT );
        }
        /* Protection len */
        /* TODO copy the bit string (pointer?) for message protection verification */
        /* TODO remember the padding ? */
        /* until then */ p += len;
    }

    /*
     *    extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                     OPTIONAL
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
    {
        /* TODO: is it needed to remember this? */
        cmp->extraCerts.p = p;
        cmp->extraCerts.len = len;

        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        {
            cmp_pkimessage_free( cmp );
            return( MBEDTLS_ERR_X509_INVALID_FORMAT );
        }
        /* Extracerts len */
        /* TODO copy the extra Certs (pointer?) */
        /* until then */ p += len;
    }

#if 0

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = mbedtls_pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     *
     *  The list of possible attributes is open-ended, though RFC 2985
     *  (PKCS#9) defines a few in section 5.4. We currently don't support any,
     *  so we just ignore them. This is a safe thing to do as the worst thing
     *  that could happen is that we issue a certificate that does not match
     *  the requester's expectations - this cannot cause a violation of our
     *  signature policies.
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    p += len;

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = mbedtls_x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = mbedtls_x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

#endif
    if( p != end )
    {
        cmp_pkimessage_free( cmp );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

void cmp_CertifiedKeyPair_free(cmp_CertifiedKeyPair *certifiedKeyPair) {
    if( certifiedKeyPair == NULL)
        return;
    if( certifiedKeyPair->cert ) {
        mbedtls_x509_crt_free( certifiedKeyPair->cert);
        mbedtls_free( certifiedKeyPair->cert);
        certifiedKeyPair->cert = NULL;
    }

    zeroize( certifiedKeyPair, sizeof( cmp_CertifiedKeyPair ) );
}

void cmp_CertResponse_free(cmp_CertResponse *response) {
    if( response == NULL)
        return;
    if( response->certifiedKeyPair) {
        cmp_CertifiedKeyPair_free(response->certifiedKeyPair);
        mbedtls_free( response->certifiedKeyPair);
        response->certifiedKeyPair = NULL;
    }
    zeroize( response, sizeof( cmp_CertResponse ) );
}


void cmp_CertRepMessage_free(cmp_CertRepMessage *crep) {
    if( crep == NULL)
        return;
    if( crep->response) {
        cmp_CertResponse_free(crep->response);
        mbedtls_free(crep->response);
        crep->response = NULL;
    }
    zeroize( crep, sizeof( cmp_CertRepMessage ) );
}


/*
 * Initialize a CMP PKIMessage
 */
void cmp_pkimessage_init( cmp_pkimessage *cmp )
{
    memset( cmp, 0, sizeof(cmp_pkimessage) );
}

/*
 * Unallocate all CMP data
 */
void cmp_pkimessage_free( cmp_pkimessage *cmp )
{
    mbedtls_x509_name *name_cur = NULL;
    mbedtls_x509_name *name_prv = NULL;

    if( cmp == NULL)
        return;
    if( cmp->crep) {
        cmp_CertRepMessage_free(cmp->crep);
        mbedtls_free(cmp->crep);
        cmp->crep = NULL;
    }
    name_cur = cmp->sender.next;
    while( name_cur != NULL ) {
        name_prv = name_cur;
        name_cur = name_cur->next;
        zeroize( name_prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( name_prv );
    }

    name_cur = cmp->recipient.next;
    while( name_cur != NULL ) {
        name_prv = name_cur;
        name_cur = name_cur->next;
        zeroize( name_prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( name_prv );
    }

    zeroize( cmp->raw.p, cmp->raw.len );
    mbedtls_free( cmp->raw.p);


    zeroize( cmp, sizeof( cmp_pkimessage ) );
}

/* #endif */ /* MBEDTLS_CMP_PARSE_C */
