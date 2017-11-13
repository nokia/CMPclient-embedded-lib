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

/* for socket */
#include <unistd.h>
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

/* TODO: check needs to be done for entropy... */
//#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h> /* Random generator */



#define OUTPUT_BUF_SIZE 2048

int cmpcl_ir(cmp_ctx *ctx) {
    int outcome = 0;
    unsigned char *output_buf;
    unsigned char *output_start = NULL;
    int len;
    char *input = NULL;
    size_t inputlen;
    cmp_pkimessage *cmp;

    output_buf = mbedtls_calloc(1, OUTPUT_BUF_SIZE);

    cmp_ctx_set_next_body( ctx, MBEDTLS_CMP_PKIBODY_IR);

    len = cmpcl_CMPwrite_PKIMessage_der( ctx,
                                         output_buf,
                                         OUTPUT_BUF_SIZE,
                                         &output_start);  /* TODO that random stuff for ECDSA... */

    if (len < 0) {
        CMPERRV("cmpcl_CMPwrite_PKIMessage der returned %d", len);
        return -1;
    }
    ctx->send_receive_cb( ctx->shost, ctx->sport, ctx->spath,
                          (char *)output_start, (size_t) len,
                          &input, &inputlen);

    cmp = calloc(1, sizeof (cmp_pkimessage));
    if( !cmp)
        goto cleanup;
    cmp_pkimessage_parse_der( cmp, (unsigned char *)input, inputlen );

    CMPDBGV("Received Header Len %d", cmp->header.len);
    CMPDBGV("Received Body Len %d", cmp->body.len);

    if( cmp->crep
        && cmp->crep->response
        && cmp->crep->response->certifiedKeyPair
        && cmp->crep->response->certifiedKeyPair->cert
       ) {
        /* remember */
        ctx->new_cert = cmp->crep->response->certifiedKeyPair->cert;
        cmp->crep->response->certifiedKeyPair->cert = NULL; /* don't free */
        /*
        mbedtls_x509write_crt_pem( cmp.crep->response->certifiedKeyPair->cert,
                certbuf, 4000, NULL, NULL);
         */
        outcome = 1;
    } else {
        CMPDBGS("No Certificate received\n");
        outcome = -1;
    }
cleanup:
    if( cmp) {
        cmp_pkimessage_free( cmp );
        mbedtls_free( cmp);
    }

    if(output_buf) {
        mbedtls_free(output_buf);
    }
    return outcome;
}
