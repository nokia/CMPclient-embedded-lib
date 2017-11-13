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


#if !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && \
    !defined(MBEDTLS_ENTROPY_NV_SEED) && !defined(MBEDTLS_TEST_NULL_ENTROPY)
#error "This hardware does not have an entropy source."
#endif /* !MBEDTLS_ENTROPY_HARDWARE_ALT && !MBEDTLS_ENTROPY_NV_SEED &&
        * !MBEDTLS_TEST_NULL_ENTROPY */

#define MBEDTLS_SHA1_C

/* Needed for writing X.509 certificates */
#define MBEDTLS_X509_CREATE_C

/*
 * There are some ways to tweak mbed TLS described here
 * https://tls.mbed.org/kb/how-to/increasing_ssl_performance_and_tls_performance
 */
#define MBEDTLS_MPI_MAX_SIZE        256

#define MBEDTLS_MPI_WINDOW_SIZE     1


/* https://tls.mbed.org/kb/how-to/how-do-i-tune-elliptic-curves-resource-usage */
/* https://tls.mbed.org/kb/how-to/reduce-mbedtls-memory-and-storage-footprint */

#define MBEDTLS_ECP_WINDOW_SIZE 2
//#define MBEDTLS_ECP_MAX_BITS 256 /* that strangely leads to errors computing the message protection with secp256r1 */
