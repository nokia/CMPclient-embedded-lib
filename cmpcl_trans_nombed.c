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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#define mbedtls_snprintf   snprintf
#endif
/* TODO: validates what needs to be done for entropy... */
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h> /* Random generator */


/* for writes the given array to the given file */
#define DER_OUTPUT_REQ "req.der"
#define DER_OUTPUT_REP "rep.der"
static int write_to_file(const char* ofile, unsigned char* output,
                         const size_t len) __attribute__((unused));

/* ************************************************************************** */
/* Transfer */
/* ************************************************************************** */
static int open_tcp_sock( const unsigned char *name, const int port)
{
  int sockfd;
  struct sockaddr_in serv_addr;
  struct hostent *server;

  server = gethostbyname((const char *)name);
  if (server == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
  }

  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
  serv_addr.sin_port = htons(port);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
      printf("ERROR opening socket\n");
  if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
      printf("ERROR connecting\n");

  return sockfd;
}

#define MAX_CMP_DER 8192
#define MAX_HTTP_HDR 512 /* that should be quite generous */
static int recv_http( const int sockfd, unsigned char **inbuf, size_t *inlen)
{
    char http_hdr_buf[MAX_HTTP_HDR+1];
    ssize_t n;
    size_t rcvd = 0;
    size_t http_rcvd = 0;
    size_t der_rcvd = 0;
    size_t max = MAX_HTTP_HDR;
    unsigned char *p = (unsigned char *) http_hdr_buf;
    char *s = NULL;
    char *e = NULL;
    size_t len = MAX_HTTP_HDR+1;

    http_hdr_buf[MAX_HTTP_HDR] = '\0'; /* to avoid strstr going out of bounds */

    do {
        n = read(sockfd, p, max - rcvd); /* TODO: asuming this is blocking... */
        if( n < 0) {
            printf("ERROR reading from socket\n");
            goto err;
        }

        rcvd += n;
        p += n;

        if( e == NULL) {
            /* TODO: check for 200/OK */
            /* TODO: check for content-type */
            if( (e = strstr( http_hdr_buf, "\r\n\r\n")) != NULL)
                e += 4;
            else
                continue;

            s = strstr( http_hdr_buf, "Content-Length: ");
            if( s == NULL)
                goto err;
            sscanf( s, "Content-Length: %lu\r\n", &len);
            if( len > MAX_CMP_DER) /* for safety */
                goto err; /* TODO set error */

            *inbuf = (unsigned char *) mbedtls_calloc(1, len);
            max = len;
            der_rcvd = rcvd-(e-http_hdr_buf);
            memcpy(*inbuf, e, der_rcvd);
            p = *inbuf + der_rcvd;
            http_rcvd = rcvd;
            rcvd = der_rcvd;
        }

    } while (rcvd < len);

    *inlen = len;

    return (der_rcvd + http_rcvd); /* amount of bytes read */
err:
    if( *inbuf)
        mbedtls_free(*inbuf);
    return -1;
}


static int send_http( int sockfd, const char *path, const char *host, const char *buf, const size_t len)
{
    int n;

    static const char req_hdr[] =
        "POST /%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/pkixcmp\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Length: %zd\r\n"
        "\r\n";

    /* write to socket */
    n = dprintf( sockfd, req_hdr, path, host, len);
    if (n < 0) {
        printf("ERROR writing to socket\n");
        return -1;
    }
//CMPDBGV("wrote %d bytes to socket", n)

    n = write( sockfd, buf, len);
    if (n < 0) {
        printf("ERROR writing to socket\n");
        return -1;
    }
//CMPDBGV("wrote %d bytes to socket", n)

    return n;
}

int send_receive( const unsigned char *shost, const int sport, const unsigned char *spath,
                  const unsigned char *outbuf, const size_t len,
                  unsigned char **inbuf, size_t *inlen) {
    int sockfd;
    int ret = 0;

    sockfd = open_tcp_sock( shost, sport);

    ret = send_http( sockfd, (const char *)spath, (const char*)shost, (const char*)outbuf, len ); /* TODO if... */
    //write_to_file( DER_OUTPUT_REQ, output_buf+sizeof(output_buf)-len, len);
    if (ret < 0) goto err;

    ret = recv_http( sockfd, inbuf, inlen); /* TODO if... */
    //write_to_file( DER_OUTPUT_REP, der, derlen);

err:
    close(sockfd);
    return ret;
}

/* ************************************************************************** */
/* Devel HELPERS */
/* ************************************************************************** */

static int write_to_file(const char* ofile, unsigned char* output,
                         const size_t len)
{
    FILE *f;

    if( ( f = fopen( ofile, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );
    return( 0 );
}
