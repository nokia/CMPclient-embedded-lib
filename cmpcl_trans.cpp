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

#include "cmpcl_int.h"
#include "mbed.h"
#include "http_request.h"
#include <cstring>

extern NetworkInterface* network;


int send_receive( const char *shost, const int sport, const char *spath,
                  const char *outbuf, const size_t len,
                  char **inbuf, size_t *inlen)
{
    char *addr;
    addr = (char*)calloc(1, 7+strlen(shost)+1+5+1+strlen(spath)+1);
    sprintf(addr, "http://%s:%d/%s", shost, sport, spath);
    CMPDBGV("Attempting to post %d bytes to addr %s", len, addr);

    HttpRequest* request = new HttpRequest(network, HTTP_POST, addr);
    request->set_header("Content-Type", "application/pkixcmp");
    request->set_header("Cache-Control", "no-cache");
    HttpResponse* response = request->send(outbuf, len);
    // if response is NULL, check response->get_error()

    if (response == NULL) {
        CMPERRS("Response was NULL");
        free(addr);
        delete request;
        return -1;
    }

    CMPDBGV("status is %d - %s", response->get_status_code(), response->get_status_message().c_str());

    *inlen = response->get_body_as_string().length();
    *inbuf = (char*) malloc(*inlen);
    memcpy(*inbuf, response->get_body_as_string().c_str(), *inlen);

    free(addr);
    delete request; // also clears out the response
    return 0;
}
