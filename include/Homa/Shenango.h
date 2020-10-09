/* Copyright (c) 2020 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @file Shenango.h
 *
 * Contains the glue code for Homa-Shenango integration. This is the only
 * header Shenango needs to include in order to use Homa transport.
 *
 * Shenango is an experimental operating system that aims to provide low tail
 * latency and high CPU efficiency simultaneously for servers in datacenters.
 * See <https://github.com/shenango/shenango> for more information.
 *
 * This file follows the Shenango coding style.
 */

#pragma once

#include "Bindings/CHoma.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * homa_driver_create - creates a shim driver that translates Homa::Driver
 * operations to Shenango functions
 * @proto: protocol number reserved for Homa transport protocol
 * @local_ip: local IP address of the driver
 * @max_payload: maximum number of bytes carried by the packet payload
 * @link_speed: effective network bandwidth, in Mbits/second
 *
 * Returns a handle to the driver created.
 */
extern homa_driver homa_driver_create(uint8_t proto, uint32_t local_ip,
                                      uint32_t max_payload,
                                      uint32_t link_speed);

/**
 * homa_driver_free - frees a shim driver created earlier with
 * @homa_driver_create.
 * @param drv: the driver to free
 */
extern void homa_driver_free(homa_driver drv);

/**
 * homa_callbacks_create - creates a collection of the Shenango-defined
 * callbacks for the transport.
 * @proto: protocol number reserved for Homa transport protocol
 * @local_ip: local IP address of the driver
 * @cb_send_ready: callback function to invoke in Callbacks::notifySendReady
 * @cb_data: input data for @cb_send_ready
 *
 * Returns a handle to the callbacks created.
 */
extern homa_callbacks homa_callbacks_create(uint8_t proto, uint32_t local_ip,
                                            void (*cb_send_ready)(void*),
                                            void* cb_data);

/**
 * homa_callbacks_free - frees the Callbacks object created earlier with
 * @homa_callbacks_create.
 * @param cbs: the callbacks to free
 */
extern void homa_callbacks_free(homa_callbacks cbs);

#ifdef __cplusplus
}
#endif