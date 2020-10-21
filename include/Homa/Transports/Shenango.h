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
 * @file Homa/Transports/Shenango.h
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

#ifndef HOMA_INCLUDE_HOMA_TRANSPORTS_SHENANGO_H
#define HOMA_INCLUDE_HOMA_TRANSPORTS_SHENANGO_H

#include <Homa/Bindings/CHoma.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * homa_create_shenango_trans - creates a transport instance that can be used by
 * Shenango to send and receive messages.
 * @id:             Unique identifier for this transport instance
 * @proto:          Protocol number reserved for Homa transport protocol
 * @local_ip:       Local IP address of the driver
 * @max_payload:    Maximum number of bytes carried by the packet payload
 * @link_speed:     Effective network bandwidth, in Mbits/second
 * @cb_send_ready:  Callback function to invoke in Callbacks::notifySendReady
 * @cb_data:        Input data for @cb_send_ready
 *
 * Returns a handle to the callbacks created.
 */
extern homa_trans homa_create_shenango_trans(uint64_t id,
    uint8_t proto, uint32_t local_ip, uint32_t max_payload, uint32_t link_speed,
    void (*cb_send_ready)(void*), void* cb_data);

/**
 * homa_free_shenango_trans - frees a transport created earlier with
 * @homa_create_shenango_trans.
 * @param trans: the transport to free
 */
extern void homa_free_shenango_trans(homa_trans trans);

#ifdef __cplusplus
}
#endif

#endif  // HOMA_INCLUDE_HOMA_TRANSPORTS_SHENANGO_H