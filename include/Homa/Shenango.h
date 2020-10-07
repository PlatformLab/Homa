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
extern "C"
{
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
        uint32_t max_payload, uint32_t link_speed);

/**
 * homa_driver_free - frees a shim driver created earlier with
 * @homa_driver_create.
 * @param drv: the driver to free
 */
extern void homa_driver_free(homa_driver drv);

/**
 * homa_mb_dir_create - creates a shim mailbox directory that translates
 * Homa::Mailbox operations to Shenango functions
 * @proto: protocol number reserved for Homa transport protocol
 * @local_ip: local IP address of the driver
 *
 * Returns a handle to the mailbox created.
 */
extern homa_mailbox_dir homa_mb_dir_create(uint8_t proto, uint32_t local_ip);

/**
 * homa_mb_dir_free - frees a shim mailbox directory created earlier with
 * @homa_mb_dir_create.
 * @param mailbox_dir: the mailbox directory to free
 */
extern void homa_mb_dir_free(homa_mailbox_dir mailbox_dir);

#ifdef __cplusplus
}
#endif