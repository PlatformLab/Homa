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
 * @file CHoma.h
 *
 * Contains C-bindings for the Homa Transport API.
 */

#pragma once

#include "Homa/OutMessageStatus.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Define handle types for various Homa objects.
 *
 * A handle type is essentially a thin wrapper around an opaque pointer.
 * Compared to generic pointers, using handle types in the C API enables
 * some type safety.
 */
#define DEFINE_HOMA_OBJ_HANDLE(x) typedef struct { void *p; } homa_##x;

DEFINE_HOMA_OBJ_HANDLE(driver)      /* Homa::Driver     */
DEFINE_HOMA_OBJ_HANDLE(inmsg)       /* Homa::InMessage  */
DEFINE_HOMA_OBJ_HANDLE(outmsg)      /* Homa::OutMessage */
DEFINE_HOMA_OBJ_HANDLE(mailbox)     /* Homa::Mailbox    */
DEFINE_HOMA_OBJ_HANDLE(mailbox_dir) /* Homa::MailboxDir */
DEFINE_HOMA_OBJ_HANDLE(sk)          /* Homa::Socket     */
DEFINE_HOMA_OBJ_HANDLE(trans)       /* Homa::Transport  */

/* ============================ */
/*     Homa::InMessage API      */
/* ============================ */

/**
 * homa_inmsg_ack - C-binding for Homa::InMessage::acknowledge
 */
extern void homa_inmsg_ack(homa_inmsg in_msg);

/**
 * homa_inmsg_dropped - C-binding for Homa::InMessage::dropped
 */
extern bool homa_inmsg_dropped(homa_inmsg in_msg);

/**
 * homa_inmsg_fail - C-binding for Homa::InMessage::fail
 */
extern void homa_inmsg_fail(homa_inmsg in_msg);

/**
 * homa_inmsg_get - C-binding for Homa::InMessage::get
 */
extern size_t homa_inmsg_get(homa_inmsg in_msg, size_t ofs, void *dst,
                             size_t len);

/**
 * homa_inmsg_src_addr - C-binding for Homa::InMessage::getSourceAddress
 */
extern void homa_inmsg_src_addr(homa_inmsg in_msg, uint32_t *ip,
                                uint16_t *port);

/**
 * homa_inmsg_len - C-binding for Homa::InMessage::length
 */
extern size_t homa_inmsg_len(homa_inmsg in_msg);

/**
 * homa_inmsg_release - C-binding for Homa::InMessage::release
 */
extern void homa_inmsg_release(homa_inmsg in_msg);

/**
 * homa_inmsg_strip - C-binding for Homa::InMessage::strip
 */
extern void homa_inmsg_strip(homa_inmsg in_msg, size_t n);


/* ============================ */
/*     Homa::OutMessage API     */
/* ============================ */

/**
 * homa_outmsg_append - C-binding for Homa::OutMessage::append
 */
extern void homa_outmsg_append(homa_outmsg out_msg, const void *buf,
                               size_t len);

/**
 * homa_outmsg_cancel - C-binding for Homa::OutMessage::cancel
 */
extern void homa_outmsg_cancel(homa_outmsg out_msg);

/**
 * homa_outmsg_status - C-binding for Homa::OutMessage::getStatus
 */
extern int homa_outmsg_status(homa_outmsg out_msg);

/**
 * homa_outmsg_prepend - C-binding for Homa::OutMessage::prepend
 */
extern void homa_outmsg_prepend(homa_outmsg out_msg, const void *buf,
                                size_t len);

/**
 * homa_outmsg_reserve - C-binding for Homa::OutMessage::reserve
 */
extern void homa_outmsg_reserve(homa_outmsg out_msg, size_t n);

/**
 * homa_outmsg_send - C-binding for Homa::OutMessage::send
 */
extern void homa_outmsg_send(homa_outmsg out_msg, uint32_t ip, uint16_t port);

/**
 * homa_outmsg_register_cb - C-binding for
 * Homa::OutMessage::registerCallbackEndState
 */
extern void homa_outmsg_register_cb_end_state(homa_outmsg out_msg,
                                              void (*cb) (void*),
                                              void *data);

/**
 * homa_outmsg_release - C-binding for Homa::OutMessage::release
 */
extern void homa_outmsg_release(homa_outmsg out_msg);

/* ============================ */
/*       Homa::Socket API       */
/* ============================ */

/**
 * homa_sk_alloc - C-binding for Homa::Socket::alloc
 */
extern homa_outmsg homa_sk_alloc(homa_sk sk);

/**
 * homa_sk_receive - C-binding for Homa::Socket::receive
 */
extern homa_inmsg homa_sk_receive(homa_sk sk, bool blocking);

/**
 * homa_sk_shutdown - C-binding for Homa::Socket::shutdown
 */
extern void homa_sk_shutdown(homa_sk sk);

/**
 * homa_sk_is_shutdown - C-binding for Homa::Socket::isShutdown
 */
extern bool homa_sk_is_shutdown(homa_sk sk);

/**
 * homa_sk_local_addr - C-binding for Homa::Socket::getLocalAddress
 */
extern void homa_sk_local_addr(homa_sk sk, uint32_t *ip, uint16_t *port);

/**
 * homa_sk_close - C-binding for Homa::Socket::close
 */
extern void homa_sk_close(homa_sk sk);

/* ============================ */
/*     Homa::Transport API      */
/* ============================ */

/**
 * homa_trans_create - C-binding for Homa::Transport::create
 */
extern homa_trans homa_trans_create(homa_driver drv, homa_mailbox_dir dir,
                                    uint64_t id);

/**
 * homa_trans_free - C-binding for Homa::Transport::free
 */
extern void homa_trans_free(homa_trans trans);

/**
 * homa_trans_open - C-binding for Homa::Transport::open
 */
extern homa_sk homa_trans_open(homa_trans trans, uint16_t port);

/**
 * homa_trans_check_timeouts - C-binding for Homa::Transport::checkTimeouts
 */
extern uint64_t homa_trans_check_timeouts(homa_trans trans);

/**
 * homa_trans_id - C-binding for Homa::Transport::getId
 */
extern uint64_t homa_trans_id(homa_trans trans);

/**
 * homa_trans_proc - C-binding for Homa::Transport::processPacket
 */
extern void homa_trans_proc(homa_trans trans, uintptr_t desc, void* payload,
                            int32_t len, uint32_t src_ip);

/**
 * homa_trans_try_send - C-binding for
 * Homa::Transport::registerCallbackSendReady
 */
extern void homa_trans_register_cb_send_ready(homa_trans trans,
                                              void (*cb) (void*), void *data);

/**
 * homa_trans_try_send - C-binding for Homa::Transport::trySend
 */
extern bool homa_trans_try_send(homa_trans trans, uint64_t *wait_until);

/**
 * homa_trans_try_grant - C-binding for Homa::Transport::trySendGrants
 */
extern bool homa_trans_try_grant(homa_trans trans);

#ifdef __cplusplus
}
#endif