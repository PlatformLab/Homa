/* Copyright (c) 2020, Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "Homa/Homa.h"
#include "Homa/Bindings/CHoma.h"

using namespace Homa;

/// Shorthand for converting C-style Homa object handle types back to C++ types.
#define deref(T, x) (*static_cast<T*>(x.p))

void homa_inmsg_ack(homa_inmsg in_msg)
{
    deref(InMessage, in_msg).acknowledge();
}

bool homa_inmsg_dropped(homa_inmsg in_msg)
{
    return deref(InMessage, in_msg).dropped();
}

void homa_inmsg_fail(homa_inmsg in_msg)
{
    deref(InMessage, in_msg).fail();
}

size_t homa_inmsg_get(homa_inmsg in_msg, size_t ofs, void* dst, size_t len)
{
    return deref(InMessage, in_msg).get(ofs, dst, len);
}

void homa_inmsg_src_addr(homa_inmsg in_msg, uint32_t *ip, uint16_t *port)
{
    SocketAddress src = deref(InMessage, in_msg).getSourceAddress();
    *ip = (uint32_t)src.ip;
    *port = src.port;
}

size_t homa_inmsg_len(homa_inmsg in_msg)
{
    return deref(InMessage, in_msg).length();
}

void homa_inmsg_release(homa_inmsg in_msg)
{
    InMessage::Deleter deleter;
    deleter(&deref(InMessage, in_msg));
}

void homa_inmsg_strip(homa_inmsg in_msg, size_t n)
{
    deref(InMessage, in_msg).strip(n);
}

void homa_outmsg_append(homa_outmsg out_msg, const void* buf, size_t len)
{
    deref(OutMessage, out_msg).append(buf, len);
}

void homa_outmsg_cancel(homa_outmsg out_msg)
{
    deref(OutMessage, out_msg).cancel();
}

int homa_outmsg_status(homa_outmsg out_msg)
{
    return int(deref(OutMessage, out_msg).getStatus());
}

void homa_outmsg_prepend(homa_outmsg out_msg, const void* buf, size_t len)
{
    deref(OutMessage, out_msg).prepend(buf, len);
}

void homa_outmsg_reserve(homa_outmsg out_msg, size_t n)
{
    deref(OutMessage, out_msg).reserve(n);
}

void homa_outmsg_send(homa_outmsg out_msg, uint32_t ip, uint16_t port)
{
    deref(OutMessage, out_msg).send({IpAddress{ip}, port});
}

void homa_outmsg_register_cb_end_state(homa_outmsg out_msg,
                                       void (*cb) (void*), void *data)
{
    std::function<void()> func = std::bind(cb, data);
    deref(OutMessage, out_msg).registerCallbackEndState(func);
}

void homa_outmsg_release(homa_outmsg out_msg)
{
    OutMessage::Deleter deleter;
    deleter(&deref(OutMessage, out_msg));
}

homa_outmsg homa_sk_alloc(homa_sk sk)
{
    unique_ptr<OutMessage> out_msg = deref(Socket, sk).alloc();
    return homa_outmsg{out_msg.release()};
}

homa_inmsg homa_sk_receive(homa_sk sk, bool blocking)
{
    unique_ptr<InMessage> in_msg = deref(Socket, sk).receive(blocking);
    return homa_inmsg{in_msg.release()};
}

void homa_sk_shutdown(homa_sk sk)
{
    deref(Socket, sk).shutdown();
}

bool homa_sk_is_shutdown(homa_sk sk)
{
    return deref(Socket, sk).isShutdown();
}

void homa_sk_local_addr(homa_sk sk, uint32_t *ip, uint16_t *port)
{
    SocketAddress addr = deref(Socket, sk).getLocalAddress();
    *ip = (uint32_t)addr.ip;
    *port = addr.port;
}

void homa_sk_close(homa_sk sk)
{
    Socket::Deleter deleter;
    deleter(&deref(Socket, sk));
}

homa_trans homa_trans_create(homa_driver drv, homa_mailbox_dir dir, uint64_t id)
{
    unique_ptr<Transport> trans =
        Transport::create(&deref(Driver, drv), &deref(MailboxDir, dir), id);
    return homa_trans{trans.release()};
}

void homa_trans_free(homa_trans trans)
{
    Transport::Deleter deleter;
    deleter(&deref(Transport, trans));
}

homa_sk homa_trans_open(homa_trans trans, uint16_t port)
{
    unique_ptr<Socket> sk = deref(Transport, trans).open(port);
    return homa_sk{sk.release()};
}

uint64_t homa_trans_check_timeouts(homa_trans trans)
{
    return deref(Transport, trans).checkTimeouts();
}

uint64_t homa_trans_id(homa_trans trans)
{
    return deref(Transport, trans).getId();
}

void homa_trans_proc(homa_trans trans, uintptr_t desc, void* payload,
                     int32_t len, uint32_t src_ip)
{
    Driver::Packet packet = {
        .descriptor = desc,
        .payload = payload,
        .length = len
    };
    deref(Transport, trans).processPacket(&packet, IpAddress{src_ip});
}

void homa_trans_register_cb_send_ready(homa_trans trans, void (*cb) (void*),
                                       void *data)
{
    std::function<void()> func = std::bind(cb, data);
    deref(Transport, trans).registerCallbackSendReady(func);
}

bool homa_trans_try_send(homa_trans trans, uint64_t *wait_until)
{
    return deref(Transport, trans).trySend(wait_until);
}

bool homa_trans_try_grant(homa_trans trans)
{
    return deref(Transport, trans).trySendGrants();
}
