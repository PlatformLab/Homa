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

#include "Homa/Transports/Shenango.h"

#include <utility>
#include "../Debug.h"
#include "Homa/Core/Transport.h"

using namespace Homa;

/**
 * Shorthand for declaring "extern" function pointers to Shenango functions.
 * These functions pointers will be initialized on the Shenango side in homa.c.
 */
#define DECLARE_SHENANGO_FUNC(ReturnType, MethodName, ...) \
    extern ReturnType (*shenango_##MethodName)(__VA_ARGS__);

/**
 * Protect RCU read-side critical sections.
 */
DECLARE_SHENANGO_FUNC(void, rcu_read_lock)
DECLARE_SHENANGO_FUNC(void, rcu_read_unlock)

/**
 * Allocate a Shenango mbuf struct to hold an egress Homa packet.
 */
DECLARE_SHENANGO_FUNC(void*, homa_tx_alloc_mbuf, void**)

/**
 * Free a packet buffer allocated earlier.
 */
DECLARE_SHENANGO_FUNC(void, mbuf_free, void*)

/**
 * Transmit an IP packet using Shenango's driver stack.
 */
DECLARE_SHENANGO_FUNC(int, homa_tx_ip, uintptr_t, void*, int32_t, uint8_t,
                      uint32_t, uint8_t)

/**
 * Deliver an ingress message to a homa socket in Shenango.
 */
DECLARE_SHENANGO_FUNC(void, homa_mb_deliver, void*, homa_inmsg)

/**
 * Return the number of bytes queued up in the transmit queue.
 */
DECLARE_SHENANGO_FUNC(uint32_t, homa_queued_bytes)

/**
 * Find a socket that matches the 5-tuple.
 */
DECLARE_SHENANGO_FUNC(void*, trans_table_lookup, uint8_t, SocketAddress,
                      SocketAddress)

/**
 * Callback functions specialized for the Shenango runtime.
 */
class ShenangoCallbacks final : Core::Transport::Callbacks {
  public:
    explicit ShenangoCallbacks(uint8_t proto, uint32_t local_ip,
                               std::function<void()> notify_send_ready)
        : proto(proto)
        , local_ip{local_ip}
        , notify_send_ready(std::move(notify_send_ready))
    {}

    ~ShenangoCallbacks() override = default;

    bool deliver(uint16_t port, Homa::unique_ptr<InMessage> message) override
    {
        // The socket table in Shenango is protected by an RCU.
        shenango_rcu_read_lock();
        SocketAddress laddr = {local_ip, port};
        void* trans_entry = shenango_trans_table_lookup(proto, laddr, {});
        if (trans_entry) {
            shenango_homa_mb_deliver(trans_entry,
                                     homa_inmsg{message.release()});
        }
        shenango_rcu_read_unlock();
        return trans_entry != nullptr;
    }

    void notifySendReady() override
    {
        notify_send_ready();
    }

    /// Protocol number reserved for Homa; defined as IPPROTO_HOMA in Shenango.
    const uint8_t proto;

    /// Local IP address of the transport.
    const IpAddress local_ip;

    /// Callback function for notifySendReady().
    std::function<void()> notify_send_ready;
};

/**
 * A simple shim driver that translates Driver operations to Shenango
 * functions.
 */
class ShenangoDriver final : public Driver {
  public:
    explicit ShenangoDriver(uint8_t proto, uint32_t local_ip,
                            uint32_t max_payload, uint32_t link_speed)
        : Driver()
        , proto(proto)
        , local_ip{local_ip}
        , max_payload(max_payload)
        , link_speed(link_speed)
        , callbacks()
    {}

    ~ShenangoDriver() override = default;

    void allocPacket(Packet* packet) override
    {
        void* payload;
        void* mbuf = shenango_homa_tx_alloc_mbuf(&payload);
        return Packet{(uintptr_t)mbuf, payload, 0};
    }

    void sendPacket(Packet* packet, IpAddress destination,
                    int priority) override
    {
        shenango_homa_tx_ip(packet->descriptor, packet->payload, packet->length,
                            proto, (uint32_t)destination, (uint8_t)priority);
    }

    uint32_t receivePackets(uint32_t maxPackets, Packet receivedPackets[],
                            IpAddress sourceAddresses[]) override
    {
        (void)maxPackets;
        (void)receivedPackets;
        (void)sourceAddresses;
        PANIC("receivePackets must not be called when used with Shenango");
        return 0;
    }

    void releasePackets(Packet packets[], uint16_t numPackets) override
    {
        for (uint16_t i = 0; i < numPackets; i++) {
            shenango_mbuf_free((void*)packets[i].descriptor);
        }
    }

    uint32_t getMaxPayloadSize() override
    {
        return max_payload;
    }

    uint32_t getBandwidth() override
    {
        return link_speed;
    }

    IpAddress getLocalAddress() override
    {
        return local_ip;
    }

    uint32_t getQueuedBytes() override
    {
        return shenango_homa_queued_bytes();
    }

    /// Protocol number reserved for Homa; defined as IPPROTO_HOMA in Shenango.
    const uint8_t proto;

    /// Local IP address of the driver.
    const IpAddress local_ip;

    /// # bytes in a payload
    const uint32_t max_payload;

    /// Effective network bandwidth, in Mbits/second.
    const uint32_t link_speed;

    /// Callback object. Piggybacked here to allow automatic destruction.
    std::unique_ptr<ShenangoCallbacks> callbacks;
};

homa_trans
homa_create_shenango_trans(uint64_t id, uint8_t proto, uint32_t local_ip,
                           uint32_t max_payload, uint32_t link_speed,
                           void (*cb_send_ready)(void*), void* cb_data)
{
    ShenangoCallbacks* callbacks = new ShenangoCallbacks(
        proto, local_ip, std::bind(cb_send_ready, cb_data));
    ShenangoDriver* drv =
        new ShenangoDriver(proto, local_ip, max_payload, link_speed);
    drv->callbacks.reset(callbacks);
    return homa_trans_create(homa_driver{drv}, homa_callbacks{callbacks}, id);
}

void
homa_free_shenango_trans(homa_trans trans)
{
    homa_driver drv = homa_trans_get_drv(trans);
    homa_trans_free(trans);
    delete static_cast<ShenangoDriver*>(drv.p);
}
