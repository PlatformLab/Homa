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

#include "Debug.h"
#include "Homa/Homa.h"
#include "Homa/Shenango.h"

using namespace Homa;

/**
 * Shorthand for declaring "extern" function pointers to Shenango functions.
 * These functions pointers will be initialized on the Shenango side in homa.c.
 */
#define DECLARE_SHENANGO_FUNC(ReturnType, MethodName, ...)  \
    extern ReturnType (*shenango_##MethodName) (__VA_ARGS__);

/**
 * Fast thread-local slab-based memory allocation.
 */
DECLARE_SHENANGO_FUNC(void*, smalloc, size_t)
DECLARE_SHENANGO_FUNC(void, sfree, void*)

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
DECLARE_SHENANGO_FUNC(int, homa_tx_ip,
        uintptr_t, void*, int32_t, uint8_t, uint32_t, uint8_t)

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
DECLARE_SHENANGO_FUNC(void*, trans_table_lookup,
        uint8_t, SocketAddress, SocketAddress)

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
    {}

    Packet allocPacket() override
    {
        void* payload;
        void* mbuf = shenango_homa_tx_alloc_mbuf(&payload);
        return Packet{(uintptr_t) mbuf, payload, 0};
    }

    void
    sendPacket(Packet* packet, IpAddress destination, int priority) override
    {
        shenango_homa_tx_ip(packet->descriptor, packet->payload, packet->length,
                proto, (uint32_t)destination, (uint8_t)priority);
    }

    uint32_t
    receivePackets(uint32_t maxPackets, Packet receivedPackets[],
                   IpAddress sourceAddresses[]) override
    {
        (void)maxPackets;
        (void)receivedPackets;
        (void)sourceAddresses;
        PANIC("receivePackets must not be called when used with Shenango");
        return 0;
    }

    void
    releasePackets(Packet packets[], uint16_t numPackets) override
    {
        for (uint16_t i = 0; i < numPackets; i++) {
            shenango_mbuf_free((void*) packets[i].descriptor);
        }
    }

    uint32_t getMaxPayloadSize() override { return max_payload; }

    uint32_t getBandwidth() override { return link_speed; }

    IpAddress getLocalAddress() override { return local_ip; }

    uint32_t getQueuedBytes() override { return shenango_homa_queued_bytes(); }

  private:
    /// Protocol number reserved for Homa; defined as IPPROTO_HOMA in Shenango.
    const uint8_t proto;

    /// Local IP address of the driver.
    const IpAddress local_ip;

    /// # bytes in a payload
    const uint32_t max_payload;

    /// Effective network bandwidth, in Mbits/second.
    const uint32_t link_speed;
};

homa_driver
homa_driver_create(uint8_t proto, uint32_t local_ip, uint32_t max_payload,
                   uint32_t link_speed)
{
    void* driver = new ShenangoDriver(proto, local_ip, max_payload, link_speed);
    return homa_driver{driver};
}

void homa_driver_free(homa_driver drv)
{
    delete static_cast<ShenangoDriver*>(drv.p);
}

/**
 * An almost trivial implementation of Mailbox.  This class is essentially
 * a wrapper around a socket table entry in Shenango (i.e., struct trans_entry).
 *
 */
class ShenangoMailbox final : public Mailbox {
  public:
    explicit ShenangoMailbox(void* trans_entry)
        : trans_entry(trans_entry)
    {}

    ~ShenangoMailbox() override = default;

    void close() override
    {
        this->~ShenangoMailbox();
        shenango_sfree(this);
        shenango_rcu_read_unlock();
    }

    void deliver(InMessage* message) override
    {
        shenango_homa_mb_deliver(trans_entry, homa_inmsg{message});
    }

    InMessage* retrieve(bool blocking) override
    {
        (void)blocking;
        PANIC("Shenango should never call Homa::Socket::receive");
    }

    void socketShutdown() override
    {
        PANIC("Shenango should never call Homa::Socket::shutdown");
    }

  private:
    /// An opaque pointer to "struct trans_entry" in Shenango.
    void* const trans_entry;
};

/**
 * An almost trivial implementation of MailboxDir that uses Shenango's RCU
 * mechanism to prevent a mailbox from being destroyed until all readers have
 * closed it.
 *
 * Note: Shenango doesn't use Homa::Socket to receive messages, so the only
 * method that has a meaningful implementation is open().
 */
class ShenangoMailboxDir final : MailboxDir {
  public:
    explicit ShenangoMailboxDir(uint8_t proto, uint32_t local_ip)
        : proto(proto)
        , local_ip{local_ip}
    {}

    ~ShenangoMailboxDir() override = default;

    Mailbox* alloc(uint16_t port) override
    {
        // Shenango doesn't rely on Homa::Socket to receive messages,
        // so there is no need to assign a real mailbox to SocketImpl.
        static ShenangoMailbox dummyMailbox(nullptr);
        (void)port;
        return &dummyMailbox;
    }

    Mailbox* open(uint16_t port) override
    {
        SocketAddress laddr = {local_ip, port};
        shenango_rcu_read_lock();
        void* trans_entry = shenango_trans_table_lookup(proto, laddr, {});
        if (!trans_entry) {
            return nullptr;
        }
        void* backing = shenango_smalloc(sizeof(ShenangoMailbox));
        return new (backing) ShenangoMailbox(trans_entry);
    }

    bool remove(uint16_t port) override
    {
        // Nothing to do; Shenango is responsible for taking care of freeing
        // the resources related to homa sockets.
        (void)port;
        return true;
    }

    /// Protocol number reserved for Homa; defined as IPPROTO_HOMA in Shenango.
    const uint8_t proto;

    /// Local IP address of the transport.
    const IpAddress local_ip;
};

homa_mailbox_dir homa_mb_dir_create(uint8_t proto, uint32_t local_ip)
{
    void* dir = new ShenangoMailboxDir(proto, local_ip);
    return homa_mailbox_dir{dir};
}

void homa_mb_dir_free(homa_mailbox_dir mailbox_dir)
{
    delete static_cast<ShenangoMailboxDir*>(mailbox_dir.p);
}
