/* Copyright (c) 2018, Stanford University
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

#ifndef HOMA_CORE_MESSAGECONTEXT_H
#define HOMA_CORE_MESSAGECONTEXT_H

#include "Driver.h"
#include "ObjectPool.h"
#include "SpinLock.h"

#include <atomic>
#include <bitset>

namespace Homa {
namespace Core {

// forward declaration
class MessagePool;

/**
 * Holds the contents and metadata from a Transport::Message.
 *
 * The lifetime of instances of this class are controlled with reference counts.
 *
 * This class is not thread-safe but should only be modified by one part of
 * the transport a time.
 */
class MessageContext {
  public:
    /// Define the maximum number of packets that a message can hold.
    static const uint16_t MAX_MESSAGE_PACKETS = 1024;

    explicit MessageContext(uint16_t dataHeaderLength, Driver* driver,
                            MessagePool* messagePool);
    ~MessageContext();

    Driver::Packet* getPacket(uint16_t index);
    bool setPacket(uint16_t index, Driver::Packet* packet);
    void retain();
    void release();

    /// Contains the source address for a recevied message and and the
    /// destination for an sent message.
    Driver::Address* address;

    /// Total length of the message.
    uint32_t messageLength;

    /// Number of bytes of data in each full packet.
    const uint16_t PACKET_DATA_LENGTH;

    /// Number of bytes used by the Homa protocol header in each packet.
    const uint16_t DATA_HEADER_LENGTH;

  private:
    /// Memory pool from which this MessageContext was allocated and to which it
    /// should be returned on destruction.
    MessagePool* messagePool;

    /// Driver from which packets were allocated and to which they should be
    /// returned when this message is no longer needed.
    Driver* driver;

    /// Number of times this context has been retained (see retain()).
    /// Constructing a instances of MessageCountext set the refCount to 1.
    /// When the refCount reaches 0, the instance will be destroyed.
    std::atomic<int> refCount;

    /// Number of packets contained in this message.
    uint16_t numPackets;

    /// Bit array representing which entires in the _packets_ array are set.
    /// Used to avoid having to zero out the entire _packets_ array.
    std::bitset<MAX_MESSAGE_PACKETS> occupied;

    /// Collection of packets that form this message.
    Driver::Packet* packets[MAX_MESSAGE_PACKETS];

    MessageContext(const MessageContext&) = delete;
    MessageContext& operator=(const MessageContext&) = delete;
};

/**
 * Provides a pool allocator for MessageContext objects.
 *
 * This class is thread-safe.
 */
class MessagePool {
  public:
    MessagePool();
    ~MessagePool() {}

    MessageContext* construct(uint16_t dataHeaderLength, Driver* driver);
    void destroy(MessageContext* messageContext);

  private:
    /// Monitor style lock for the pool.
    SpinLock mutex;

    /// Actual memory allocator for MessageContext objects.
    ObjectPool<MessageContext> pool;

    MessagePool(const MessagePool&) = delete;
    MessagePool& operator=(const MessagePool&) = delete;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_MESSAGECONTEXT_H