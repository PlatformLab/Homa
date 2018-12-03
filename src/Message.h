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

#ifndef HOMA_CORE_MESSAGE_H
#define HOMA_CORE_MESSAGE_H

#include "Homa/Driver.h"
#include "Homa/Homa.h"

#include "ObjectPool.h"
#include "Protocol.h"
#include "SpinLock.h"

#include <atomic>
#include <bitset>

namespace Homa {
namespace Core {

// forward declaration
class MessagePool;

/**
 * The Message holds the Driver::Packet objects and metadata that make up
 * a Homa::Message.  The Message also manages the lifetimes of held
 * Packet objects on behalf of a Homa::Message.
 *
 * The lifetime of instances of this class are controlled with reference counts.
 *
 * This class is not thread-safe but should only be modified by one part of
 * the transport a time.
 */
class Message : Homa::Message {
  public:
    /// Define the maximum number of packets that a message can hold.
    static const uint16_t MAX_MESSAGE_PACKETS = 1024;

    explicit Message(Protocol::MessageId msgId, uint16_t dataHeaderLength,
                     Driver* driver, MessagePool* messagePool);
    ~Message();

    virtual void append(const void* source, uint32_t num);
    virtual uint32_t get(uint32_t offset, void* destination,
                         uint32_t num) const;
    virtual void set(uint32_t offset, const void* source, uint32_t num);

    Driver::Packet* getPacket(uint16_t index) const;
    bool setPacket(uint16_t index, Driver::Packet* packet);
    uint16_t getNumPackets() const;
    void retain();
    void release();

    /// Contains the unique identifier for this message.
    const Protocol::MessageId msgId;

    /// Contains the source address for a recevied message and and the
    /// destination for an sent message.
    Driver::Address* address;

    /// Driver from which packets were allocated and to which they should be
    /// returned when this message is no longer needed.
    Driver* const driver;

    /// Total length of the message.
    uint32_t messageLength;

    /// Number of bytes of data in each full packet.
    const uint16_t PACKET_DATA_LENGTH;

    /// Number of bytes used by the Homa protocol header in each packet.
    const uint16_t DATA_HEADER_LENGTH;

  private:
    /// Memory pool from which this Message was allocated and to which it
    /// should be returned on destruction.
    MessagePool* messagePool;

    /// Number of times this context has been retained (see retain()).
    /// Constructing a instances of MessageCountext set the refCount to 1.
    /// When the refCount reaches 0, the instance will be destroyed.
    std::atomic<int> refCount;

    /// Number of packets contained in this context.
    uint16_t numPackets;

    /// Bit array representing which entires in the _packets_ array are set.
    /// Used to avoid having to zero out the entire _packets_ array.
    std::bitset<MAX_MESSAGE_PACKETS> occupied;

    /// Collection of Packet objects that make up this context's Message.
    /// These Packets will be released when this context is destroyed.
    Driver::Packet* packets[MAX_MESSAGE_PACKETS];

    Message(const Message&) = delete;
    Message& operator=(const Message&) = delete;
};

/**
 * Provides a pool allocator for Message objects.
 *
 * This class is thread-safe.
 */
class MessagePool {
  public:
    MessagePool();
    ~MessagePool() {}

    Message* construct(Protocol::MessageId msgId, uint16_t dataHeaderLength,
                       Driver* driver);
    void destroy(Message* message);

  private:
    /// Monitor style lock for the pool.
    SpinLock mutex;

    /// Actual memory allocator for Message objects.
    ObjectPool<Message> pool;

    MessagePool(const MessagePool&) = delete;
    MessagePool& operator=(const MessagePool&) = delete;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_MESSAGE_H