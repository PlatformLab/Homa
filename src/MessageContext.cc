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

#include "MessageContext.h"

#include <mutex>

namespace Homa {
namespace Core {

/**
 * Construct a MessageContext.
 *
 * MessageContext objects are constructed with a refCount of 1.
 *
 * @param msgId
 *      Unique identifier for this message.
 * @param dataHeaderLength
 *      Number of bytes at the beginning of every packet used to hold the Homa
 *      protocol DataHeader. This should be the same for every packet in a given
 *      message, but may be different for different messages since they may use
 *      different versions of the protocol header.
 * @param driver
 *      Driver from which packets were/will be allocated and to which they
 *      should be returned when this message is no longer needed.
 * @param messagePool
 *      Pool from which this MessageContext was allocated and to which it should
 *      be returned on destruction.
 *
 * @sa MessageContext::release()
 */
MessageContext::MessageContext(Protocol::MessageId msgId,
                               uint16_t dataHeaderLength, Driver* driver,
                               MessagePool* messagePool)
    : msgId(msgId)
    , address(nullptr)
    , driver(driver)
    , messageLength(0)
    , PACKET_DATA_LENGTH(driver->getMaxPayloadSize() - dataHeaderLength)
    , DATA_HEADER_LENGTH(dataHeaderLength)
    , messagePool(messagePool)
    , refCount(1)
    , numPackets(0)
    , occupied()
    , packets()
{}

/**
 * Destruct a MessageContext. Will release all contained Packet objects.
 */
MessageContext::~MessageContext()
{
    // If the packets are all continguous, we can release them all at once.
    if ((occupied >> numPackets).none()) {
        driver->releasePackets(packets, numPackets);
    } else {  // otherwise, we need to find which packets need to be released.
        for (uint16_t i = 0; i < MAX_MESSAGE_PACKETS && numPackets > 0; ++i) {
            if (occupied.test(i)) {
                driver->releasePackets(packets + i, 1);
                --numPackets;
            }
        }
    }
}

/**
 * Return the Packet with the given index.
 *
 * @param index
 *      A Packet's index in the array of packets that form the message.
 *      "packet index = "packet message offset" / PACKET_DATA_LENGTH
 * @return
 *      Pointer to a Packet at the given index if it exists; nullptr otherwise.
 */
Driver::Packet*
MessageContext::getPacket(uint16_t index)
{
    if (occupied.test(index)) {
        return packets[index];
    }
    return nullptr;
}

/**
 * Store the given packet as the Packet of the given index if one does not
 * already exist.
 *
 * Responsibly for releasing the given Packet is passed to this context if the
 * Packet is stored (returns true).
 *
 * @param index
 *      The Packet's index in the array of packets that form the message.
 *      "packet index = "packet message offset" / PACKET_DATA_LENGTH
 * @param packet
 *      The packet pointer that should be stored.
 * @return
 *      True if the packet was stored; false if a packet already exists (the new
 *      packet is not stored).
 */
bool
MessageContext::setPacket(uint16_t index, Driver::Packet* packet)
{
    if (occupied.test(index)) {
        return false;
    }
    packets[index] = packet;
    occupied.set(index);
    numPackets++;
    return true;
}

/**
 * Return the number of packet this message currently holds.
 */
uint16_t
MessageContext::getNumPackets()
{
    return numPackets;
}

/**
 * Used by a module to indicate that it would like to retain access to this
 * MessageContext. When the module no longer needs access, it should call
 * MessageContext::release().
 *
 * @sa MessageContext::release()
 */
void
MessageContext::retain()
{
    // if the refCount is 0, something bad happend.
    assert(refCount > 0);
    refCount++;
}

/**
 * Used by a module to indicate it no longer needs access to this MessageContext
 * object. Normally called after previously calling MessageContext::retain().
 *
 * @sa MessageContext::retain()
 */
void
MessageContext::release()
{
    refCount--;
    if (refCount.load() < 1) {
        messagePool->destroy(this);
        // can't do anything after this, the object is destroyed
    }
}

/**
 * MessagePool constructor.
 */
MessagePool::MessagePool()
    : mutex()
    , pool()
{}

/**
 * Construct a new MessageContext object in the pool and return a pointer to it.
 *
 * \sa MessageContext()
 */
MessageContext*
MessagePool::construct(Protocol::MessageId msgId, uint16_t dataHeaderLength,
                       Driver* driver)
{
    std::lock_guard<SpinLock> lock(mutex);
    return pool.construct(msgId, dataHeaderLength, driver, this);
}

/**
 * Destory the given MessageContext object previously allocated by this
 * MessagePool.
 */
void
MessagePool::destroy(MessageContext* messageContext)
{
    std::lock_guard<SpinLock> lock(mutex);
    pool.destroy(messageContext);
}

}  // namespace Core
}  // namespace Homa