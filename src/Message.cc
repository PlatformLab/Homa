/* Copyright (c) 2018-2020, Stanford University
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

#include "Message.h"

#include <mutex>

#include "Debug.h"

namespace Homa {
namespace Core {

/**
 * Construct a Message.
 *
 * @param driver
 *      Driver from which packets were/will be allocated and to which they
 *      should be returned when this message is no longer needed.
 * @param packetHeaderLength
 *      Number of bytes at the beginning of every packet used to hold the Homa
 *      protocol DataHeader. This should be the same for every packet in a given
 *      message, but may be different for different messages since they may use
 *      different versions of the protocol header.
 * @param messageLength
 *      Number of bytes know to be in this Message.  Used by the Receiver since
 *      it should know the length of the Message when the first packet arrives.
 */
Message::Message(Driver* driver, uint16_t packetHeaderLength,
                 uint32_t messageLength)
    : driver(driver)
    , TRANSPORT_HEADER_LENGTH(packetHeaderLength)
    , PACKET_DATA_LENGTH(driver->getMaxPayloadSize() - TRANSPORT_HEADER_LENGTH)
    , start(0)
    , messageLength(messageLength)
    , numPackets(0)
    , occupied()
// packets is not initialized to reduce the work done during construction.
// See Message::occupied.
{}

/**
 * Destruct a Message. Will release all contained Packet objects.
 */
Message::~Message()
{
    driver->releasePackets(packets, numPackets);
}

/**
 * @copydoc Homa::Message::append()
 */
void
Message::append(const void* source, uint32_t count)
{
    uint32_t packetIndex = messageLength / PACKET_DATA_LENGTH;
    uint32_t packetOffset = messageLength % PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;
    uint32_t maxMessageLength = PACKET_DATA_LENGTH * MAX_MESSAGE_PACKETS;

    if (messageLength + count > maxMessageLength) {
        WARNING("Max message size limit (%uB) reached; %u of %u bytes appended",
                maxMessageLength, maxMessageLength - messageLength, count);
        count = maxMessageLength - messageLength;
    }

    while (bytesCopied < count) {
        uint32_t bytesToCopy =
            std::min(count - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getOrAllocPacket(packetIndex);
        char* destination = static_cast<char*>(packet->payload);
        destination += packetOffset + TRANSPORT_HEADER_LENGTH;
        std::memcpy(destination, static_cast<const char*>(source) + bytesCopied,
                    bytesToCopy);
        // TODO(cstlee): A Message probably shouldn't be in charge of setting
        //               the packet length.
        packet->length += bytesToCopy;
        assert(packet->length <= TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH);
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }

    messageLength += count;
}

/**
 * @copydoc Homa::Message::get()
 */
uint32_t
Message::get(uint32_t offset, void* destination, uint32_t count) const
{
    // This operation should be performed with the offset relative to the
    // logical beginning of the Message.
    uint32_t realOffset = offset + start;
    uint32_t packetIndex = realOffset / PACKET_DATA_LENGTH;
    uint32_t packetOffset = realOffset % PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;

    // Offset is passed the end of the message.
    if (realOffset >= messageLength) {
        return 0;
    }

    if (realOffset + count > messageLength) {
        count = messageLength - realOffset;
    }

    while (bytesCopied < count) {
        uint32_t bytesToCopy =
            std::min(count - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getPacket(packetIndex);
        if (packet != nullptr) {
            char* source = static_cast<char*>(packet->payload);
            source += packetOffset + TRANSPORT_HEADER_LENGTH;
            std::memcpy(static_cast<char*>(destination) + bytesCopied, source,
                        bytesToCopy);
        } else {
            ERROR("Message is missing data starting at packet index %u",
                  packetIndex);
            break;
        }
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
    return bytesCopied;
}

/**
 * @copydoc Homa::Message::length()
 */
uint32_t
Message::length() const
{
    return messageLength - start;
}

/**
 * @copydoc Homa::Message::prepend()
 */
void
Message::prepend(const void* source, uint32_t count)
{
    // Make sure there is enough space reserved.
    assert(count <= start);
    start -= count;

    uint32_t packetIndex = start / PACKET_DATA_LENGTH;
    uint32_t packetOffset = start % PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;

    while (bytesCopied < count) {
        uint32_t bytesToCopy =
            std::min(count - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getPacket(packetIndex);
        assert(packet != nullptr);
        char* destination = static_cast<char*>(packet->payload);
        destination += packetOffset + TRANSPORT_HEADER_LENGTH;
        std::memcpy(destination, static_cast<const char*>(source) + bytesCopied,
                    bytesToCopy);
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
}

/**
 * @copydoc Homa::Message::reserve()
 */
void
Message::reserve(uint32_t count)
{
    // Make sure there have been no prior calls to append or prepend.
    assert(start == messageLength);

    uint32_t packetIndex = start / PACKET_DATA_LENGTH;
    uint32_t packetOffset = start % PACKET_DATA_LENGTH;
    uint32_t bytesReserved = 0;
    uint32_t maxMessageLength = PACKET_DATA_LENGTH * MAX_MESSAGE_PACKETS;

    if (start + count > maxMessageLength) {
        WARNING("Max message size limit (%uB) reached; %u of %u bytes reserved",
                maxMessageLength, maxMessageLength - start, count);
        count = maxMessageLength - start;
    }

    while (bytesReserved < count) {
        uint32_t bytesToReserve =
            std::min(count - bytesReserved, PACKET_DATA_LENGTH - packetOffset);
        Driver::Packet* packet = getOrAllocPacket(packetIndex);
        // TODO(cstlee): A Message probably shouldn't be in charge of setting
        //               the packet length.
        packet->length += bytesToReserve;
        assert(packet->length <= TRANSPORT_HEADER_LENGTH + PACKET_DATA_LENGTH);
        bytesReserved += bytesToReserve;
        packetIndex++;
        packetOffset = 0;
    }

    start += count;
    messageLength += count;
}

/**
 * @copydoc Homa::Message::strip()
 */
void
Message::strip(uint32_t count)
{
    start = std::min(start + count, messageLength);
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
Message::getPacket(uint16_t index) const
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
Message::setPacket(uint16_t index, Driver::Packet* packet)
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
int
Message::getNumPackets() const
{
    return numPackets;
}

/**
 * Return the number of bytes this message holds (including the message header).
 */
uint32_t
Message::rawLength() const
{
    return messageLength;
}

/**
 * Return the Packet with the given index.  If the Packet does yet exist,
 * allocate a new Packet.
 *
 * @param index
 *      A Packet's index in the array of packets that form the message.
 *      "packet index = "packet message offset" / PACKET_DATA_LENGTH
 * @return
 *      Pointer to a Packet at the given index.
 */
Driver::Packet*
Message::getOrAllocPacket(uint16_t index)
{
    if (!occupied.test(index)) {
        packets[index] = driver->allocPacket();
        occupied.set(index);
        numPackets++;
        // TODO(cstlee): A Message probably shouldn't be in charge of setting
        //               the packet length.
        packets[index]->length = TRANSPORT_HEADER_LENGTH;
    }
    return packets[index];
}

}  // namespace Core
}  // namespace Homa