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

#include "Message.h"

#include <mutex>

namespace Homa {
namespace Core {

/**
 * Construct a Message.
 *
 * Message objects are constructed with a refCount of 1.
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
 *
 * @sa Message::release()
 */
Message::Message(Protocol::MessageId msgId, uint16_t dataHeaderLength,
                 Driver* driver)
    : msgId(msgId)
    , address(nullptr)
    , driver(driver)
    , messageLength(0)
    , PACKET_DATA_LENGTH(driver->getMaxPayloadSize() - dataHeaderLength)
    , DATA_HEADER_LENGTH(dataHeaderLength)
    , numPackets(0)
    , occupied()
    , packets()
{}

/**
 * Destruct a Message. Will release all contained Packet objects.
 */
Message::~Message()
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
 * @copydoc Homa::Message::append()
 */
void
Message::append(const void* source, uint32_t num)
{
    uint32_t offset = messageLength;
    set(offset, source, num);
}

/**
 * @copydoc Homa::Message::get()
 */
uint32_t
Message::get(uint32_t offset, void* destination, uint32_t num) const
{
    uint32_t packetIndex = offset / PACKET_DATA_LENGTH;
    uint32_t packetOffset = offset % PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;

    // Offset is passed the end of the message.
    if (offset >= messageLength) {
        return 0;
    }

    if (offset + num > messageLength) {
        num = messageLength - offset;
    }

    while (bytesCopied < num) {
        Driver::Packet* packet = getPacket(packetIndex);
        if (packet == nullptr) {
            WARNING(
                "Copy cut short; message (%lu:%lu) of length %uB has no "
                "packet at offset %u (index %u)",
                msgId.transportId, msgId.sequence, messageLength,
                packetIndex * PACKET_DATA_LENGTH, packetIndex);
            break;
        }
        char* source = static_cast<char*>(packet->payload);
        source += packetOffset + DATA_HEADER_LENGTH;
        uint32_t bytesToCopy =
            std::min(num - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        std::memcpy(static_cast<char*>(destination) + bytesCopied, source,
                    bytesToCopy);
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
    return bytesCopied;
}

/**
 * @copydoc Homa::Message::set()
 */
void
Message::set(uint32_t offset, const void* source, uint32_t num)
{
    uint32_t packetIndex = offset / PACKET_DATA_LENGTH;
    uint32_t packetOffset = offset % PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;
    uint32_t maxMessageLength = PACKET_DATA_LENGTH * MAX_MESSAGE_PACKETS;
    // Offset is passed the end of the max length.
    if (offset >= maxMessageLength) {
        return;
    }

    if (offset + num > maxMessageLength) {
        ERROR(
            "Max message size limit (%uB) reached; "
            "trying to set bytes %u - %u; "
            "message will be truncated",
            maxMessageLength, offset, offset + num - 1);
        num = maxMessageLength - offset;
    }

    while (bytesCopied < num) {
        Driver::Packet* packet = getPacket(packetIndex);
        if (packet == nullptr) {
            packet = driver->allocPacket();
            bool ret = setPacket(packetIndex, packet);
            assert(ret);
            assert(packet->length == 0);
            assert(packet->getMaxPayloadSize() >=
                   DATA_HEADER_LENGTH + PACKET_DATA_LENGTH);
            assert(getPacket(packetIndex) != nullptr);
        }

        char* destination = static_cast<char*>(packet->payload);
        destination += packetOffset + DATA_HEADER_LENGTH;
        uint32_t bytesToCopy =
            std::min(num - bytesCopied, PACKET_DATA_LENGTH - packetOffset);
        std::memcpy(destination, static_cast<const char*>(source) + bytesCopied,
                    bytesToCopy);
        packet->length =
            std::max(packet->length,
                     Util::downCast<uint16_t>(bytesToCopy + packetOffset +
                                              DATA_HEADER_LENGTH));
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }

    messageLength = std::max(messageLength, offset + num);
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
uint16_t
Message::getNumPackets() const
{
    return numPackets;
}

}  // namespace Core
}  // namespace Homa