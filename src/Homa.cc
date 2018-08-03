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

#include "Homa.h"

#include "MessageContext.h"

#include <algorithm>

namespace Homa {
Transport::Message::Message()
    : context(nullptr)
{}

Transport::Message::~Message()
{
    if (context != nullptr) {
        context->release();
    }
}

Transport::Message::operator bool()
{
    if (context != nullptr) {
        return true;
    } else {
        return false;
    }
}

void
Transport::Message::append(const void* source, uint32_t num)
{
    uint32_t offset = context->messageLength;
    set(offset, source, num);
}

uint32_t
Transport::Message::get(uint32_t offset, void* destination, uint32_t num)
{
    uint16_t packetIndex = offset / context->PACKET_DATA_LENGTH;
    uint16_t packetOffset = offset % context->PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;
    if (offset + num > context->messageLength) {
        num = context->messageLength - offset;
    }
    while (bytesCopied < num) {
        uint16_t rawOffset = context->DATA_HEADER_LENGTH + packetOffset;
        char* source =
            static_cast<char*>(context->getPacket(packetIndex)->payload);
        source += rawOffset;
        uint16_t bytesToCopy =
            std::min(Util::downCast<uint16_t>(num - bytesCopied),
                     context->PACKET_DATA_LENGTH);
        std::memcpy(destination, source, bytesToCopy);
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
    return bytesCopied;
}

void
Transport::Message::set(uint32_t offset, const void* source, uint32_t num)
{
    uint16_t packetIndex = offset / context->PACKET_DATA_LENGTH;
    uint16_t packetOffset = offset % context->PACKET_DATA_LENGTH;
    uint32_t bytesCopied = 0;
    uint32_t maxMessageLength =
        context->PACKET_DATA_LENGTH * context->MAX_MESSAGE_PACKETS;
    if (offset + num > maxMessageLength) {
        LOG(ERROR,
            "Max message size limit (%uB) reached; "
            "trying to set bytes %u - %u; "
            "message will be truncated",
            maxMessageLength, offset, offset + num - 1);
        num = maxMessageLength - offset;
    }

    while (bytesCopied < num) {
        Driver::Packet* packet = context->getPacket(packetIndex);
        if (packet == nullptr) {
            packet = context->driver->allocPacket();
            bool ret = context->setPacket(packetIndex, packet);
            assert(ret);
            assert(packet->len == 0);
            assert(packet->getMaxPayloadSize() >=
                   context->DATA_HEADER_LENGTH + context->PACKET_DATA_LENGTH);
        }

        uint16_t rawOffset = context->DATA_HEADER_LENGTH + packetOffset;
        char* destination = static_cast<char*>(packet->payload);
        destination += rawOffset;
        uint16_t bytesToCopy =
            std::min(Util::downCast<uint16_t>(num - bytesCopied),
                     context->PACKET_DATA_LENGTH);
        std::memcpy(destination, source, bytesToCopy);
        packet->len = std::max(
            packet->len, Util::downCast<uint16_t>(bytesToCopy + rawOffset));
        bytesCopied += bytesToCopy;
        packetIndex++;
        packetOffset = 0;
    }
}

Driver::Address*
Transport::Message::getAddress()
{
    return context->address;
}

void
Transport::Message::setDestination(Driver::Address* destination)
{
    context->address = destination;
}

}  // namespace Homa