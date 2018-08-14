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

#include <Homa/Homa.h>

#include "MessageContext.h"
#include "TransportImpl.h"

namespace Homa {

Message::Message()
    : context(nullptr)
    , transportImpl(nullptr)
{}

Message::Message(Message&& other)
    : context(std::move(other.context))
    , transportImpl(std::move(other.transportImpl))
{
    other.context = nullptr;
    other.transportImpl = nullptr;
}

Message::~Message()
{
    if (context != nullptr) {
        context->release();
    }
}

Message&
Message::operator=(Message&& other)
{
    context = std::move(other.context);
    transportImpl = std::move(other.transportImpl);
    other.context = nullptr;
    other.transportImpl = nullptr;
    return *this;
}

Message::operator bool() const
{
    if (context != nullptr) {
        return true;
    } else {
        return false;
    }
}

void
Message::append(const void* source, uint32_t num)
{
    uint32_t offset = context->messageLength;
    set(offset, source, num);
}

uint32_t
Message::get(uint32_t offset, void* destination, uint32_t num) const
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
Message::set(uint32_t offset, const void* source, uint32_t num)
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
            assert(context->getPacket(packetIndex) != nullptr);
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

    context->messageLength = std::max(context->messageLength, offset + num);
}

Driver::Address*
Message::getAddress() const
{
    return context->address;
}

void
Message::send(SendFlag flags, Message* completes[], uint16_t numCompletes)
{
    transportImpl->sendMessage(this, flags, completes, numCompletes);
}

void
Message::send(Driver::Address* destination, SendFlag flags,
              Message* completes[], uint16_t numCompletes)
{
    context->address = destination;
    transportImpl->sendMessage(this, flags, completes, numCompletes);
}

Transport::Transport(Driver* driver, uint64_t transportId)
    : transportImpl(new Core::TransportImpl(driver, transportId))
{}

Transport::~Transport()
{
    delete transportImpl;
}

Message
Transport::newMessage()
{
    return transportImpl->newMessage();
}

Message
Transport::receiveMessage()
{
    return transportImpl->receiveMessage();
}

Driver::Address*
Transport::getAddress(std::string const* const addressString)
{
    return transportImpl->driver->getAddress(addressString);
}

void
Transport::poll()
{
    transportImpl->poll();
}

}  // namespace Homa