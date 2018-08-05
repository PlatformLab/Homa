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
#include "Protocol.h"
#include "Receiver.h"
#include "Scheduler.h"
#include "Sender.h"

#include <algorithm>
#include <utility>

namespace Homa {
Transport::Message::Message()
    : context(nullptr)
{}

Transport::Message::Message(Transport::Message&& other)
    : context(std::move(other.context))
{
    other.context = nullptr;
}

Transport::Message::~Message()
{
    if (context != nullptr) {
        context->release();
    }
}

Transport::Message&
Transport::Message::operator=(Transport::Message&& other)
{
    context = std::move(other.context);
    other.context = nullptr;
    return *this;
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
Transport::Message::getAddress()
{
    return context->address;
}

void
Transport::Message::setDestination(Driver::Address* destination)
{
    context->address = destination;
}

Transport::Transport(Driver* driver, uint64_t transportId)
    : driver(driver)
    , messagePool(new Core::MessagePool())
    , sender(new Core::Sender())
    , scheduler(new Core::Scheduler(driver))
    , receiver(new Core::Receiver(scheduler, messagePool))
    , transportId(transportId)
    , nextMessgeId(1)
{}

Transport::~Transport()
{
    if (receiver != nullptr)
        delete receiver;
    if (scheduler != nullptr)
        delete scheduler;
    if (sender != nullptr)
        delete sender;
    if (messagePool != nullptr)
        delete messagePool;
}

Transport::Message
Transport::newMessage()
{
    Transport::Message message;
    message.context = messagePool->construct(
        Protocol::MessageId(transportId, nextMessgeId.fetch_add(1)),
        sizeof(Protocol::DataHeader), driver);
    return std::move(message);
}

Transport::Message
Transport::receiveMessage()
{
    Transport::Message message;
    message.context = receiver->receiveMessage();
    return std::move(message);
}

void
Transport::sendMessage(Message* message, SendFlag flags, Message* completes[],
                       uint16_t numCompletes)
{
    // TODO(cstlee): actually use the flags and completes
    sender->sendMessage(message->context);
}

void
Transport::poll()
{
    const int MAX_BURST = 32;
    Driver::Packet* packets[MAX_BURST];
    int numPackets = driver->receivePackets(MAX_BURST, packets);
    for (int i = 0; i < numPackets; ++i) {
        Driver::Packet* packet = packets[i];
        assert(packet->len >= sizeof(Protocol::CommonHeader));
        Protocol::CommonHeader* header =
            static_cast<Protocol::CommonHeader*>(packet->payload);

        switch (header->opcode) {
            case Protocol::DATA:
                LOG(DEBUG, "Handle DataPacket");
                receiver->handleDataPacket(packet, driver);
                break;
            case Protocol::GRANT:
                LOG(DEBUG, "Handle GrantPacket");
                sender->handleGrantPacket(packet, driver);
                break;
        }
    }
    sender->poll();
    receiver->poll();
}

}  // namespace Homa