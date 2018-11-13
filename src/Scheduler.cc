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

#include "Scheduler.h"

namespace Homa {
namespace Core {

namespace {
const uint32_t RTT_TIME_US = 5;
}

/**
 * Constructor for the Scheduler.
 *
 * @param driver
 *      Pointer to a driver that can be used to send packets.
 */
Scheduler::Scheduler(Driver* driver)
    : driver(driver)
    , RTT_BYTES(RTT_TIME_US * (driver->getBandwidth() / 8))
{}

/**
 * Inform the Scheduler that a packet for a given Message has been received.
 *
 * Called by the Homa::Core::Receiver when a new packet is received.
 *
 * @param msgId
 *      Id of the Message that the received packet is a part of.
 * @param sourceAddr
 *      Network address of the Transport from which the packet was sent.
 *      Grants will be sent back to this address.
 * @param totalMessageLength
 *      Total number of bytes the Message is expected to contain.
 * @param totalBytesReceived
 *      Total number of bytes of the Message received so far.
 */
void
Scheduler::packetReceived(Protocol::MessageId msgId,
                          Driver::Address* sourceAddr,
                          uint32_t totalMessageLength,
                          uint32_t totalBytesReceived)
{
    // TODO(cstlee): Implement Homa's grant policy.
    (void)totalMessageLength;
    // Implements a very simple grant policy which tries to maintain RTT bytes
    // granted for every Message.
    // TODO(cstlee): Add safe guards to prevent RTT_BYTES from being less than
    //               a single packet length. The sender might get stuck if the
    //               grants are smaller than a single packet.
    uint32_t offset = totalBytesReceived + RTT_BYTES;

    Driver::Packet* packet = driver->allocPacket();
    new (packet->payload) Protocol::GrantHeader(msgId, offset);
    packet->length = sizeof(Protocol::GrantHeader);
    packet->address = sourceAddr;
    driver->sendPackets(&packet, 1);
    driver->releasePackets(&packet, 1);
}

}  // namespace Core
}  // namespace Homa