/* Copyright (c) 2019-2020, Stanford University
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

#ifndef HOMA_CORE_CONTROLPACKET_H
#define HOMA_CORE_CONTROLPACKET_H

#include <Homa/Driver.h>

#include "Perf.h"

namespace Homa {
namespace Core {
namespace ControlPacket {

/**
 * Send a packet of the given type.  Helper function used to other modules to
 * send various control packets.
 *
 * @param driver
 *      Driver with which to send the packet.
 * @param address
 *      Destination IP address for the packet to be sent.
 * @param args
 *      Arguments to PacketHeaderType's constructor.
 */
template <typename PacketHeaderType, typename... Args>
void
send(Driver* driver, IpAddress address, Args&&... args)
{
    Driver::Packet* packet = driver->allocPacket();
    new (packet->payload) PacketHeaderType(static_cast<Args&&>(args)...);
    packet->length = sizeof(PacketHeaderType);
    Perf::counters.tx_bytes.add(packet->length);
    driver->sendPacket(packet, address, driver->getHighestPacketPriority());
    driver->releasePackets(&packet, 1);
}

}  // namespace ControlPacket
}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_CONTROLPACKET_H
