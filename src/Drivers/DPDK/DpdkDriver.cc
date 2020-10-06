/* Copyright (c) 2020, Stanford University
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

#include <Homa/Drivers/DPDK/DpdkDriver.h>

#include "DpdkDriverImpl.h"

namespace Homa {
namespace Drivers {
namespace DPDK {

DpdkDriver::DpdkDriver(const char* ifname, const Config* const config)
    : pImpl(new Impl(ifname, config))
{}

DpdkDriver::DpdkDriver(const char* ifname, int argc, char* argv[],
                       const Config* const config)
    : pImpl(new Impl(ifname, argc, argv, config))
{}

DpdkDriver::DpdkDriver(const char* ifname, NoEalInit _,
                       const Config* const config)
    : pImpl(new Impl(ifname, _, config))
{}

DpdkDriver::~DpdkDriver() = default;

/// See Driver::allocPacket()
Driver::Packet*
DpdkDriver::allocPacket()
{
    return pImpl->allocPacket();
}

/// See Driver::sendPacket()
void
DpdkDriver::sendPacket(Packet* packet, IpAddress destination, int priority)
{
    return pImpl->sendPacket(packet, destination, priority);
}

/// See Driver::cork()
void
DpdkDriver::cork()
{
    pImpl->cork();
}

/// See Driver::uncork()
void
DpdkDriver::uncork()
{
    pImpl->uncork();
}

/// See Driver::receivePackets()
uint32_t
DpdkDriver::receivePackets(uint32_t maxPackets, Packet* receivedPackets[],
                           IpAddress sourceAddresses[])
{
    return pImpl->receivePackets(maxPackets, receivedPackets, sourceAddresses);
}
/// See Driver::releasePackets()
void
DpdkDriver::releasePackets(Packet* packets[], uint16_t numPackets)
{
    pImpl->releasePackets(packets, numPackets);
}

/// See Driver::getHighestPacketPriority()
int
DpdkDriver::getHighestPacketPriority()
{
    return pImpl->getHighestPacketPriority();
}

/// See Driver::getMaxPayloadSize()
uint32_t
DpdkDriver::getMaxPayloadSize()
{
    return pImpl->getMaxPayloadSize();
}

/// See Driver::getBandwidth()
uint32_t
DpdkDriver::getBandwidth()
{
    return pImpl->getBandwidth();
}

/// See Driver::getLocalAddress()
IpAddress
DpdkDriver::getLocalAddress()
{
    return pImpl->getLocalAddress();
}

/// See Driver::getQueuedBytes();
uint32_t
DpdkDriver::getQueuedBytes()
{
    return pImpl->getQueuedBytes();
}

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa
