/* Copyright (c) 2018-2019, Stanford University
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

#include "Homa/Drivers/DPDK/DpdkDriver.h"

#include "DpdkDriverImpl.h"

namespace Homa {
namespace Drivers {
namespace DPDK {

DpdkDriver::DpdkDriver(int port)
    : impl(new DpdkDriverImpl(port))
{}

DpdkDriver::DpdkDriver(int port, int argc, char* argv[])
    : impl(new DpdkDriverImpl(port, argc, argv))
{}

DpdkDriver::DpdkDriver(int port, DpdkDriver::NoEalInit)
    : impl(new DpdkDriverImpl(port, DpdkDriverImpl::NO_EAL_INIT))
{}

Driver::Address*
DpdkDriver::getAddress(std::string const* const addressString)
{
    return impl->getAddress(addressString);
}

Driver::Packet*
DpdkDriver::allocPacket()
{
    return impl->allocPacket();
}

void
DpdkDriver::sendPackets(Packet* packets[], uint16_t numPackets)
{
    impl->sendPackets(packets, numPackets);
}

uint32_t
DpdkDriver::receivePackets(uint32_t maxPackets, Packet* receivedPackets[])
{
    return impl->receivePackets(maxPackets, receivedPackets);
}

void
DpdkDriver::releasePackets(Packet* packets[], uint16_t numPackets)
{
    impl->releasePackets(packets, numPackets);
}

int
DpdkDriver::getHighestPacketPriority()
{
    return impl->getHighestPacketPriority();
}

uint32_t
DpdkDriver::getMaxPayloadSize()
{
    return impl->getMaxPayloadSize();
}

uint32_t
DpdkDriver::getBandwidth()
{
    return impl->getBandwidth();
}

Driver::Address*
DpdkDriver::getLocalAddress()
{
    return impl->getLocalAddress();
}

void
DpdkDriver::setLocalAddress(std::string const* const addressString)
{
    impl->setLocalAddress(addressString);
}

}  // namespace DPDK
}  // namespace Drivers
}  // namespace Homa
