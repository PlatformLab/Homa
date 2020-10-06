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

#ifndef HOMA_MOCK_MOCKDRIVER_H
#define HOMA_MOCK_MOCKDRIVER_H

#include <Homa/Driver.h>
#include <gmock/gmock.h>

namespace Homa {
namespace Mock {

/**
 * MockDriver is a gmock supported mock driver implementation that is used
 * in unit testing.
 *
 * @sa Driver
 */
class MockDriver : public Driver {
  public:
    /**
     * Used in unit tests to mock calls to Driver::Packet.
     *
     * @sa Driver::Packet.
     */
    using MockPacket = Driver::Packet;

    MOCK_METHOD(Packet*, allocPacket, (), (override));
    MOCK_METHOD(void, sendPacket,
                (Packet * packet, IpAddress destination, int priority),
                (override));
    MOCK_METHOD(void, flushPackets, ());
    MOCK_METHOD(uint32_t, receivePackets,
                (uint32_t maxPackets, Packet* receivedPackets[],
                 IpAddress sourceAddresses[]),
                (override));
    MOCK_METHOD(void, releasePackets, (Packet * packets[], uint16_t numPackets),
                (override));
    MOCK_METHOD(int, getHighestPacketPriority, (), (override));
    MOCK_METHOD(uint32_t, getMaxPayloadSize, (), (override));
    MOCK_METHOD(uint32_t, getBandwidth, (), (override));
    MOCK_METHOD(IpAddress, getLocalAddress, (), (override));
    MOCK_METHOD(uint32_t, getQueuedBytes, (), (override));
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKDRIVER_H
