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
    class MockPacket : public Driver::Packet {
      public:
        MockPacket(void* payload, uint16_t length = 0)
            : Packet(payload, length)
        {}

        MOCK_METHOD0(getMaxPayloadSize, int());
    };

    MOCK_METHOD1(getAddress, Address(std::string const* const addressString));
    MOCK_METHOD1(getAddress,
                 Address(WireFormatAddress const* const wireAddress));
    MOCK_METHOD1(addressToString, std::string(Address address));
    MOCK_METHOD2(addressToWireFormat,
                 void(Address address, WireFormatAddress* wireAddress));
    MOCK_METHOD0(allocPacket, Packet*());
    MOCK_METHOD1(sendPacket, void(Packet* packet));
    MOCK_METHOD0(flushPackets, void());
    MOCK_METHOD2(receivePackets,
                 uint32_t(uint32_t maxPackets, Packet* receivedPackets[]));
    MOCK_METHOD2(releasePackets, void(Packet* packets[], uint16_t numPackets));
    MOCK_METHOD0(getHighestPacketPriority, int());
    MOCK_METHOD0(getMaxPayloadSize, uint32_t());
    MOCK_METHOD0(getBandwidth, uint32_t());
    MOCK_METHOD0(getLocalAddress, Address());
    MOCK_METHOD0(getQueuedBytes, uint32_t());
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKDRIVER_H
