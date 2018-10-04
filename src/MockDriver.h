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

#ifndef HOMA_MOCKDRIVER_H
#define HOMA_MOCKDRIVER_H

#include <gmock/gmock.h>

#include <Homa/Driver.h>

namespace Homa {

/**
 * MockDriver is a gmock supported mock driver implmentation that is used
 * in unit testing.
 *
 * @sa Driver
 */
class MockDriver : public Driver {
  public:
    /**
     * Used in unit test to mock calls to Driver::Address.
     *
     * @sa Driver::Address
     */
    class MockAddress : public Driver::Address {
      public:
        MOCK_CONST_METHOD0(toString, std::string());
    };

    /**
     * Used in unit tests to mock calls to Driver::Packet.
     *
     * @sa Driver::Packet.
     */
    class MockPacket : public Driver::Packet {
      public:
        MockPacket(void* payload, uint16_t len)
            : Packet(payload, len)
        {}

        MOCK_METHOD0(getMaxPayloadSize, uint16_t());
    };

    MOCK_METHOD1(getAddress, Address*(std::string const* const addressString));
    MOCK_METHOD0(allocPacket, Packet*());
    MOCK_METHOD2(sendPackets, void(Packet* packets[], uint16_t numPackets));
    MOCK_METHOD2(receivePackets,
                 uint32_t(uint32_t maxPackets, Packet* receivedPackets[]));
    MOCK_METHOD2(releasePackets, void(Packet* packets[], uint16_t numPackets));
    MOCK_METHOD0(getHighestPacketPriority, int());
    MOCK_METHOD0(getMaxPayloadSize, uint32_t());
    MOCK_METHOD0(getBandwidth, uint32_t());
    MOCK_METHOD0(getLocalAddress, Address*());
};

}  // namespace Homa

#endif  // HOMA_MOCKDRIVER_H
