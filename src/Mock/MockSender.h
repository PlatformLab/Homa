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

#ifndef HOMA_MOCK_MOCKSENDER_H
#define HOMA_MOCK_MOCKSENDER_H

#include <gmock/gmock.h>

#include "Sender.h"

namespace Homa {
namespace Mock {

/**
 * MockSender is a gmock supported mock implementation of Homa::Core::Sender
 * that is used in unit testing.
 *
 * @sa Sender
 */
class MockSender : public Core::Sender {
  public:
    MockSender(uint64_t transportId, Driver* driver,
               uint64_t messageTimeoutCycles, uint64_t pingIntervalCycles)
        : Sender(transportId, driver, nullptr, messageTimeoutCycles,
                 pingIntervalCycles)
    {}

    MOCK_METHOD(Homa::OutMessage*, allocMessage, (uint16_t sport), (override));
    MOCK_METHOD(void, handleDonePacket, (Driver::Packet * packet), (override));
    MOCK_METHOD(void, handleGrantPacket, (Driver::Packet * packet), (override));
    MOCK_METHOD(void, handleResendPacket, (Driver::Packet * packet),
                (override));
    MOCK_METHOD(void, handleUnknownPacket, (Driver::Packet * packet),
                (override));
    MOCK_METHOD(void, handleErrorPacket, (Driver::Packet * packet), (override));
    MOCK_METHOD(void, poll, (), (override));
    MOCK_METHOD(void, checkTimeouts, (), (override));
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKSENDER_H
