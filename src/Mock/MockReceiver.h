/* Copyright (c) 2019, Stanford University
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

#ifndef HOMA_MOCK_MOCKRECEIVER_H
#define HOMA_MOCK_MOCKRECEIVER_H

#include <gmock/gmock.h>

#include "Receiver.h"

namespace Homa {
namespace Mock {

/**
 * MockReceiver is a gmock supported mock implementation of Homa::Core::Receiver
 * that is used in unit testing.
 *
 * @sa Receiver
 */
class MockReceiver : public Core::Receiver {
  public:
    MockReceiver(Core::Transport* transport, uint64_t messageTimeoutCycles,
                 uint64_t resendIntervalCycles)
        : Receiver(transport, nullptr, messageTimeoutCycles,
                   resendIntervalCycles)
    {}

    MOCK_METHOD2(handleDataPacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD2(handleBusyPacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD2(handlePingPacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD0(receiveMessage, Homa::InMessage*());
    MOCK_METHOD0(poll, void());
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKRECEIVER_H
