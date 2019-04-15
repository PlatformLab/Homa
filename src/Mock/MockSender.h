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
    MOCK_METHOD2(handleDonePacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD2(handleGrantPacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD2(handleResendPacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD2(handleUnknownPacket,
                 void(Driver::Packet* packet, Driver* driver));
    MOCK_METHOD4(sendMessage,
                 void(Protocol::MessageId id, Driver::Address* destination,
                      Core::Transport::Op* op, bool expectAcknowledgement));
    MOCK_METHOD1(dropMessage, void(Core::Transport::Op* op));
    MOCK_METHOD0(poll, void());
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKSENDER_H
