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

#ifndef HOMA_MOCK_MOCKSCHEDULER_H
#define HOMA_MOCK_MOCKSCHEDULER_H

#include <gmock/gmock.h>

#include "Scheduler.h"

namespace Homa {
namespace Mock {

/**
 * MockScheduler is a gmock supported mock implementation of
 * Homa::Core::Scheduler that is used in unit testing.
 *
 * @sa Scheduler
 */
class MockScheduler : public Core::Scheduler {
  public:
    MockScheduler(Driver* driver)
        : Scheduler(driver)
    {}

    MOCK_METHOD4(packetReceived,
                 void(Protocol::MessageId msgId, Driver::Address* sourceAddr,
                      uint32_t totalMessageLength,
                      uint32_t totalBytesReceived));
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKSCHEDULER_H
