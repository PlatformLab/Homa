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

#ifndef HOMA_MOCK_MOCKPOLICY_H
#define HOMA_MOCK_MOCKPOLICY_H

#include <gmock/gmock.h>

#include "Policy.h"

namespace Homa {
namespace Mock {

/**
 * MockPolicyManger is a gmock supported mock implementation of
 * Homa::Policy::Manager that is used in unit testing.
 */
class MockPolicyManager : public Core::Policy::Manager {
  public:
    explicit MockPolicyManager(Driver* driver)
        : Core::Policy::Manager(driver)
    {}

    MOCK_METHOD0(getResendPriority, int());
    MOCK_METHOD0(getScheduledPolicy, Core::Policy::Scheduled());
    MOCK_METHOD2(getUnscheduledPolicy,
                 Core::Policy::Unscheduled(const IpAddress destination,
                                           const uint32_t messageLength));
    MOCK_METHOD3(signalNewMessage,
                 void(const IpAddress source, uint8_t policyVersion,
                      uint32_t messageLength));
    MOCK_METHOD0(poll, void());
};

}  // namespace Mock
}  // namespace Homa

#endif  // HOMA_MOCK_MOCKPOLICY_H
