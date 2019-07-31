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

#ifndef HOMA_CORE_POLICY_H
#define HOMA_CORE_POLICY_H

#include <cstdint>

#include <Homa/Driver.h>

#include "SpinLock.h"

namespace Homa {
namespace Core {
// Forward declaration.
class Transport;

/**
 * Contains the structures and classes related to Homa's policy for setting
 * network packet priority.
 */
namespace Policy {

/**
 * Holds the result of a Policy::Manager::getUnscheduledPolicy() query.
 */
struct Unscheduled {
    /// Version of the policy that resulted in this decision.
    uint8_t version;
    /// Number of bytes that can be sent without grants.
    uint32_t unscheduledByteLimit;
    /// Priority at which the queried message should be initially sent.
    int priority;
};

/**
 * Holds the results of a Policy::Manger::getScheduledPolicy()
 */
struct Scheduled {
    /// Highest priority that should be used for scheduled message.
    int maxScheduledPriority;
    /// Number of messages that can be granted concurrently.  This number should
    /// always at least be as large as the number of scheduled priority levels
    /// (> maxScheduledPriority).
    int degreeOvercommitment;
    /// Number of bytes that should be granted to a scheduled message.
    uint32_t scheduledByteLimit;
};

/**
 * Maintains the current Homa network priority policies for each of peered
 * Homa::Transport on the network.
 *
 * This class is thread-safe.
 */
class Manager {
  public:
    explicit Manager(Driver* driver);
    virtual ~Manager() = default;
    virtual int getResendPriority();
    virtual Scheduled getScheduledPolicy();
    virtual Unscheduled getUnscheduledPolicy(const Driver::Address destination,
                                             const uint32_t messageLength);
    virtual void signalNewMessage(const Driver::Address source,
                                  uint8_t policyVersion,
                                  uint32_t messageLength);
    virtual void poll();

  private:
    /// Monitor-style lock
    SpinLock mutex;
    /// Driver used by the Transport that owns this Manager.
    Driver* const driver;
};

}  // namespace Policy
}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_POLICY_H
