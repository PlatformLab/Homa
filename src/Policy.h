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

#ifndef HOMA_CORE_POLICY_H
#define HOMA_CORE_POLICY_H

#include <Homa/Driver.h>

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "SpinLock.h"

namespace Homa {
namespace Core {

/**
 * Contains the structures and classes related to Homa's policy for setting
 * network packet priorities.
 */
namespace Policy {

/**
 * Holds the result of a Policy::Manager::getUnscheduledPolicy() query; used to
 * return multiple values.
 */
struct Unscheduled {
    /// Identifies the version of a peer transport's policy that is in use.
    uint8_t version;
    /// Number of bytes that can be sent without grants.
    uint32_t unscheduledByteLimit;
    /// Priority at which the queried message should be initially sent.
    int priority;
};

/**
 * Holds the results of a Policy::Manger::getScheduledPolicy(); used to return
 * multiple values.
 */
struct Scheduled {
    /// Highest priority that should be used for scheduled message.
    int maxScheduledPriority;
    /// Number of messages that can be granted concurrently.  This number should
    /// always at least be as large as the number of scheduled priority levels
    /// (> maxScheduledPriority).
    int degreeOvercommitment;
    /// Minimum number of granted but unreceived bytes.
    int minScheduledBytes;
    /// Maximum number of granted but unreceived bytes.
    int maxScheduledBytes;
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
    virtual Unscheduled getUnscheduledPolicy(const IpAddress destination,
                                             const uint32_t messageLength);
    virtual void signalNewMessage(const IpAddress source, uint8_t policyVersion,
                                  uint32_t messageLength);
    virtual void poll();

  private:
    /**
     * Holds the known network priority policy for a particular Homa::Transport
     * on the network.
     */
    struct UnscheduledPolicy {
        /// The version number of this policy.
        uint8_t version;
        /// The highest network priority that should be used for the unscheduled
        /// bytes of a message.
        int highestPriority;
        /// The number of bytes below which a particular network priority should
        /// be used.
        std::vector<uint32_t> priorityCutoffBytes;
    };

    /// Monitor-style lock
    SpinLock mutex;
    /// Driver used by the Transport that owns this Manager.
    Driver* const driver;
    /// The unscheduled policy for the Transport that owns this Policy::Manager.
    UnscheduledPolicy localUnscheduledPolicy;
    /// The scheduled policy for the Transport that owns this Policy::Manager.
    Scheduled localScheduledPolicy;
    /// Collection of the known Policies for each peered Homa::Transport;
    std::unordered_map<IpAddress, UnscheduledPolicy, IpAddress::Hasher>
        peerPolicies;
    /// Number of bytes that can be transmitted in one round-trip-time.
    const uint32_t RTT_BYTES;
    /// The highest network packet priority that the driver supports.
    const int MAX_PRIORITY;
};

}  // namespace Policy
}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_POLICY_H
