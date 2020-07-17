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

#include "Policy.h"

#include <iterator>

namespace Homa {
namespace Core {
namespace Policy {

/**
 * Contains the default policy configuration information that is used when no
 * other policy is specified.
 */
namespace Default {
// Set to the policy configuration used to run homa+dpdk W3 in the Homa paper.
const uint32_t RTT_TIME_US = 8;
const uint32_t UNSCHEDULED_PRIORITY_CUTOFFS[] = {469, 5521, 15267};
const int MAX_OVERCOMMIT_COUNT = 4;
}  // namespace Default

/**
 * Construct a Policy::Manager.
 *
 * @param transport
 *      The transport that owns this Policy::Manager.
 */
Manager::Manager(Driver* driver)
    : mutex()
    , driver(driver)
    , localUnscheduledPolicy()
    , localScheduledPolicy()
    , peerPolicies()
    , RTT_BYTES(Default::RTT_TIME_US * (driver->getBandwidth() / 8))
    , MAX_PRIORITY(driver->getHighestPacketPriority())
{
    // Set default unschedule policy
    localUnscheduledPolicy.version = 0;
    localUnscheduledPolicy.highestPriority = MAX_PRIORITY;
    localUnscheduledPolicy.priorityCutoffBytes =
        std::vector<uint32_t>(std::begin(Default::UNSCHEDULED_PRIORITY_CUTOFFS),
                              std::end(Default::UNSCHEDULED_PRIORITY_CUTOFFS));

    // Set default scheduled policy
    localScheduledPolicy.maxScheduledPriority = std::max(
        0, MAX_PRIORITY -
               Util::downCast<int>(
                   localUnscheduledPolicy.priorityCutoffBytes.size() + 1));
    localScheduledPolicy.degreeOvercommitment = Default::MAX_OVERCOMMIT_COUNT;
    localScheduledPolicy.minScheduledBytes = RTT_BYTES;
    localScheduledPolicy.maxScheduledBytes = 2 * RTT_BYTES;
}

/**
 * Return the network priority that should be used for resent packets
 * (i.e. packets that were lost and need to be resent).
 */
int
Manager::getResendPriority()
{
    return MAX_PRIORITY;
}

/**
 * Returns the highest priority that should be used for scheduled (granted)
 * messages and the number of messages that should be concurrently granted.
 *
 * Used by Receiver to set granted message priorities.
 *
 * @sa Policy::Scheduled
 */
Scheduled
Manager::getScheduledPolicy()
{
    SpinLock::Lock lock(mutex);
    return localScheduledPolicy;
}

/**
 * Get the unscheduled byte limit and network priority for a message of a
 * particular size bound for a particular peer.
 *
 * Used by the Sender to decided the initial priority and number of
 * unilaterally "granted" (unscheduled) bytes for a new Message to be sent.
 *
 * @param destination
 *      The policy for the Transport at this IpAddress will be returned.
 * @param messageLength
 *      The policy for message containing this many bytes will be returned.
 *
 * @sa Policy::Unscheduled
 */
Unscheduled
Manager::getUnscheduledPolicy(const IpAddress destination,
                              const uint32_t messageLength)
{
    SpinLock::Lock lock(mutex);
    Unscheduled policy;
    auto ret = peerPolicies.insert({destination, UnscheduledPolicy()});
    UnscheduledPolicy* peer = &ret.first->second;
    bool inserted = ret.second;
    if (inserted) {
        // No existing peer policy; set policy to the default.
        peer->version = 0;
        peer->highestPriority = MAX_PRIORITY;
        peer->priorityCutoffBytes = std::vector<uint32_t>(
            std::begin(Default::UNSCHEDULED_PRIORITY_CUTOFFS),
            std::end(Default::UNSCHEDULED_PRIORITY_CUTOFFS));
    }
    policy.version = peer->version;
    policy.unscheduledByteLimit = RTT_BYTES;
    int rank = 0;
    int numCutoffs = peer->priorityCutoffBytes.size();
    for (; rank < numCutoffs; ++rank) {
        if (messageLength < peer->priorityCutoffBytes.at(rank)) {
            break;
        }
    }
    policy.priority = std::max(0, peer->highestPriority - rank);
    return policy;
}

/**
 * Record statistics about a new incoming Message that are used to recalculate
 * this Transport's unscheduled and scheduled policies.
 *
 * Called by the Receiver when a new Message has started to arrive.
 *
 * @param source
 *      IpAddress of the Transport from which the new Message was received.
 * @param policyVersion
 *      Version of the policy the Sender used when sending the Message.
 * @param messageLength
 *      Number of bytes the new incoming Message contains.
 */
void
Manager::signalNewMessage(const IpAddress source, uint8_t policyVersion,
                          uint32_t messageLength)
{
    SpinLock::Lock lock(mutex);
    (void)source;
    (void)policyVersion;
    (void)messageLength;
    // TODO(cstlee): Collect statistics
}

/**
 * Allow the Manager to perform periodic background tasks like managing and
 * updating the policy.
 */
void
Manager::poll()
{
    SpinLock::Lock lock(mutex);
    // TODO(cstlee): Add policy update logic
}

}  // namespace Policy
}  // namespace Core
}  // namespace Homa
