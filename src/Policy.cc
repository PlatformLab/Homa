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

#include "Policy.h"

#include "Transport.h"

namespace Homa {
namespace Core {
namespace Policy {

namespace {
const uint32_t RTT_TIME_US = 5;
}

/**
 * Construct a Policy::Manager.
 *
 * @param transport
 *      The transport that owns this Policy::Manager.
 */
Manager::Manager(Driver* driver)
    : driver(driver)
{}

/**
 * Return the network priority that should be used for resent packets (i.e.
 * packets that were lost and need to be resent).
 */
int
Manager::getResendPriority()
{
    return 0;
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
    Scheduled policy;
    policy.maxScheduledPriority = 0;
    policy.degreeOvercommitment = 1;
    policy.scheduledByteLimit = RTT_TIME_US * (driver->getBandwidth() / 8);
    return policy;
}

/**
 * Return the unscheduled policy for messages of a particular size bound for a
 * particular Transport.
 *
 * Used by the Sender to decided the initial priority and number of unilaterally
 * "granted" (unscheduled) bytes for a new Message to be sent.
 *
 * @param destination
 *      The policy for the Transport at this Address will be returned.
 * @param messageLength
 *      The policy for message containing this many bytes will be returned.
 *
 * @sa Policy::Unscheduled
 */
Unscheduled
Manager::getUnscheduledPolicy(const Driver::Address destination,
                              const uint32_t messageLength)
{
    (void)destination;
    (void)messageLength;
    Unscheduled policy;
    policy.version = 0;
    policy.unscheduledByteLimit =
        std::min(RTT_TIME_US * (driver->getBandwidth() / 8), messageLength);
    policy.priority = 0;
    return policy;
}

/**
 * Inform the PolicyManager that a new Message is being delivered.  The
 * information provided in this call will be used to update and maintain
 * policies on behalf of the manager's Transport.
 *
 * Used by the Receiver when a new Message has started to arrive.
 *
 * @param source
 *      Address of the Transport from which the new Message was received.
 * @param policyVersion
 *      Version of the policy the Sender used when sending the Message.
 * @param messageLength
 *      Number of bytes the new incoming Message contains.
 */
void
Manager::signalNewMessage(const Driver::Address source, uint8_t policyVersion,
                          uint32_t messageLength)
{
    (void)source;
    (void)policyVersion;
    (void)messageLength;
}

/**
 * Allow the Manager to perform periodic background tasks like managing and
 * updating the policy.
 */
void
Manager::poll()
{}

}  // namespace Policy
}  // namespace Core
}  // namespace Homa
