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

#include <gtest/gtest.h>

#include "Mock/MockDriver.h"
#include "Policy.h"

namespace Homa {
namespace Core {
namespace Policy {
namespace {

using ::testing::Return;

TEST(PolicyManagerTest, constructor_default)
{
    Homa::Mock::MockDriver mockDriver;

    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));
    EXPECT_CALL(mockDriver, getHighestPacketPriority).WillOnce(Return(7));

    Policy::Manager manager(&mockDriver);

    EXPECT_EQ(8000U, manager.RTT_BYTES);
    EXPECT_EQ(7, manager.MAX_PRIORITY);
    EXPECT_EQ(3, manager.localScheduledPolicy.maxScheduledPriority);
}

TEST(PolicyManagerTest, constructor_limitedPriority)
{
    Homa::Mock::MockDriver mockDriver;

    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));
    EXPECT_CALL(mockDriver, getHighestPacketPriority).WillOnce(Return(2));

    Policy::Manager manager(&mockDriver);

    EXPECT_EQ(8000U, manager.RTT_BYTES);
    EXPECT_EQ(2, manager.MAX_PRIORITY);
    EXPECT_EQ(0, manager.localScheduledPolicy.maxScheduledPriority);
}

TEST(PolicyManagerTest, getUnscheduledPolicy)
{
    Homa::Mock::MockDriver mockDriver;
    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));
    EXPECT_CALL(mockDriver, getHighestPacketPriority).WillOnce(Return(7));
    Policy::Manager manager(&mockDriver);
    IpAddress dest{22};

    {
        Policy::Unscheduled policy = manager.getUnscheduledPolicy(dest, 1);
        EXPECT_EQ(0, policy.version);
        EXPECT_EQ(manager.RTT_BYTES, policy.unscheduledByteLimit);
        EXPECT_EQ(7, policy.priority);
    }

    manager.peerPolicies.at(dest).version = 1;
    manager.peerPolicies.at(dest).highestPriority = 2;

    {
        Policy::Unscheduled policy = manager.getUnscheduledPolicy(dest, 1000);
        EXPECT_EQ(1, policy.version);
        EXPECT_EQ(manager.RTT_BYTES, policy.unscheduledByteLimit);
        EXPECT_EQ(1, policy.priority);
    }

    {
        Policy::Unscheduled policy = manager.getUnscheduledPolicy(dest, 100000);
        EXPECT_EQ(1, policy.version);
        EXPECT_EQ(manager.RTT_BYTES, policy.unscheduledByteLimit);
        EXPECT_EQ(0, policy.priority);
    }
}

}  // namespace
}  // namespace Policy
}  // namespace Core
}  // namespace Homa
