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

#include <Cycles.h>
#include <gtest/gtest.h>

#include "Timeout.h"

namespace Homa {
namespace Core {
namespace {

TEST(TimeoutTest, hasElapsed)
{
    PerfUtils::Cycles::mockTscValue = 999;

    Timeout<char> t(nullptr);
    t.expirationCycleTime = 1000;

    EXPECT_FALSE(t.hasElapsed());

    PerfUtils::Cycles::mockTscValue = 1000;

    EXPECT_TRUE(t.hasElapsed());

    PerfUtils::Cycles::mockTscValue = 0;
}

TEST(TimeoutManagerTest, setTimeout)
{
    PerfUtils::Cycles::mockTscValue = 10000;
    TimeoutManager<char> manager(100);
    char dummyOwner;
    char owner;
    Timeout<char> dummy(&dummyOwner);
    dummy.expirationCycleTime = 42;
    manager.list.push_back(&dummy.node);
    manager.nextTimeout = 0;

    Timeout<char> t(&owner);

    EXPECT_EQ(0U, t.expirationCycleTime);
    EXPECT_EQ(nullptr, t.node.list);
    EXPECT_EQ(&dummyOwner, manager.list.back().owner);

    manager.setTimeout(&t);

    EXPECT_EQ(10100U, t.expirationCycleTime);
    EXPECT_EQ(42U, manager.nextTimeout.load());
    EXPECT_EQ(&manager.list, t.node.list);
    EXPECT_EQ(&owner, manager.list.back().owner);

    manager.list.clear();
    PerfUtils::Cycles::mockTscValue = 0;
}

TEST(TimeoutManagerTest, setTimeout_reset)
{
    PerfUtils::Cycles::mockTscValue = 10000;
    TimeoutManager<char> manager(100);
    char owner;
    char dummyOwner;
    Timeout<char> t(&owner);
    Timeout<char> dummy(&dummyOwner);
    dummy.expirationCycleTime = 9001;
    manager.list.push_back(&t.node);
    manager.list.push_back(&dummy.node);
    t.expirationCycleTime = 50;

    EXPECT_EQ(50U, t.expirationCycleTime);
    EXPECT_EQ(&manager.list, t.node.list);
    EXPECT_EQ(&owner, &manager.front());
    EXPECT_EQ(&dummyOwner, manager.list.back().owner);

    manager.setTimeout(&t);

    EXPECT_EQ(10100U, t.expirationCycleTime);
    EXPECT_EQ(9001U, manager.nextTimeout.load());
    EXPECT_EQ(&manager.list, t.node.list);
    EXPECT_EQ(&dummyOwner, &manager.front());
    EXPECT_EQ(&owner, manager.list.back().owner);

    manager.list.clear();
    PerfUtils::Cycles::mockTscValue = 0;
}

TEST(TimeoutManagerTest, cancelTimeout)
{
    TimeoutManager<char> manager(100);
    char owner;
    Timeout<char> t1(&owner);
    t1.expirationCycleTime = 42;
    Timeout<char> t2(&owner);
    t2.expirationCycleTime = 9001;
    manager.list.push_back(&t1.node);
    manager.list.push_back(&t2.node);

    EXPECT_EQ(2, manager.list.size());

    manager.cancelTimeout(&t1);

    EXPECT_EQ(nullptr, t1.node.list);
    EXPECT_EQ(9001U, manager.nextTimeout.load());
    EXPECT_EQ(1, manager.list.size());

    manager.cancelTimeout(&t2);

    EXPECT_EQ(nullptr, t2.node.list);
    EXPECT_EQ(UINT64_MAX, manager.nextTimeout.load());
    EXPECT_TRUE(manager.list.empty());
}

}  // namespace
}  // namespace Core
}  // namespace Homa