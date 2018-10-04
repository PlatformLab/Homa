/* Copyright (c) 2018, Stanford University
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

#include "MessageContext.h"

#include "MockDriver.h"

#include <Homa/Debug.h>

namespace Homa {
namespace Core {
namespace {

using ::testing::Eq;
using ::testing::Exactly;
using ::testing::NiceMock;
using ::testing::Return;

class MessageContextTest : public ::testing::Test {
  public:
    MessageContextTest()
        : mockDriver()
        , pool()
        , context()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        Protocol::MessageId msgId(42, 32);
        pool = new MessagePool();
        context = pool->construct(msgId, 10, &mockDriver);
    }

    ~MessageContextTest()
    {
        delete pool;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    MessagePool* pool;
    MessageContext* context;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(MessageContextTest, constructor)
{
    EXPECT_CALL(mockDriver, getMaxPayloadSize).WillOnce(Return(10000));
    Protocol::MessageId msgId(42, 32);
    context = pool->construct(msgId, 999, &mockDriver);

    EXPECT_EQ(msgId, context->msgId);
    EXPECT_TRUE(nullptr == context->address);
    EXPECT_EQ(&mockDriver, context->driver);
    EXPECT_EQ(0U, context->messageLength);
    EXPECT_EQ(9001U, context->PACKET_DATA_LENGTH);
    EXPECT_EQ(999, context->DATA_HEADER_LENGTH);
    EXPECT_EQ(pool, context->messagePool);
    EXPECT_EQ(1U, context->refCount);
    EXPECT_EQ(0U, context->numPackets);
    EXPECT_FALSE(context->occupied.any());
}

TEST_F(MessageContextTest, destructor_contiguousPackets)
{
    const uint16_t NUM_PKTS = 5;

    context->numPackets = NUM_PKTS;
    for (int i = 0; i < NUM_PKTS; ++i) {
        context->occupied.set(i);
    }

    EXPECT_CALL(mockDriver, releasePackets(Eq(context->packets), Eq(NUM_PKTS)))
        .Times(1);

    pool->destroy(context);
}

TEST_F(MessageContextTest, destructor_discontiguousPackets)
{
    context->numPackets = 4;
    context->occupied.set(0);
    context->occupied.set(2);
    context->occupied.set(3);
    context->occupied.set(5);

    EXPECT_CALL(mockDriver, releasePackets(Eq(context->packets + 0), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(context->packets + 2), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(context->packets + 3), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(context->packets + 5), Eq(1)))
        .Times(1);

    pool->destroy(context);
}

TEST_F(MessageContextTest, getPacket)
{
    Driver::Packet* packet = (Driver::Packet*)42;
    context->packets[0] = packet;

    EXPECT_EQ(nullptr, context->getPacket(0));

    context->occupied.set(0);

    EXPECT_EQ(packet, context->getPacket(0));
}

TEST_F(MessageContextTest, setPacket)
{
    Driver::Packet* packet = (Driver::Packet*)42;

    EXPECT_FALSE(context->occupied.test(0));
    EXPECT_EQ(0U, context->numPackets);

    EXPECT_TRUE(context->setPacket(0, packet));

    EXPECT_EQ(packet, context->packets[0]);
    EXPECT_TRUE(context->occupied.test(0));
    EXPECT_EQ(1U, context->numPackets);

    EXPECT_FALSE(context->setPacket(0, packet));
}

TEST_F(MessageContextTest, getNumPackets)
{
    context->numPackets = 42;
    EXPECT_EQ(42U, context->getNumPackets());
}

TEST_F(MessageContextTest, retain)
{
    EXPECT_EQ(1U, context->refCount);
    context->retain();
    EXPECT_EQ(2U, context->refCount);
}

TEST_F(MessageContextTest, release_basic)
{
    EXPECT_CALL(mockDriver, releasePackets).Times(Exactly(0));
    context->refCount = 2;
    context->release();
    EXPECT_EQ(1U, context->refCount);
}

TEST_F(MessageContextTest, release_destroy)
{
    EXPECT_CALL(mockDriver, releasePackets).Times(Exactly(1));
    context->release();
}

TEST(MessagePoolTest, basic)
{
    MessagePool pool;
    NiceMock<MockDriver> mockDriver;
    ON_CALL(mockDriver, getMaxPayloadSize())
        .WillByDefault(::testing::Return(1000));
    EXPECT_EQ(0U, pool.pool.outstandingObjects);
    Protocol::MessageId msgId(42, 32);
    MessageContext* context = pool.construct(msgId, 0, &mockDriver);
    EXPECT_EQ(1U, pool.pool.outstandingObjects);
    pool.destroy(context);
    EXPECT_EQ(0U, pool.pool.outstandingObjects);
}

}  // namespace
}  // namespace Core
}  // namespace Homa