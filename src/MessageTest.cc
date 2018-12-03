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

#include "Message.h"

#include "MockDriver.h"

#include <Homa/Debug.h>

namespace Homa {
namespace Core {
namespace {

using ::testing::Eq;
using ::testing::Exactly;
using ::testing::NiceMock;
using ::testing::Return;

class MessageTest : public ::testing::Test {
  public:
    MessageTest()
        : mockDriver()
        , pool()
        , msg()
        , buf()
        , packet0(buf + 0)
        , packet1(buf + 1024)
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        Protocol::MessageId msgId(42, 32);
        pool = new MessagePool();
        msg = pool->construct(msgId, 24, &mockDriver);
    }

    ~MessageTest()
    {
        delete pool;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    MessagePool* pool;
    Message* msg;
    char buf[2048];
    MockDriver::MockPacket packet0;
    MockDriver::MockPacket packet1;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(MessageTest, constructor)
{
    EXPECT_CALL(mockDriver, getMaxPayloadSize).WillOnce(Return(10000));
    Protocol::MessageId msgId(42, 32);
    msg = pool->construct(msgId, 999, &mockDriver);

    EXPECT_EQ(msgId, msg->msgId);
    EXPECT_TRUE(nullptr == msg->address);
    EXPECT_EQ(&mockDriver, msg->driver);
    EXPECT_EQ(0U, msg->messageLength);
    EXPECT_EQ(9001U, msg->PACKET_DATA_LENGTH);
    EXPECT_EQ(999, msg->DATA_HEADER_LENGTH);
    EXPECT_EQ(pool, msg->messagePool);
    EXPECT_EQ(1U, msg->refCount);
    EXPECT_EQ(0U, msg->numPackets);
    EXPECT_FALSE(msg->occupied.any());
}

TEST_F(MessageTest, destructor_contiguousPackets)
{
    const uint16_t NUM_PKTS = 5;

    msg->numPackets = NUM_PKTS;
    for (int i = 0; i < NUM_PKTS; ++i) {
        msg->occupied.set(i);
    }

    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets), Eq(NUM_PKTS)))
        .Times(1);

    pool->destroy(msg);
}

TEST_F(MessageTest, destructor_discontiguousPackets)
{
    msg->numPackets = 4;
    msg->occupied.set(0);
    msg->occupied.set(2);
    msg->occupied.set(3);
    msg->occupied.set(5);

    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets + 0), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets + 2), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets + 3), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets + 5), Eq(1)))
        .Times(1);

    pool->destroy(msg);
}

TEST_F(MessageTest, get_basic)
{
    char source[] = "Hello, world!";
    msg->setPacket(0, &packet0);
    msg->setPacket(1, &packet1);
    msg->messageLength = 1007;
    std::memcpy(buf + 24 + 1000 - 7, source, 7);
    std::memcpy(buf + 24 + 1000 + 24, source + 7, 7);
    packet0.length = 24 + 1000;
    packet1.length = 24 + 7;
    EXPECT_EQ(24U, msg->DATA_HEADER_LENGTH);

    char dest[2048];
    uint32_t bytes = msg->get(1000 - 7, dest, 20);

    EXPECT_EQ(14U, bytes);
    EXPECT_STREQ(source, dest);
}

TEST_F(MessageTest, get_offsetTooLarge)
{
    msg->setPacket(0, &packet0);
    msg->setPacket(1, &packet1);
    msg->messageLength = 1007;
    packet0.length = 24 + 1000;
    packet1.length = 24 + 7;

    char dest[2048];
    uint32_t bytes = msg->get(2000, dest, 20);

    EXPECT_EQ(0U, bytes);
}

// Used to capture log output.
struct VectorHandler {
    VectorHandler()
        : messages()
    {}
    void operator()(Debug::DebugMessage message)
    {
        messages.push_back(message);
    }
    std::vector<Debug::DebugMessage> messages;
};

TEST_F(MessageTest, get_missingPacket)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    char source[] = "Hello,";
    msg->setPacket(0, &packet0);
    msg->messageLength = 1007;
    std::memcpy(buf + 24 + 1000 - 7, source, 7);
    packet0.length = 24 + 1000;
    EXPECT_EQ(24U, msg->DATA_HEADER_LENGTH);

    char dest[2048];
    uint32_t bytes = msg->get(1000 - 7, dest, 20);

    EXPECT_EQ(7U, bytes);
    EXPECT_STREQ(source, dest);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Message.cc", m.filename);
    EXPECT_STREQ("get", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Copy cut short; message (42:32) of length 1007B has no packet at "
        "offset 1000 (index 1)",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(MessageTest, set_basic)
{
    char source[] = "Hello, world!";
    msg->setPacket(1, &packet1);
    msg->messageLength = 1042;
    packet1.length = 24 + 42;
    EXPECT_EQ(24U, msg->DATA_HEADER_LENGTH);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    EXPECT_CALL(packet0, getMaxPayloadSize).WillOnce(Return(1024));

    msg->set(1000 - 7, source, 14);

    EXPECT_TRUE(std::memcmp(buf + 24 + 1000 - 7, source, 7) == 0);
    EXPECT_TRUE(std::memcmp(buf + 24 + 1000 + 24, source + 7, 7) == 0);
    EXPECT_EQ(24 + 1000, packet0.length);
    EXPECT_EQ(24 + 42, packet1.length);
    EXPECT_EQ(1042U, msg->messageLength);
}

TEST_F(MessageTest, set_offsetTooLarge)
{
    char source[] = "Hello, world!";
    const uint32_t MAX_LEN = msg->MAX_MESSAGE_PACKETS * msg->PACKET_DATA_LENGTH;

    EXPECT_CALL(mockDriver, allocPacket).Times(0);

    msg->set(MAX_LEN, source, 14);
}

TEST_F(MessageTest, set_truncate)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    char source[] = "Hello, world!";
    const uint32_t MAX_LEN = msg->MAX_MESSAGE_PACKETS * msg->PACKET_DATA_LENGTH;
    msg->messageLength = 0;
    EXPECT_EQ(24U, msg->DATA_HEADER_LENGTH);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    EXPECT_CALL(packet0, getMaxPayloadSize).WillOnce(Return(1024));

    msg->set(MAX_LEN - 7, source, 14);

    EXPECT_TRUE(std::memcmp(buf + 24 + 1000 - 7, source, 7) == 0);
    EXPECT_FALSE(std::memcmp(buf + 24 + 1000 + 24, source + 7, 7) == 0);
    EXPECT_EQ(24 + 1000, packet0.length);
    EXPECT_EQ(MAX_LEN, msg->messageLength);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Message.cc", m.filename);
    EXPECT_STREQ("set", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ(
        "Max message size limit (1024000B) reached; trying to set bytes "
        "1023993 - 1024006; message will be truncated",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(MessageTest, getPacket)
{
    Driver::Packet* packet = (Driver::Packet*)42;
    msg->packets[0] = packet;

    EXPECT_EQ(nullptr, msg->getPacket(0));

    msg->occupied.set(0);

    EXPECT_EQ(packet, msg->getPacket(0));
}

TEST_F(MessageTest, setPacket)
{
    Driver::Packet* packet = (Driver::Packet*)42;

    EXPECT_FALSE(msg->occupied.test(0));
    EXPECT_EQ(0U, msg->numPackets);

    EXPECT_TRUE(msg->setPacket(0, packet));

    EXPECT_EQ(packet, msg->packets[0]);
    EXPECT_TRUE(msg->occupied.test(0));
    EXPECT_EQ(1U, msg->numPackets);

    EXPECT_FALSE(msg->setPacket(0, packet));
}

TEST_F(MessageTest, getNumPackets)
{
    msg->numPackets = 42;
    EXPECT_EQ(42U, msg->getNumPackets());
}

TEST_F(MessageTest, retain)
{
    EXPECT_EQ(1U, msg->refCount);
    msg->retain();
    EXPECT_EQ(2U, msg->refCount);
}

TEST_F(MessageTest, release_basic)
{
    EXPECT_CALL(mockDriver, releasePackets).Times(Exactly(0));
    msg->refCount = 2;
    msg->release();
    EXPECT_EQ(1U, msg->refCount);
}

TEST_F(MessageTest, release_destroy)
{
    EXPECT_CALL(mockDriver, releasePackets).Times(Exactly(1));
    msg->release();
}

TEST(MessagePoolTest, basic)
{
    MessagePool pool;
    NiceMock<MockDriver> mockDriver;
    ON_CALL(mockDriver, getMaxPayloadSize())
        .WillByDefault(::testing::Return(1000));
    EXPECT_EQ(0U, pool.pool.outstandingObjects);
    Protocol::MessageId msgId(42, 32);
    Message* msg = pool.construct(msgId, 0, &mockDriver);
    EXPECT_EQ(1U, pool.pool.outstandingObjects);
    pool.destroy(msg);
    EXPECT_EQ(0U, pool.pool.outstandingObjects);
}

}  // namespace
}  // namespace Core
}  // namespace Homa