/* Copyright (c) 2018-2019, Stanford University
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

#include "Mock/MockDriver.h"

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
        , msg()
        , buf()
        , packet0(buf + 0)
        , packet1(buf + 2048)
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(2048));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        msg = new Message(&mockDriver, 28, 0);
    }

    ~MessageTest()
    {
        delete msg;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    Message* msg;
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0;
    Homa::Mock::MockDriver::MockPacket packet1;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

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

TEST_F(MessageTest, constructor)
{
    EXPECT_CALL(mockDriver, getMaxPayloadSize).WillOnce(Return(10000));
    msg = new Message(&mockDriver, 999, 10);

    EXPECT_EQ(&mockDriver, msg->driver);
    EXPECT_EQ(9001U, msg->PACKET_DATA_LENGTH);
    EXPECT_EQ(999, msg->PACKET_HEADER_LENGTH);
    EXPECT_EQ(0U, msg->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(10U, msg->messageLength);
    EXPECT_EQ(0U, msg->numPackets);
    EXPECT_FALSE(msg->occupied.any());
}

TEST_F(MessageTest, destructor)
{
    const uint16_t NUM_PKTS = 5;

    msg->numPackets = NUM_PKTS;
    for (int i = 0; i < NUM_PKTS; ++i) {
        msg->occupied.set(i);
    }

    EXPECT_CALL(mockDriver, releasePackets(Eq(msg->packets), Eq(NUM_PKTS)))
        .Times(1);
}

TEST_F(MessageTest, append_basic)
{
    char source[] = "Hello, world!";
    msg->setPacket(0, &packet0);
    packet0.length = 28 + 20 + 2000 - 7;
    msg->messageLength = 20 + 2000 - 7;

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet1));

    msg->append(source, 14);

    EXPECT_EQ(20 + 2000 + 7, msg->messageLength);
    EXPECT_EQ(2U, msg->numPackets);
    EXPECT_TRUE(msg->packets[1] == &packet1);
    EXPECT_EQ(28 + 20 + 2000, packet0.length);
    EXPECT_EQ(28 + 7, packet1.length);
    EXPECT_TRUE(std::memcmp(buf + 28 + 20 + 2000 - 7, source, 7) == 0);
    EXPECT_TRUE(std::memcmp(buf + 28 + 20 + 2000 + 28, source + 7, 7) == 0);
}

TEST_F(MessageTest, append_truncated)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    char source[] = "Hello, world!";
    msg->setPacket(msg->MAX_MESSAGE_PACKETS - 1, &packet0);
    packet0.length = msg->PACKET_HEADER_LENGTH + msg->PACKET_DATA_LENGTH - 7;
    msg->messageLength = msg->PACKET_DATA_LENGTH * msg->MAX_MESSAGE_PACKETS - 7;
    EXPECT_EQ(1U, msg->numPackets);

    msg->append(source, 14);

    EXPECT_EQ(msg->PACKET_DATA_LENGTH * msg->MAX_MESSAGE_PACKETS,
              msg->messageLength);
    EXPECT_EQ(1U, msg->numPackets);
    EXPECT_EQ(msg->PACKET_HEADER_LENGTH + msg->PACKET_DATA_LENGTH,
              packet0.length);
    EXPECT_TRUE(std::memcmp(buf + 28 + 20 + 2000 - 7, source, 7) == 0);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Message.cc", m.filename);
    EXPECT_STREQ("append", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Max message size limit (2068480B) reached; 7 of 14 bytes appended",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(MessageTest, get_basic)
{
    char source[] = "Hello, world!";
    msg->setPacket(0, &packet0);
    msg->setPacket(1, &packet1);
    msg->messageLength = 20 + 2007;
    std::memcpy(buf + 28 + 20 + 2000 - 7, source, 7);
    std::memcpy(buf + 28 + 20 + 2000 + 28, source + 7, 7);
    packet0.length = 28 + 20 + 2000;
    packet1.length = 28 + 7;
    msg->MESSAGE_HEADER_LENGTH = 20;
    EXPECT_EQ(28U, msg->PACKET_HEADER_LENGTH);

    char dest[4096];
    uint32_t bytes = msg->get(2000 - 7, dest, 20);

    EXPECT_EQ(14U, bytes);
    EXPECT_STREQ(source, dest);
}

TEST_F(MessageTest, get_offsetTooLarge)
{
    msg->setPacket(0, &packet0);
    msg->setPacket(1, &packet1);
    msg->messageLength = 20 + 2007;
    packet0.length = 28 + 20 + 2000;
    packet1.length = 28 + 7;
    msg->MESSAGE_HEADER_LENGTH = 20;
    EXPECT_EQ(28U, msg->PACKET_HEADER_LENGTH);

    char dest[4096];
    uint32_t bytes = msg->get(4000, dest, 20);

    EXPECT_EQ(0U, bytes);
}

TEST_F(MessageTest, get_missingPacket)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    char source[] = "Hello,";
    msg->setPacket(0, &packet0);
    msg->messageLength = 20 + 2007;
    std::memcpy(buf + 28 + 20 + 2000 - 7, source, 7);
    packet0.length = 28 + 20 + 2000;
    msg->MESSAGE_HEADER_LENGTH = 20;
    EXPECT_EQ(28U, msg->PACKET_HEADER_LENGTH);

    char dest[4096];
    uint32_t bytes = msg->get(2000 - 7, dest, 20);

    EXPECT_EQ(7U, bytes);
    EXPECT_STREQ(source, dest);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Message.cc", m.filename);
    EXPECT_STREQ("get", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ("Message is missing data starting at packet index 1", m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(MessageTest, length)
{
    msg->messageLength = 200;
    msg->MESSAGE_HEADER_LENGTH = 20;
    EXPECT_EQ(180U, msg->length());
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

TEST_F(MessageTest, rawLength)
{
    msg->messageLength = 200;
    msg->MESSAGE_HEADER_LENGTH = 20;
    EXPECT_EQ(200U, msg->rawLength());
}

TEST_F(MessageTest, defineHeader)
{
    msg->setPacket(0, &packet0);
    msg->messageLength = 20;

    msg->defineHeader<char[10]>();

    EXPECT_EQ(10U, msg->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(20U, msg->messageLength);
}

TEST_F(MessageTest, defineHeader_emptyMessage)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    EXPECT_EQ(0U, msg->messageLength);

    msg->defineHeader<char[10]>();

    EXPECT_EQ(10U, msg->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(10U, msg->messageLength);
}

TEST_F(MessageTest, getOrAllocPacket)
{
    EXPECT_FALSE(msg->occupied.test(0));
    EXPECT_EQ(0U, msg->numPackets);
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    EXPECT_TRUE(&packet0 == msg->getOrAllocPacket(0));

    EXPECT_TRUE(msg->occupied.test(0));
    EXPECT_EQ(1U, msg->numPackets);

    EXPECT_TRUE(&packet0 == msg->getOrAllocPacket(0));

    EXPECT_TRUE(msg->occupied.test(0));
    EXPECT_EQ(1U, msg->numPackets);
}

TEST_F(MessageTest, getHeader)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    EXPECT_TRUE(packet0.payload == msg->getHeader());
}

}  // namespace
}  // namespace Core
}  // namespace Homa