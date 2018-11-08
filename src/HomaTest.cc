/**
 * Copyright (c) 2018, Stanford University
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

#include <Homa/Homa.h>

#include "MockDriver.h"
#include "TransportImpl.h"

namespace Homa {
namespace {

using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;

using Core::TransportImpl;

class MessageTest : public ::testing::Test {
  public:
    MessageTest()
        : mockDriver()
        , transport(new TransportImpl(&mockDriver, 22))
        , buf()
        , packet0(buf + 0)
        , packet1(buf + 1024)
        , savedLogPolicy(Debug::getLogPolicy())
    {
        std::memset(buf, 0, sizeof(buf));
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~MessageTest()
    {
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    TransportImpl* transport;
    char buf[2048];
    MockDriver::MockPacket packet0;
    MockDriver::MockPacket packet1;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(MessageTest, constructor)
{
    Message message;
    EXPECT_EQ(nullptr, message.context);
    EXPECT_EQ(nullptr, message.transportImpl);
}

TEST_F(MessageTest, moveConstructor)
{
    Message srcMsg;
    srcMsg.context = (Core::MessageContext*)42;
    srcMsg.transportImpl = (TransportImpl*)41;

    Message dstMsg(std::move(srcMsg));

    EXPECT_EQ(nullptr, srcMsg.context);
    EXPECT_EQ(nullptr, srcMsg.transportImpl);

    EXPECT_EQ((Core::MessageContext*)42, dstMsg.context);
    EXPECT_EQ((TransportImpl*)41, dstMsg.transportImpl);

    // Avoid causing a segfault in the test.
    dstMsg.context = nullptr;
}

TEST_F(MessageTest, destructor)
{
    Core::MessageContext* context =
        transport->messagePool.construct({42, 1}, 24, &mockDriver);
    context->retain();

    EXPECT_EQ(2U, context->refCount);

    Message* message = new Message();
    message->context = context;

    delete message;

    EXPECT_EQ(1U, context->refCount);
}

TEST_F(MessageTest, moveAssignment)
{
    Message srcMsg;
    srcMsg.context = (Core::MessageContext*)42;
    srcMsg.transportImpl = (TransportImpl*)41;

    Message dstMsg;

    dstMsg = std::move(srcMsg);

    EXPECT_EQ(nullptr, srcMsg.context);
    EXPECT_EQ(nullptr, srcMsg.transportImpl);

    EXPECT_EQ((Core::MessageContext*)42, dstMsg.context);
    EXPECT_EQ((TransportImpl*)41, dstMsg.transportImpl);

    // Avoid causing a segfault in the test.
    dstMsg.context = nullptr;
}

TEST_F(MessageTest, operatorBool)
{
    Message message;
    message.context = (Core::MessageContext*)42;

    EXPECT_TRUE(message);

    message.context = nullptr;

    EXPECT_FALSE(message);
}

TEST_F(MessageTest, get_basic)
{
    Message message = transport->newMessage();
    char source[] = "Hello, world!";
    message.context->setPacket(0, &packet0);
    message.context->setPacket(1, &packet1);
    message.context->messageLength = 1007;
    std::memcpy(buf + 24 + 1000 - 7, source, 7);
    std::memcpy(buf + 24 + 1000 + 24, source + 7, 7);
    packet0.length = 24 + 1000;
    packet1.length = 24 + 7;
    EXPECT_EQ(24U, message.context->DATA_HEADER_LENGTH);

    char dest[2048];
    uint32_t bytes = message.get(1000 - 7, dest, 20);

    EXPECT_EQ(14U, bytes);
    EXPECT_STREQ(source, dest);
}

TEST_F(MessageTest, get_offsetTooLarge)
{
    Message message = transport->newMessage();
    message.context->setPacket(0, &packet0);
    message.context->setPacket(1, &packet1);
    message.context->messageLength = 1007;
    packet0.length = 24 + 1000;
    packet1.length = 24 + 7;

    char dest[2048];
    uint32_t bytes = message.get(2000, dest, 20);

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

    Message message = transport->newMessage();
    char source[] = "Hello,";
    message.context->setPacket(0, &packet0);
    message.context->messageLength = 1007;
    std::memcpy(buf + 24 + 1000 - 7, source, 7);
    packet0.length = 24 + 1000;
    EXPECT_EQ(24U, message.context->DATA_HEADER_LENGTH);

    char dest[2048];
    uint32_t bytes = message.get(1000 - 7, dest, 20);

    EXPECT_EQ(7U, bytes);
    EXPECT_STREQ(source, dest);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Homa.cc", m.filename);
    EXPECT_STREQ("get", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Copy cut short; message (22:1) of length 1007B has no packet at "
        "offset 1000 (index 1)",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(MessageTest, set_basic)
{
    Message message = transport->newMessage();
    char source[] = "Hello, world!";
    message.context->setPacket(1, &packet1);
    message.context->messageLength = 1042;
    packet1.length = 24 + 42;
    EXPECT_EQ(24U, message.context->DATA_HEADER_LENGTH);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    EXPECT_CALL(packet0, getMaxPayloadSize).WillOnce(Return(1024));

    message.set(1000 - 7, source, 14);

    EXPECT_TRUE(std::memcmp(buf + 24 + 1000 - 7, source, 7) == 0);
    EXPECT_TRUE(std::memcmp(buf + 24 + 1000 + 24, source + 7, 7) == 0);
    EXPECT_EQ(24 + 1000, packet0.length);
    EXPECT_EQ(24 + 42, packet1.length);
    EXPECT_EQ(1042U, message.context->messageLength);
}

TEST_F(MessageTest, set_offsetTooLarge)
{
    Message message = transport->newMessage();
    char source[] = "Hello, world!";
    const uint32_t MAX_LEN = message.context->MAX_MESSAGE_PACKETS *
                             message.context->PACKET_DATA_LENGTH;

    EXPECT_CALL(mockDriver, allocPacket).Times(0);

    message.set(MAX_LEN, source, 14);
}

TEST_F(MessageTest, set_truncate)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    Message message = transport->newMessage();
    char source[] = "Hello, world!";
    const uint32_t MAX_LEN = message.context->MAX_MESSAGE_PACKETS *
                             message.context->PACKET_DATA_LENGTH;
    message.context->messageLength = 0;
    EXPECT_EQ(24U, message.context->DATA_HEADER_LENGTH);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    EXPECT_CALL(packet0, getMaxPayloadSize).WillOnce(Return(1024));

    message.set(MAX_LEN - 7, source, 14);

    EXPECT_TRUE(std::memcmp(buf + 24 + 1000 - 7, source, 7) == 0);
    EXPECT_FALSE(std::memcmp(buf + 24 + 1000 + 24, source + 7, 7) == 0);
    EXPECT_EQ(24 + 1000, packet0.length);
    EXPECT_EQ(MAX_LEN, message.context->messageLength);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Homa.cc", m.filename);
    EXPECT_STREQ("set", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ(
        "Max message size limit (1024000B) reached; trying to set bytes "
        "1023993 - 1024006; message will be truncated",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

}  // namespace
}  // namespace Homa
