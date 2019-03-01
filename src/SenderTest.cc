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

#include "OpContext.h"
#include "Sender.h"

#include "MockDriver.h"

#include <Homa/Debug.h>

#include <mutex>

namespace Homa {
namespace Core {
namespace {

using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;

class SenderTest : public ::testing::Test {
  public:
    SenderTest()
        : mockDriver()
        , mockPacket(&payload)
        , opContextPool()
        , sender()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1028));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        opContextPool = new OpContextPool();
    }

    ~SenderTest()
    {
        delete opContextPool;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    NiceMock<MockDriver::MockPacket> mockPacket;
    char payload[1028];
    OpContextPool* opContextPool;
    Sender sender;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;

    static Sender::OutboundMessage* addMessage(Sender* sender,
                                               OpContext* context,
                                               uint32_t grantOffset = 0)
    {
        Sender::OutboundMessage* message = context->outMessage.get();
        sender->sendQueue.push_back(message);
        message->sending.test_and_set();
        message->grantOffset = grantOffset;
        message->grantIndex =
            message->grantOffset / message->PACKET_DATA_LENGTH;
        return message;
    }
};

TEST_F(SenderTest, handleGrantPacket_basic)
{
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    context->outMessage->messageLength = 9000;
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 6500;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(context, &mockPacket, &mockDriver);

    EXPECT_EQ(6500, message->grantOffset);
    EXPECT_EQ(6, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_staleGrant)
{
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    context->outMessage->messageLength = 9000;
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 4000;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(context, &mockPacket, &mockDriver);

    EXPECT_EQ(4999, message->grantOffset);
    EXPECT_EQ(4, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_excessGrant)
{
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    context->outMessage->messageLength = 9000;
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 9001;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(context, &mockPacket, &mockDriver);

    EXPECT_EQ(8999, message->grantOffset);
    EXPECT_EQ(8, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_dropGrant)
{
    Protocol::MessageId msgId = {42, 1};
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 6500;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(nullptr, &mockPacket, &mockDriver);
}

TEST_F(SenderTest, sendMessage_basic)
{
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    Sender::OutboundMessage* outMessage = context->outMessage.get();

    outMessage->setPacket(0, &mockPacket);
    outMessage->messageLength = 420;
    mockPacket.length =
        outMessage->messageLength + outMessage->DATA_HEADER_LENGTH;
    outMessage->address = (Driver::Address*)22;

    EXPECT_EQ(0U, sender.sendQueue.size());

    sender.sendMessage(context);

    EXPECT_EQ(22U, (uint64_t)mockPacket.address);
    EXPECT_EQ(0U, mockPacket.priority);
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(outMessage->msgId, header->common.messageId);
    EXPECT_EQ(outMessage->messageLength, header->totalLength);
    EXPECT_EQ(1U, sender.sendQueue.size());
    EXPECT_EQ(outMessage, sender.sendQueue.front());
    EXPECT_EQ(419U, outMessage->grantOffset);
    EXPECT_EQ(0U, outMessage->grantIndex);
}

TEST_F(SenderTest, sendMessage_multipacket)
{
    char payload0[1028];
    char payload1[1028];
    NiceMock<MockDriver::MockPacket> packet0(payload0);
    NiceMock<MockDriver::MockPacket> packet1(payload1);
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    Sender::OutboundMessage* outMessage = context->outMessage.get();

    outMessage->setPacket(0, &packet0);
    outMessage->setPacket(1, &packet1);
    outMessage->messageLength = 1420;
    packet0.length = 1000 + 28;
    packet1.length = 420 + 28;
    outMessage->address = (Driver::Address*)22;

    EXPECT_EQ(28U, sizeof(Protocol::Packet::DataHeader));
    EXPECT_EQ(1000U, outMessage->PACKET_DATA_LENGTH);

    sender.sendMessage(context);

    Protocol::Packet::DataHeader* header = nullptr;
    // Packet0
    EXPECT_EQ(22U, (uint64_t)packet0.address);
    EXPECT_EQ(0U, packet0.priority);
    header = static_cast<Protocol::Packet::DataHeader*>(packet0.payload);
    EXPECT_EQ(outMessage->msgId, header->common.messageId);
    EXPECT_EQ(outMessage->messageLength, header->totalLength);

    // Packet1
    EXPECT_EQ(22U, (uint64_t)packet1.address);
    EXPECT_EQ(0U, packet1.priority);
    header = static_cast<Protocol::Packet::DataHeader*>(packet1.payload);
    EXPECT_EQ(outMessage->msgId, header->common.messageId);
    EXPECT_EQ(outMessage->messageLength, header->totalLength);
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

TEST_F(SenderTest, sendMessage_missingPacket)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    Sender::OutboundMessage* outMessage = context->outMessage.get();
    outMessage->setPacket(1, &mockPacket);

    EXPECT_EQ(0U, sender.sendQueue.size());

    sender.sendMessage(context);

    EXPECT_EQ(0U, sender.sendQueue.size());

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("sendMessage", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ(
        "Incomplete message with id (42:1:1); missing packet at offset 0; "
        "send request dropped.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, sendMessage_duplicateMessage)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    Sender::OutboundMessage* outMessage = context->outMessage.get();
    outMessage->setPacket(0, &mockPacket);
    outMessage->messageLength = 420;
    mockPacket.length =
        outMessage->messageLength + outMessage->DATA_HEADER_LENGTH;
    outMessage->address = (Driver::Address*)22;

    // First send should succeed.
    sender.sendMessage(context);

    EXPECT_EQ(0U, handler.messages.size());

    // Second send should be dropped.
    sender.sendMessage(context);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("sendMessage", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Duplicate call to sendMessage for msgId (42:1:1); "
        "send request dropped.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, sendMessage_unsheduledLimit)
{
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    Sender::OutboundMessage* outMessage = context->outMessage.get();
    for (int i = 0; i < 9; ++i) {
        outMessage->setPacket(i, &mockPacket);
    }
    outMessage->messageLength = 9000;
    mockPacket.length = 1000 + sizeof(Protocol::Packet::DataHeader);
    outMessage->address = (Driver::Address*)22;
    EXPECT_EQ(9U, outMessage->getNumPackets());
    EXPECT_EQ(1000U, outMessage->PACKET_DATA_LENGTH);

    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));

    sender.sendMessage(context);

    EXPECT_EQ(outMessage, sender.sendQueue.front());
    EXPECT_EQ(4999U, outMessage->grantOffset);
    EXPECT_EQ(4U, outMessage->grantIndex);
}

TEST_F(SenderTest, trySend_basic)
{
    OpContext* context[3];
    Sender::OutboundMessage* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        context[i] = opContextPool->construct();
        Protocol::MessageId msgId = {42, 10 + i};
        context[i]->outMessage.construct(
            msgId, sizeof(Protocol::Packet::DataHeader), &mockDriver);
        message[i] = SenderTest::addMessage(&sender, context[i], 4999);
    }

    // Message 0: All packets sent
    message[0]->messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[0]->sentIndex = 4;
    for (int i = 0; i < 5; ++i) {
        message[0]->setPacket(i, nullptr);
    }

    // Message 1: Waiting for more grants
    message[1]->messageLength = 9000;
    EXPECT_EQ(4, message[1]->grantIndex);
    message[1]->sentIndex = 4;
    for (int i = 0; i < 9; ++i) {
        message[1]->setPacket(i, nullptr);
    }

    // Message 2: New message, send 5 packets
    message[2]->messageLength = 9000;
    EXPECT_EQ(4, message[2]->grantIndex);
    EXPECT_EQ(-1, message[2]->sentIndex);
    for (int i = 0; i < 9; ++i) {
        message[2]->setPacket(i, &mockPacket);
    }

    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(5);

    sender.trySend();

    EXPECT_EQ(4U, message[0]->sentIndex);
    EXPECT_EQ(4U, message[1]->sentIndex);
    EXPECT_EQ(4U, message[2]->sentIndex);
}

TEST_F(SenderTest, trySend_alreadyRunning)
{
    Protocol::MessageId msgId = {42, 1};
    OpContext* context = opContextPool->construct();
    context->outMessage.construct(msgId, sizeof(Protocol::Packet::DataHeader),
                                  &mockDriver);
    Sender::OutboundMessage* outMessage = context->outMessage.get();
    outMessage->setPacket(0, &mockPacket);
    outMessage->messageLength = 1000;
    EXPECT_EQ(1U, outMessage->getNumPackets());
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 999);
    EXPECT_EQ(0, message->grantIndex);
    EXPECT_EQ(-1, message->sentIndex);

    std::lock_guard<SpinLock> _(sender.queueMutex);

    EXPECT_CALL(mockDriver, sendPackets).Times(0);

    sender.trySend();

    EXPECT_EQ(-1, message->sentIndex);
}

TEST_F(SenderTest, trySend_sendQueueEmpty)
{
    EXPECT_TRUE(sender.sendQueue.empty());
    EXPECT_CALL(mockDriver, sendPackets).Times(0);
    sender.trySend();
}

TEST_F(SenderTest, cleanup)
{
    OpContext* context[3];
    Sender::OutboundMessage* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        context[i] = opContextPool->construct();
        Protocol::MessageId msgId = {42, 10 + i};
        context[i]->outMessage.construct(
            msgId, sizeof(Protocol::Packet::DataHeader), &mockDriver);
        message[i] = SenderTest::addMessage(&sender, context[i], 4999);
    }

    // Message 0: All packets sent
    message[0]->messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[0]->sentIndex = 4;
    for (int i = 0; i < 5; ++i) {
        message[0]->setPacket(i, nullptr);
    }
    EXPECT_EQ(5U, message[0]->getNumPackets());

    // Message 1: Waiting for more grants
    message[1]->messageLength = 9000;
    EXPECT_EQ(4, message[1]->grantIndex);
    message[1]->sentIndex = 4;
    for (int i = 0; i < 9; ++i) {
        message[1]->setPacket(i, nullptr);
    }

    // Message 2: All packets sent
    message[2]->messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[2]->sentIndex = 4;
    for (int i = 0; i < 5; ++i) {
        message[2]->setPacket(i, nullptr);
    }

    EXPECT_TRUE(message[0]->sending.test_and_set());
    EXPECT_TRUE(message[1]->sending.test_and_set());
    EXPECT_TRUE(message[2]->sending.test_and_set());
    EXPECT_EQ(3U, sender.sendQueue.size());

    // Clean Message 0
    sender.cleanup();

    EXPECT_FALSE(message[0]->sending.test_and_set());
    message[0]->sending.clear();
    EXPECT_TRUE(message[1]->sending.test_and_set());
    EXPECT_TRUE(message[2]->sending.test_and_set());
    EXPECT_EQ(2U, sender.sendQueue.size());

    // Clean Nothing
    sender.cleanup();

    EXPECT_TRUE(message[1]->sending.test_and_set());
    EXPECT_TRUE(message[2]->sending.test_and_set());
    EXPECT_EQ(2U, sender.sendQueue.size());

    message[1]->sentIndex = 9;

    // Clean All
    sender.cleanup();

    EXPECT_FALSE(message[1]->sending.test_and_set());
    message[1]->sending.clear();
    EXPECT_FALSE(message[2]->sending.test_and_set());
    message[2]->sending.clear();
    EXPECT_EQ(0U, sender.sendQueue.size());
}

}  // namespace
}  // namespace Core
}  // namespace Homa
