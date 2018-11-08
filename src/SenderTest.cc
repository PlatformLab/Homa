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
        , messagePool()
        , sender()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        messagePool = new MessagePool();
    }

    ~SenderTest()
    {
        delete messagePool;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    NiceMock<MockDriver::MockPacket> mockPacket;
    char payload[1024];
    MessagePool* messagePool;
    Sender sender;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;

    static Sender::OutboundMessage* addMessage(Sender* sender,
                                               MessageContext* context,
                                               uint32_t grantOffset = 0)
    {
        Sender::OutboundMessage* message =
            sender->outboundPool.construct(context);
        message->context->retain();
        sender->messageMap.insert({message->context->msgId, message});
        message->grantOffset = grantOffset;
        message->grantIndex =
            message->grantOffset / message->context->PACKET_DATA_LENGTH;
        return message;
    }
};

TEST_F(SenderTest, destructor)
{
    Sender* sender = new Sender();
    MessageContext* context[3];
    for (uint64_t i = 0; i < 3; ++i) {
        context[i] = messagePool->construct({42, 10 + i}, 24, &mockDriver);
        SenderTest::addMessage(sender, context[i]);
    }

    EXPECT_EQ(2, context[0]->refCount);
    EXPECT_EQ(2, context[1]->refCount);
    EXPECT_EQ(2, context[2]->refCount);

    delete sender;

    EXPECT_EQ(1, context[0]->refCount);
    EXPECT_EQ(1, context[1]->refCount);
    EXPECT_EQ(1, context[2]->refCount);
}

TEST_F(SenderTest, handleGrantPacket_basic)
{
    Protocol::MessageId msgId = {42, 1};
    MessageContext* context = messagePool->construct(msgId, 24, &mockDriver);
    context->messageLength = 9000;
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(mockPacket.payload);
    header->common.msgId = msgId;
    header->offset = 6500;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(6500, message->grantOffset);
    EXPECT_EQ(6, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_staleGrant)
{
    Protocol::MessageId msgId = {42, 1};
    MessageContext* context = messagePool->construct(msgId, 24, &mockDriver);
    context->messageLength = 9000;
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(mockPacket.payload);
    header->common.msgId = msgId;
    header->offset = 4000;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(4999, message->grantOffset);
    EXPECT_EQ(4, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_excessGrant)
{
    Protocol::MessageId msgId = {42, 1};
    MessageContext* context = messagePool->construct(msgId, 24, &mockDriver);
    context->messageLength = 9000;
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(mockPacket.payload);
    header->common.msgId = msgId;
    header->offset = 9001;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(8999, message->grantOffset);
    EXPECT_EQ(8, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_dropGrant)
{
    Protocol::MessageId msgId = {42, 1};
    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(mockPacket.payload);
    header->common.msgId = msgId;
    header->offset = 6500;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);
}

TEST_F(SenderTest, sendMessage_basic)
{
    MessageContext* context = messagePool->construct(
        {42, 1}, sizeof(Protocol::DataHeader), &mockDriver);
    context->setPacket(0, &mockPacket);
    context->messageLength = 420;
    mockPacket.length = context->messageLength + context->DATA_HEADER_LENGTH;
    context->address = (Driver::Address*)22;

    EXPECT_EQ(0U, sender.sendQueue.size());
    EXPECT_EQ(0U, sender.outboundPool.outstandingObjects);

    sender.sendMessage(context);

    EXPECT_EQ(22U, (uint64_t)mockPacket.address);
    EXPECT_EQ(0U, mockPacket.priority);
    Protocol::DataHeader* header =
        static_cast<Protocol::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(context->msgId, header->common.msgId);
    EXPECT_EQ(context->messageLength, header->totalLength);
    EXPECT_EQ(1U, sender.sendQueue.size());
    EXPECT_EQ(1U, sender.outboundPool.outstandingObjects);
    auto it = sender.messageMap.find(context->msgId);
    EXPECT_TRUE(it != sender.messageMap.end());
    Sender::OutboundMessage* message = it->second;
    EXPECT_EQ(message, sender.sendQueue.front());
    EXPECT_EQ(419U, message->grantOffset);
    EXPECT_EQ(0U, message->grantIndex);
}

TEST_F(SenderTest, sendMessage_multipacket)
{
    char payload0[1024];
    char payload1[1024];
    NiceMock<MockDriver::MockPacket> packet0(payload0);
    NiceMock<MockDriver::MockPacket> packet1(payload1);
    MessageContext* context = messagePool->construct(
        {42, 1}, sizeof(Protocol::DataHeader), &mockDriver);
    context->setPacket(0, &packet0);
    context->setPacket(1, &packet1);
    context->messageLength = 1420;
    packet0.length = 1000 + 24;
    packet1.length = 420 + 24;
    context->address = (Driver::Address*)22;

    EXPECT_EQ(24U, sizeof(Protocol::DataHeader));
    EXPECT_EQ(1000U, context->PACKET_DATA_LENGTH);

    sender.sendMessage(context);

    Protocol::DataHeader* header = nullptr;
    // Packet0
    EXPECT_EQ(22U, (uint64_t)packet0.address);
    EXPECT_EQ(0U, packet0.priority);
    header = static_cast<Protocol::DataHeader*>(packet0.payload);
    EXPECT_EQ(context->msgId, header->common.msgId);
    EXPECT_EQ(context->messageLength, header->totalLength);

    // Packet1
    EXPECT_EQ(22U, (uint64_t)packet1.address);
    EXPECT_EQ(0U, packet1.priority);
    header = static_cast<Protocol::DataHeader*>(packet1.payload);
    EXPECT_EQ(context->msgId, header->common.msgId);
    EXPECT_EQ(context->messageLength, header->totalLength);
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

    MessageContext* context = messagePool->construct(
        {42, 1}, sizeof(Protocol::DataHeader), &mockDriver);
    context->setPacket(1, &mockPacket);

    EXPECT_EQ(0U, sender.sendQueue.size());
    EXPECT_EQ(0U, sender.outboundPool.outstandingObjects);

    sender.sendMessage(context);

    EXPECT_EQ(0U, sender.sendQueue.size());
    EXPECT_EQ(0U, sender.outboundPool.outstandingObjects);

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("sendMessage", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ(
        "Incomplete message with id (42l:1l); missing packet at offset 0; "
        "send request dropped.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, sendMessage_duplicateMessage)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    MessageContext* context = messagePool->construct(
        {42, 1}, sizeof(Protocol::DataHeader), &mockDriver);
    context->setPacket(0, &mockPacket);
    context->messageLength = 420;
    mockPacket.length = context->messageLength + context->DATA_HEADER_LENGTH;
    context->address = (Driver::Address*)22;

    // First send should succeed.
    sender.sendMessage(context);

    EXPECT_EQ(2U, context->refCount);
    EXPECT_EQ(0U, handler.messages.size());

    // Second send should be dropped.
    sender.sendMessage(context);

    EXPECT_EQ(2U, context->refCount);
    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/Sender.cc", m.filename);
    EXPECT_STREQ("sendMessage", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ(
        "Duplicate call to sendMessage for msgId (42l:1l); "
        "send request dropped.",
        m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(SenderTest, sendMessage_unsheduledLimit)
{
    MessageContext* context = messagePool->construct(
        {42, 1}, sizeof(Protocol::DataHeader), &mockDriver);
    for (int i = 0; i < 9; ++i) {
        context->setPacket(i, &mockPacket);
    }
    context->messageLength = 9000;
    mockPacket.length = 1000 + 24;
    context->address = (Driver::Address*)22;
    EXPECT_EQ(9U, context->getNumPackets());
    EXPECT_EQ(1000U, context->PACKET_DATA_LENGTH);

    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));

    sender.sendMessage(context);

    auto it = sender.messageMap.find(context->msgId);
    EXPECT_TRUE(it != sender.messageMap.end());
    Sender::OutboundMessage* message = it->second;
    EXPECT_EQ(message, sender.sendQueue.front());
    EXPECT_EQ(4999U, message->grantOffset);
    EXPECT_EQ(4U, message->grantIndex);
}

TEST_F(SenderTest, trySend_basic)
{
    MessageContext* context[3];
    Sender::OutboundMessage* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        context[i] = messagePool->construct({42, 10 + i}, 24, &mockDriver);
        message[i] = SenderTest::addMessage(&sender, context[i], 4999);
        sender.sendQueue.push_back(message[i]);
    }

    // Message 0: All packets sent
    context[0]->messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[0]->sentIndex = 4;
    for (int i = 0; i < 5; ++i) {
        context[0]->setPacket(i, nullptr);
    }

    // Message 1: Waiting for more grants
    context[1]->messageLength = 9000;
    EXPECT_EQ(4, message[1]->grantIndex);
    message[1]->sentIndex = 4;
    for (int i = 0; i < 9; ++i) {
        context[1]->setPacket(i, nullptr);
    }

    // Message 2: New message, send 5 packets
    context[2]->messageLength = 9000;
    EXPECT_EQ(4, message[2]->grantIndex);
    EXPECT_EQ(-1, message[2]->sentIndex);
    for (int i = 0; i < 9; ++i) {
        context[2]->setPacket(i, &mockPacket);
    }

    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(5);

    sender.trySend();

    EXPECT_EQ(4U, message[0]->sentIndex);
    EXPECT_EQ(4U, message[1]->sentIndex);
    EXPECT_EQ(4U, message[2]->sentIndex);
}

TEST_F(SenderTest, trySend_alreadyRunning)
{
    MessageContext* context = messagePool->construct({42, 1}, 24, &mockDriver);
    context->setPacket(0, &mockPacket);
    context->messageLength = 1000;
    EXPECT_EQ(1U, context->getNumPackets());
    Sender::OutboundMessage* message =
        SenderTest::addMessage(&sender, context, 999);
    EXPECT_EQ(0, message->grantIndex);
    EXPECT_EQ(-1, message->sentIndex);
    sender.sendQueue.push_back(message);

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
    MessageContext* context[3];
    Sender::OutboundMessage* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        context[i] = messagePool->construct({42, 10 + i}, 24, &mockDriver);
        message[i] = SenderTest::addMessage(&sender, context[i], 4999);
        sender.sendQueue.push_back(message[i]);
    }

    // Message 0: All packets sent
    context[0]->messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[0]->sentIndex = 4;
    for (int i = 0; i < 5; ++i) {
        context[0]->setPacket(i, nullptr);
    }
    EXPECT_EQ(5U, context[0]->getNumPackets());

    // Message 1: Waiting for more grants
    context[1]->messageLength = 9000;
    EXPECT_EQ(4, message[1]->grantIndex);
    message[1]->sentIndex = 4;
    for (int i = 0; i < 9; ++i) {
        context[1]->setPacket(i, nullptr);
    }

    // Message 2: All packets sent
    context[2]->messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[2]->sentIndex = 4;
    for (int i = 0; i < 5; ++i) {
        context[2]->setPacket(i, nullptr);
    }

    EXPECT_EQ(2U, context[0]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[0]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(2U, context[1]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[1]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(2U, context[2]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[2]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(3U, sender.sendQueue.size());
    EXPECT_EQ(3U, sender.outboundPool.outstandingObjects);

    // Clean Message 0
    sender.cleanup();

    EXPECT_EQ(1U, context[0]->refCount);
    EXPECT_FALSE(sender.messageMap.find(context[0]->msgId) !=
                 sender.messageMap.end());
    EXPECT_EQ(2U, context[1]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[1]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(2U, context[2]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[2]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(2U, sender.sendQueue.size());
    EXPECT_EQ(2U, sender.outboundPool.outstandingObjects);

    // Clean Nothing
    sender.cleanup();

    EXPECT_EQ(2U, context[1]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[1]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(2U, context[2]->refCount);
    EXPECT_TRUE(sender.messageMap.find(context[2]->msgId) !=
                sender.messageMap.end());
    EXPECT_EQ(2U, sender.sendQueue.size());
    EXPECT_EQ(2U, sender.outboundPool.outstandingObjects);

    message[1]->sentIndex = 9;

    // Clean All
    sender.cleanup();

    EXPECT_EQ(1U, context[1]->refCount);
    EXPECT_FALSE(sender.messageMap.find(context[1]->msgId) !=
                 sender.messageMap.end());
    EXPECT_EQ(1U, context[2]->refCount);
    EXPECT_FALSE(sender.messageMap.find(context[2]->msgId) !=
                 sender.messageMap.end());
    EXPECT_EQ(0U, sender.sendQueue.size());
    EXPECT_EQ(0U, sender.outboundPool.outstandingObjects);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
