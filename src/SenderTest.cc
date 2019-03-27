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

#include "Sender.h"

#include <Homa/Debug.h>

#include "Mock/MockDriver.h"
#include "Transport.h"

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
        , transport()
        , sender()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1028));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        transport = new Transport(&mockDriver, 1);
    }

    ~SenderTest()
    {
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    NiceMock<Homa::Mock::MockDriver::MockPacket> mockPacket;
    char payload[1028];
    Transport* transport;
    Sender sender;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;

    static OutboundMessage* addMessage(Sender* sender, Protocol::MessageId id,
                                       Transport::Op* op,
                                       uint32_t grantOffset = 0)
    {
        OutboundMessage* message = &op->outMessage;
        message->id = id;
        message->grantOffset = grantOffset;
        message->grantIndex =
            message->grantOffset / message->message.PACKET_DATA_LENGTH;
        sender->outboundMessages.insert({id, op});
        return message;
    }
};

TEST_F(SenderTest, handleDonePacket)
{
    Protocol::MessageId id = {42, 1, 32};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.acknowledged = false;

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(2);

    sender.handleDonePacket(&mockPacket, &mockDriver);

    EXPECT_FALSE(op->outMessage.acknowledged);

    sender.outboundMessages.insert({id, op});

    sender.handleDonePacket(&mockPacket, &mockDriver);

    EXPECT_TRUE(op->outMessage.acknowledged);
}

TEST_F(SenderTest, handleGrantPacket_basic)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.messageLength = 9000;
    OutboundMessage* message = SenderTest::addMessage(&sender, msgId, op, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 6500;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(6500, message->grantOffset);
    EXPECT_EQ(6, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_staleGrant)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.messageLength = 9000;
    OutboundMessage* message = SenderTest::addMessage(&sender, msgId, op, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 4000;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(4999, message->grantOffset);
    EXPECT_EQ(4, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_excessGrant)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.messageLength = 9000;
    OutboundMessage* message = SenderTest::addMessage(&sender, msgId, op, 4999);
    EXPECT_EQ(4, message->grantIndex);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 9001;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(8999, message->grantOffset);
    EXPECT_EQ(8, message->grantIndex);
}

TEST_F(SenderTest, handleGrantPacket_dropGrant)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = msgId;
    header->offset = 6500;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender.handleGrantPacket(&mockPacket, &mockDriver);
}

TEST_F(SenderTest, sendMessage_basic)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);

    op->outMessage.message.setPacket(0, &mockPacket);
    op->outMessage.message.messageLength = 420;
    mockPacket.length = op->outMessage.message.messageLength +
                        op->outMessage.message.PACKET_HEADER_LENGTH;
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_FALSE(sender.outboundMessages.find(msgId) !=
                 sender.outboundMessages.end());

    sender.sendMessage(msgId, destination, op);

    EXPECT_EQ(22U, (uint64_t)mockPacket.address);
    EXPECT_EQ(0U, mockPacket.priority);
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(op->outMessage.id, header->common.messageId);
    EXPECT_EQ(destination, op->outMessage.destination);
    EXPECT_EQ(op->outMessage.message.messageLength, header->totalLength);
    EXPECT_TRUE(sender.outboundMessages.find(msgId) !=
                sender.outboundMessages.end());
    EXPECT_EQ(op, sender.outboundMessages.find(msgId)->second);
    EXPECT_EQ(419U, op->outMessage.grantOffset);
    EXPECT_EQ(0U, op->outMessage.grantIndex);
}

TEST_F(SenderTest, sendMessage_multipacket)
{
    char payload0[1028];
    char payload1[1028];
    NiceMock<Homa::Mock::MockDriver::MockPacket> packet0(payload0);
    NiceMock<Homa::Mock::MockDriver::MockPacket> packet1(payload1);
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);

    op->outMessage.message.setPacket(0, &packet0);
    op->outMessage.message.setPacket(1, &packet1);
    op->outMessage.message.messageLength = 1420;
    packet0.length = 1000 + 28;
    packet1.length = 420 + 28;
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_EQ(28U, sizeof(Protocol::Packet::DataHeader));
    EXPECT_EQ(1000U, op->outMessage.message.PACKET_DATA_LENGTH);

    sender.sendMessage(msgId, destination, op);

    Protocol::Packet::DataHeader* header = nullptr;
    // Packet0
    EXPECT_EQ(22U, (uint64_t)packet0.address);
    EXPECT_EQ(0U, packet0.priority);
    header = static_cast<Protocol::Packet::DataHeader*>(packet0.payload);
    EXPECT_EQ(op->outMessage.id, header->common.messageId);
    EXPECT_EQ(op->outMessage.message.messageLength, header->totalLength);

    // Packet1
    EXPECT_EQ(22U, (uint64_t)packet1.address);
    EXPECT_EQ(0U, packet1.priority);
    header = static_cast<Protocol::Packet::DataHeader*>(packet1.payload);
    EXPECT_EQ(op->outMessage.id, header->common.messageId);
    EXPECT_EQ(destination, op->outMessage.destination);
    EXPECT_EQ(op->outMessage.message.messageLength, header->totalLength);
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
    // VectorHandler handler;
    // Debug::setLogHandler(std::ref(handler));

    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.setPacket(1, &mockPacket);

    EXPECT_DEATH(sender.sendMessage(msgId, nullptr, op),
                 ".*Incomplete message with id \\(42:1:1\\); missing packet at "
                 "offset 0; this shouldn't happen.*");
}

TEST_F(SenderTest, sendMessage_duplicateMessage)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.setPacket(0, &mockPacket);
    op->outMessage.message.messageLength = 420;
    mockPacket.length = op->outMessage.message.messageLength +
                        op->outMessage.message.PACKET_HEADER_LENGTH;
    Driver::Address* destination = (Driver::Address*)22;

    // First send should succeed.
    sender.sendMessage(msgId, destination, op);

    EXPECT_EQ(0U, handler.messages.size());

    // Second send should be dropped.
    sender.sendMessage(msgId, destination, op);

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
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    for (int i = 0; i < 9; ++i) {
        op->outMessage.message.setPacket(i, &mockPacket);
    }
    op->outMessage.message.messageLength = 9000;
    mockPacket.length = 1000 + sizeof(Protocol::Packet::DataHeader);
    Driver::Address* destination = (Driver::Address*)22;
    EXPECT_EQ(9U, op->outMessage.message.getNumPackets());
    EXPECT_EQ(1000U, op->outMessage.message.PACKET_DATA_LENGTH);

    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));

    sender.sendMessage(msgId, destination, op);

    EXPECT_TRUE(sender.outboundMessages.find(msgId) !=
                sender.outboundMessages.end());
    EXPECT_EQ(op, sender.outboundMessages.find(msgId)->second);
    EXPECT_EQ(msgId, op->outMessage.id);
    EXPECT_EQ(destination, op->outMessage.destination);
    EXPECT_EQ(4999U, op->outMessage.grantOffset);
    EXPECT_EQ(4U, op->outMessage.grantIndex);
}

TEST_F(SenderTest, dropMessage)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.messageLength = 9000;
    OutboundMessage* message = SenderTest::addMessage(&sender, msgId, op, 4999);

    sender.dropMessage(op);

    EXPECT_FALSE(sender.outboundMessages.find(msgId) !=
                 sender.outboundMessages.end());
}

TEST_F(SenderTest, poll)
{
    // Nothing to test.
    sender.poll();
}

TEST_F(SenderTest, trySend_basic)
{
    Transport::Op* op[4];
    OutboundMessage* message[4];
    for (uint64_t i = 0; i < 4; ++i) {
        op[i] = transport->opPool.construct(transport, &mockDriver);
        Protocol::MessageId msgId = {42, 10 + i, 1};
        message[i] = SenderTest::addMessage(&sender, msgId, op[i], 4999);
    }

    // Message 0: All packets sent
    message[0]->message.messageLength = 5000;
    EXPECT_EQ(4, message[0]->grantIndex);
    message[0]->sentIndex = 4;
    message[0]->sent = true;
    for (int i = 0; i < 5; ++i) {
        message[0]->message.setPacket(i, nullptr);
    }

    // Message 1: Waiting for more grants
    message[1]->message.messageLength = 9000;
    EXPECT_EQ(4, message[1]->grantIndex);
    message[1]->sentIndex = 4;
    for (int i = 0; i < 9; ++i) {
        message[1]->message.setPacket(i, nullptr);
    }

    // Message 2: New message, send 5 packets
    message[2]->message.messageLength = 9000;
    EXPECT_EQ(4, message[2]->grantIndex);
    EXPECT_EQ(-1, message[2]->sentIndex);
    for (int i = 0; i < 9; ++i) {
        message[2]->message.setPacket(i, &mockPacket);
    }

    // Message 3: Send 5 packets to complete send.
    message[3]->message.messageLength = 5000;
    EXPECT_EQ(4, message[3]->grantIndex);
    EXPECT_EQ(-1, message[3]->sentIndex);
    for (int i = 0; i < 5; ++i) {
        message[3]->message.setPacket(i, &mockPacket);
    }

    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(5);

    sender.trySend();

    EXPECT_EQ(4U, message[0]->sentIndex);
    EXPECT_TRUE(message[0]->sent);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[0]));
    EXPECT_EQ(4U, message[1]->sentIndex);
    EXPECT_FALSE(message[1]->sent);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[1]));
    EXPECT_EQ(4U, message[2]->sentIndex);
    EXPECT_FALSE(message[2]->sent);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[2]));

    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(5);

    sender.trySend();

    EXPECT_EQ(4U, message[3]->sentIndex);
    EXPECT_TRUE(message[3]->sent);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[3]));
}

TEST_F(SenderTest, trySend_alreadyRunning)
{
    Protocol::MessageId msgId = {42, 1, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->outMessage.message.setPacket(0, &mockPacket);
    op->outMessage.message.messageLength = 1000;
    EXPECT_EQ(1U, op->outMessage.message.getNumPackets());
    OutboundMessage* message = SenderTest::addMessage(&sender, msgId, op, 999);
    EXPECT_EQ(0, message->grantIndex);
    EXPECT_EQ(-1, message->sentIndex);

    sender.sending.test_and_set();

    EXPECT_CALL(mockDriver, sendPackets).Times(0);

    sender.trySend();

    EXPECT_EQ(-1, message->sentIndex);
}

TEST_F(SenderTest, trySend_nothingToSend)
{
    EXPECT_TRUE(sender.outboundMessages.empty());
    EXPECT_CALL(mockDriver, sendPackets).Times(0);
    sender.trySend();
}

}  // namespace
}  // namespace Core
}  // namespace Homa
