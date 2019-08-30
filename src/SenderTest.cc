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

#include <Cycles.h>

#include <Homa/Debug.h>

#include "Mock/MockDriver.h"
#include "Mock/MockPolicy.h"
#include "Transport.h"

namespace Homa {
namespace Core {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;

class SenderTest : public ::testing::Test {
  public:
    SenderTest()
        : mockDriver()
        , mockPacket(&payload)
        , mockPolicyManager(&mockDriver)
        , transport()
        , sender()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1027));
        ON_CALL(mockDriver, getQueuedBytes).WillByDefault(Return(0));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        transport = new Transport(&mockDriver, 22);
        sender = transport->sender.get();
        sender->policyManager = &mockPolicyManager;
        sender->messageTimeouts.timeoutIntervalCycles = 1000;
        sender->pingTimeouts.timeoutIntervalCycles = 100;
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~SenderTest()
    {
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
        PerfUtils::Cycles::mockTscValue = 0;
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    NiceMock<Homa::Mock::MockDriver::MockPacket> mockPacket;
    NiceMock<Homa::Mock::MockPolicyManager> mockPolicyManager;
    char payload[1028];
    Transport* transport;
    Sender* sender;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;

    static Sender::Message* addMessage(Sender* sender, Protocol::MessageId id,
                                       Transport::Op* op,
                                       uint16_t grantIndex = 0)
    {
        Sender::Message* message = &op->outMessage;
        message->id = id;
        message->grantIndex = grantIndex;
        sender->outboundMessages.insert({id, message});
        sender->messageTimeouts.list.push_back(&message->messageTimeout.node);
        sender->pingTimeouts.list.push_back(&message->pingTimeout.node);
        return message;
    }
};

TEST_F(SenderTest, handleDonePacket)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = &op->outMessage;
    sender->messageTimeouts.setTimeout(&message->messageTimeout);
    sender->pingTimeouts.setTimeout(&message->pingTimeout);
    EXPECT_NE(Sender::Message::State::COMPLETED, message->state);

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(2);

    sender->handleDonePacket(&mockPacket, &mockDriver);

    EXPECT_EQ(&sender->messageTimeouts.list, message->messageTimeout.node.list);
    EXPECT_EQ(&sender->pingTimeouts.list, message->pingTimeout.node.list);
    EXPECT_NE(Sender::Message::State::COMPLETED, message->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    sender->outboundMessages.insert({id, message});

    sender->handleDonePacket(&mockPacket, &mockDriver);

    EXPECT_EQ(nullptr, message->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message->pingTimeout.node.list);
    EXPECT_EQ(Sender::Message::State::COMPLETED, message->state);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
}

TEST_F(SenderTest, handleResendPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    std::vector<Homa::Mock::MockDriver::MockPacket*> packets;
    for (int i = 0; i < 10; ++i) {
        packets.push_back(new Homa::Mock::MockDriver::MockPacket(payload));
        message->setPacket(i, packets[i]);
    }
    message->sentIndex = 5;
    message->grantIndex = 5;
    message->priority = 6;
    EXPECT_EQ(10U, message->getNumPackets());

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 3;
    resendHdr->num = 5;
    resendHdr->priority = 4;

    EXPECT_CALL(mockPolicyManager, getResendPriority).WillOnce(Return(7));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packets[3]))).Times(1);
    EXPECT_CALL(mockDriver, sendPacket(Eq(packets[4]))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(8U, message->grantIndex);
    EXPECT_EQ(4, message->priority);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_EQ(7, packets[3]->priority);
    EXPECT_EQ(7, packets[4]->priority);

    for (int i = 0; i < 10; ++i) {
        delete packets[i];
    }
}

TEST_F(SenderTest, handleResendPacket_staleResend)
{
    Protocol::MessageId id = {42, 1};
    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 3;
    resendHdr->num = 5;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket, &mockDriver);
}

TEST_F(SenderTest, handleResendPacket_eagerResend)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    char data[1028];
    Homa::Mock::MockDriver::MockPacket dataPacket(data);
    for (int i = 0; i < 10; ++i) {
        message->setPacket(i, &dataPacket);
    }
    message->sentIndex = 5;
    message->grantIndex = 5;
    EXPECT_EQ(10U, message->getNumPackets());

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 5;
    resendHdr->num = 3;

    // Expect the BUSY control packet.
    char busy[1028];
    Homa::Mock::MockDriver::MockPacket busyPacket(busy);
    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&busyPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&busyPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&busyPacket), Eq(1)))
        .Times(1);

    // Expect no data to be sent but the RESEND packet to be release.
    EXPECT_CALL(mockDriver, sendPacket(Eq(&dataPacket))).Times(0);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(8U, message->grantIndex);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::BusyHeader* busyHdr =
        static_cast<Protocol::Packet::BusyHeader*>(mockPacket.payload);
    EXPECT_EQ(id, busyHdr->common.messageId);
}

TEST_F(SenderTest, handleGrantPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    message->numPackets = 10;
    EXPECT_EQ(5, message->grantIndex);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->indexLimit = 7;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(7, message->grantIndex);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, handleGrantPacket_staleGrant)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    message->numPackets = 10;
    EXPECT_EQ(5, message->grantIndex);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->pingTimeout.expirationCycleTime);

    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->indexLimit = 4;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleGrantPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(5, message->grantIndex);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, handleGrantPacket_dropGrant)
{
    Protocol::MessageId id = {42, 1};
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->indexLimit = 4;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleGrantPacket(&mockPacket, &mockDriver);
}

TEST_F(SenderTest, handleUnknownPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    message->state.store(Sender::Message::State::SENT);
    message->sentIndex = 5;
    EXPECT_EQ(5, message->grantIndex);
    char packetBuf[sizeof(Protocol::Packet::DataHeader)];
    Homa::Mock::MockDriver::MockPacket packet(&packetBuf);
    packet.length = sizeof(packetBuf);
    static_cast<Protocol::Packet::DataHeader*>(packet.payload)
        ->unscheduledIndexLimit = 3;
    message->setPacket(0, &packet);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(Sender::Message::State::IN_PROGRESS, message->state);
    EXPECT_EQ(0U, message->sentIndex);
    EXPECT_EQ(3U, message->grantIndex);
}

TEST_F(SenderTest, handleUnknownPacket_no_message)
{
    Protocol::MessageId id = {42, 1};

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket, &mockDriver);
}

TEST_F(SenderTest, handleUnknownPacket_done)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    message->state.store(Sender::Message::State::COMPLETED);
    message->sentIndex = 5;
    EXPECT_EQ(5, message->grantIndex);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(Sender::Message::State::COMPLETED, message->state);
    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(5U, message->grantIndex);
}

TEST_F(SenderTest, handleErrorPacket)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = &op->outMessage;
    sender->messageTimeouts.setTimeout(&message->messageTimeout);
    sender->pingTimeouts.setTimeout(&message->pingTimeout);
    message->state.store(Sender::Message::State::IN_PROGRESS);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(2);

    sender->handleErrorPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(&sender->messageTimeouts.list, message->messageTimeout.node.list);
    EXPECT_EQ(&sender->pingTimeouts.list, message->pingTimeout.node.list);
    EXPECT_NE(Sender::Message::State::FAILED, message->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    sender->outboundMessages.insert({id, message});

    sender->handleErrorPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(nullptr, message->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message->pingTimeout.node.list);
    EXPECT_EQ(Sender::Message::State::FAILED, message->state);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
}

TEST_F(SenderTest, sendMessage_basic)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = &op->outMessage;

    message->setPacket(0, &mockPacket);
    message->messageLength = 420;
    mockPacket.length = message->messageLength + message->PACKET_HEADER_LENGTH;
    Driver::Address destination = (Driver::Address)22;
    Core::Policy::Unscheduled policy = {1, 0, 2};

    EXPECT_FALSE(sender->outboundMessages.find(id) !=
                 sender->outboundMessages.end());

    EXPECT_CALL(mockPolicyManager,
                getUnscheduledPolicy(Eq(destination), Eq(420)))
        .WillOnce(Return(policy));

    sender->sendMessage(message, destination);

    EXPECT_EQ(22U, (uint64_t)mockPacket.address);
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(destination, message->destination);
    EXPECT_EQ(Sender::Message::State::IN_PROGRESS, message->state);
    EXPECT_EQ(0U, message->grantIndex);
    EXPECT_EQ(2, message->priority);
    EXPECT_EQ(420U, message->unsentBytes);
    EXPECT_EQ(message->messageLength, header->totalLength);
    EXPECT_TRUE(sender->outboundMessages.find(id) !=
                sender->outboundMessages.end());
    EXPECT_EQ(message, sender->outboundMessages.find(id)->second);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, sendMessage_multipacket)
{
    char payload0[1027];
    char payload1[1027];
    NiceMock<Homa::Mock::MockDriver::MockPacket> packet0(payload0);
    NiceMock<Homa::Mock::MockDriver::MockPacket> packet1(payload1);
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = &op->outMessage;

    message->setPacket(0, &packet0);
    message->setPacket(1, &packet1);
    message->messageLength = 1420;
    packet0.length = 1000 + 27;
    packet1.length = 420 + 27;
    Driver::Address destination = (Driver::Address)22;
    Core::Policy::Unscheduled policy = {1, 1000, 2};

    EXPECT_EQ(27U, sizeof(Protocol::Packet::DataHeader));
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);
    EXPECT_CALL(mockPolicyManager,
                getUnscheduledPolicy(Eq(destination), Eq(1420)))
        .WillOnce(Return(policy));

    sender->sendMessage(message, destination);

    EXPECT_EQ(id, message->id);
    EXPECT_EQ(1U, message->grantIndex);

    Protocol::Packet::DataHeader* header = nullptr;
    // Packet0
    EXPECT_EQ(22U, (uint64_t)packet0.address);
    header = static_cast<Protocol::Packet::DataHeader*>(packet0.payload);
    EXPECT_EQ(message->id, header->common.messageId);
    EXPECT_EQ(message->messageLength, header->totalLength);

    // Packet1
    EXPECT_EQ(22U, (uint64_t)packet1.address);
    header = static_cast<Protocol::Packet::DataHeader*>(packet1.payload);
    EXPECT_EQ(message->id, header->common.messageId);
    EXPECT_EQ(destination, message->destination);
    EXPECT_EQ(message->messageLength, header->totalLength);
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
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = &op->outMessage;
    message->setPacket(1, &mockPacket);
    Core::Policy::Unscheduled policy = {1, 1000, 2};
    ON_CALL(mockPolicyManager, getUnscheduledPolicy(_, _))
        .WillByDefault(Return(policy));

    EXPECT_DEATH(sender->sendMessage(message, Driver::Address()),
                 ".*Incomplete message with id \\(22:1\\); missing packet at "
                 "offset 0; this shouldn't happen.*");
}

TEST_F(SenderTest, sendMessage_unscheduledLimit)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = &op->outMessage;
    for (int i = 0; i < 9; ++i) {
        message->setPacket(i, &mockPacket);
    }
    message->messageLength = 9000;
    mockPacket.length = 1000 + sizeof(Protocol::Packet::DataHeader);
    Driver::Address destination = (Driver::Address)22;
    Core::Policy::Unscheduled policy = {1, 4500, 2};
    EXPECT_EQ(9U, message->getNumPackets());
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);
    EXPECT_CALL(mockPolicyManager, getUnscheduledPolicy(destination, 9000))
        .WillOnce(Return(policy));

    sender->sendMessage(message, destination);

    EXPECT_TRUE(sender->outboundMessages.find(id) !=
                sender->outboundMessages.end());
    EXPECT_EQ(message, sender->outboundMessages.find(id)->second);
    EXPECT_EQ(id, message->id);
    EXPECT_EQ(destination, message->destination);
    EXPECT_EQ(5U, message->grantIndex);
}

TEST_F(SenderTest, dropMessage)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 5);
    message->messageLength = 9000;
    EXPECT_FALSE(sender->messageTimeouts.list.empty());
    EXPECT_FALSE(sender->pingTimeouts.list.empty());

    sender->dropMessage(message);

    EXPECT_TRUE(sender->messageTimeouts.list.empty());
    EXPECT_TRUE(sender->pingTimeouts.list.empty());
    EXPECT_FALSE(sender->outboundMessages.find(id) !=
                 sender->outboundMessages.end());
}

TEST_F(SenderTest, poll)
{
    // Nothing to test.
    sender->poll();
}

TEST_F(SenderTest, checkMessageTimeouts_basic)
{
    Transport::Op* op[4];
    Sender::Message* message[4];
    for (uint64_t i = 0; i < 4; ++i) {
        Protocol::OpId opId = {0, 0};
        Protocol::MessageId id = {42, 10 + i};
        op[i] = transport->opPool.construct(transport, &mockDriver, opId);
        message[i] = SenderTest::addMessage(sender, id, op[i]);
        sender->messageTimeouts.setTimeout(&message[i]->messageTimeout);
        sender->pingTimeouts.setTimeout(&message[i]->pingTimeout);
    }

    // Message[0]: Normal timeout: IN_PROGRESS
    message[0]->messageTimeout.expirationCycleTime = 9998;
    message[0]->state = Sender::Message::State::IN_PROGRESS;
    // Message[1]: Normal timeout: SENT
    message[1]->messageTimeout.expirationCycleTime = 9999;
    message[1]->state = Sender::Message::State::SENT;
    // Message[2]: Normal timeout: COMPLETED
    message[2]->messageTimeout.expirationCycleTime = 10000;
    message[2]->state = Sender::Message::State::COMPLETED;
    // Message[3]: No timeout
    message[3]->messageTimeout.expirationCycleTime = 10001;
    message[3]->state = Sender::Message::State::SENT;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    sender->checkMessageTimeouts();

    // Message[0]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(nullptr, message[0]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->pingTimeout.node.list);
    EXPECT_EQ(Sender::Message::State::FAILED, message[0]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[0]));
    // Message[1]: Normal timeout: SENT
    EXPECT_EQ(nullptr, message[1]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[1]->pingTimeout.node.list);
    EXPECT_EQ(Sender::Message::State::FAILED, message[1]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[1]));
    // Message[2]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[2]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[2]->pingTimeout.node.list);
    EXPECT_EQ(Sender::Message::State::COMPLETED, message[2]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[2]));
    // Message[3]: No timeout
    EXPECT_EQ(&sender->messageTimeouts.list,
              message[3]->messageTimeout.node.list);
    EXPECT_EQ(&sender->pingTimeouts.list, message[3]->pingTimeout.node.list);
    EXPECT_EQ(Sender::Message::State::SENT, message[3]->getState());
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[3]));
}

TEST_F(SenderTest, checkMessageTimeouts_empty)
{
    // Nothing to test except to ensure the call doesn't loop infinitely.
    EXPECT_TRUE(sender->messageTimeouts.list.empty());
    sender->checkMessageTimeouts();
}

TEST_F(SenderTest, trySend_basic)
{
    Protocol::MessageId id = {42, 10};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 3);
    sender->readyQueue.push_back(&message->readyQueueNode);
    Homa::Mock::MockDriver::MockPacket* packet[5];
    const uint32_t PACKET_SIZE = sender->transport->driver->getMaxPayloadSize();
    const uint32_t PACKET_DATA_SIZE =
        PACKET_SIZE - message->PACKET_HEADER_LENGTH;
    for (int i = 0; i < 5; ++i) {
        packet[i] = new Homa::Mock::MockDriver::MockPacket(payload);
        packet[i]->length = PACKET_SIZE;
        message->setPacket(i, packet[i]);
        message->unsentBytes += PACKET_DATA_SIZE;
    }
    EXPECT_EQ(5U, message->getNumPackets());
    EXPECT_EQ(3U, message->grantIndex);
    EXPECT_EQ(0U, message->sentIndex);
    EXPECT_EQ(5 * PACKET_DATA_SIZE, message->unsentBytes);
    EXPECT_NE(Sender::Message::State::SENT, message->state);
    EXPECT_TRUE(sender->readyQueue.contains(&message->readyQueueNode));

    // 3 granted packets; 2 will send; queue limit reached.
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[0])));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[1])));
    sender->trySend();  // < test call
    EXPECT_EQ(3U, message->grantIndex);
    EXPECT_EQ(2U, message->sentIndex);
    EXPECT_EQ(3 * PACKET_DATA_SIZE, message->unsentBytes);
    EXPECT_NE(Sender::Message::State::SENT, message->state);
    EXPECT_TRUE(sender->readyQueue.contains(&message->readyQueueNode));
    Mock::VerifyAndClearExpectations(&mockDriver);

    // 1 packet to be sent; grant limit reached.
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[2])));
    sender->trySend();  // < test call
    EXPECT_EQ(3U, message->grantIndex);
    EXPECT_EQ(3U, message->sentIndex);
    EXPECT_EQ(2 * PACKET_DATA_SIZE, message->unsentBytes);
    EXPECT_NE(Sender::Message::State::SENT, message->state);
    EXPECT_FALSE(sender->readyQueue.contains(&message->readyQueueNode));
    Mock::VerifyAndClearExpectations(&mockDriver);

    // No additional grants; spurious ready hint.
    EXPECT_CALL(mockDriver, sendPacket).Times(0);
    sender->readyQueue.push_back(&message->readyQueueNode);
    sender->trySend();  // < test call
    EXPECT_EQ(3U, message->grantIndex);
    EXPECT_EQ(3U, message->sentIndex);
    EXPECT_EQ(2 * PACKET_DATA_SIZE, message->unsentBytes);
    EXPECT_NE(Sender::Message::State::SENT, message->state);
    EXPECT_FALSE(sender->readyQueue.contains(&message->readyQueueNode));
    Mock::VerifyAndClearExpectations(&mockDriver);

    // 2 more granted packets; will finish.
    message->grantIndex = 5;
    sender->readyQueue.push_back(&message->readyQueueNode);
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[3])));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[4])));
    sender->trySend();  // < test call
    EXPECT_EQ(5U, message->grantIndex);
    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(0 * PACKET_DATA_SIZE, message->unsentBytes);
    EXPECT_EQ(Sender::Message::State::SENT, message->state);
    EXPECT_FALSE(sender->readyQueue.contains(&message->readyQueueNode));
    Mock::VerifyAndClearExpectations(&mockDriver);

    for (int i = 0; i < 5; ++i) {
        delete packet[i];
    }
}

TEST_F(SenderTest, trySend_multipleMessages)
{
    Transport::Op* op[3];
    Sender::Message* message[3];
    Homa::Mock::MockDriver::MockPacket* packet[3];
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::OpId opId = {42, i};
        Protocol::MessageId id = {22, 10 + i};
        op[i] = transport->opPool.construct(transport, &mockDriver, opId);
        message[i] = SenderTest::addMessage(sender, id, op[i], 1);
        packet[i] = new Homa::Mock::MockDriver::MockPacket(payload);
        packet[i]->length = sender->transport->driver->getMaxPayloadSize() / 4;
        message[i]->setPacket(0, packet[i]);
        message[i]->unsentBytes +=
            (packet[i]->length - message[i]->PACKET_HEADER_LENGTH);
        sender->readyQueue.push_back(&message[i]->readyQueueNode);
    }

    // Message 0: Will finish
    EXPECT_EQ(1, message[0]->grantIndex);
    message[0]->sentIndex = 0;

    // Message 1: Will reach grant limit
    EXPECT_EQ(1, message[1]->grantIndex);
    message[1]->sentIndex = 0;
    message[1]->setPacket(1, nullptr);
    EXPECT_EQ(2, message[1]->getNumPackets());

    // Message 2: Will finish
    EXPECT_EQ(1, message[2]->grantIndex);
    message[2]->sentIndex = 0;

    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[0])));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[1])));
    EXPECT_CALL(mockDriver, sendPacket(Eq(packet[2])));

    sender->trySend();

    EXPECT_EQ(1U, message[0]->sentIndex);
    EXPECT_EQ(Sender::Message::State::SENT, message[0]->state);
    EXPECT_FALSE(sender->readyQueue.contains(&message[0]->readyQueueNode));
    EXPECT_EQ(1U, message[1]->sentIndex);
    EXPECT_NE(Sender::Message::State::SENT, message[1]->state);
    EXPECT_FALSE(sender->readyQueue.contains(&message[1]->readyQueueNode));
    EXPECT_EQ(1U, message[2]->sentIndex);
    EXPECT_EQ(Sender::Message::State::SENT, message[2]->state);
    EXPECT_FALSE(sender->readyQueue.contains(&message[2]->readyQueueNode));
}

TEST_F(SenderTest, trySend_alreadyRunning)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    Sender::Message* message = SenderTest::addMessage(sender, id, op, 1);
    sender->readyQueue.push_back(&message->readyQueueNode);
    message->setPacket(0, &mockPacket);
    message->messageLength = 1000;
    EXPECT_EQ(1U, message->getNumPackets());
    EXPECT_EQ(1, message->grantIndex);
    EXPECT_EQ(0, message->sentIndex);

    sender->sending.test_and_set();

    EXPECT_CALL(mockDriver, sendPacket).Times(0);

    sender->trySend();

    EXPECT_EQ(0, message->sentIndex);
}

TEST_F(SenderTest, trySend_nothingToSend)
{
    EXPECT_TRUE(sender->readyQueue.empty());
    EXPECT_CALL(mockDriver, sendPacket).Times(0);
    sender->trySend();
}

TEST_F(SenderTest, checkPingTimeouts_basic)
{
    Transport::Op* op[4];
    Sender::Message* message[4];
    for (uint64_t i = 0; i < 4; ++i) {
        Protocol::OpId opId = {0, 0};
        Protocol::MessageId id = {42, 10 + i};
        op[i] = transport->opPool.construct(transport, &mockDriver, opId);
        message[i] = SenderTest::addMessage(sender, id, op[i]);
        sender->pingTimeouts.setTimeout(&message[i]->pingTimeout);
    }

    // Message[0]: Normal timeout: COMPLETED
    message[0]->state = Sender::Message::State::COMPLETED;
    message[0]->pingTimeout.expirationCycleTime = 9998;
    // Message[1]: Normal timeout: FAILED
    message[1]->state = Sender::Message::State::FAILED;
    message[1]->pingTimeout.expirationCycleTime = 9999;
    // Message[2]: Normal timeout: SENT
    message[2]->state = Sender::Message::State::SENT;
    message[2]->pingTimeout.expirationCycleTime = 10000;
    // Message[3]: No timeout
    message[3]->pingTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->checkPingTimeouts();

    // Message[0]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[0]->pingTimeout.node.list);
    // Message[1]: Normal timeout: FAILED
    EXPECT_EQ(nullptr, message[1]->pingTimeout.node.list);
    // Message[2]: Normal timeout: SENT
    EXPECT_EQ(10100, message[2]->pingTimeout.expirationCycleTime);
    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::PING, header->opcode);
    EXPECT_EQ(message[2]->id, header->messageId);
    // Message[3]: No timeout
    EXPECT_EQ(10001, message[3]->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, checkPingTimeouts_empty)
{
    // Nothing to test except to ensure the call doesn't loop infinitely.
    EXPECT_TRUE(sender->pingTimeouts.list.empty());
    sender->checkPingTimeouts();
}

TEST_F(SenderTest, hintMessageReady)
{
    Sender::Message* message[3];
    for (int i = 0; i < 3; ++i) {
        Protocol::OpId opId = {0, 0};
        message[i] = &transport->opPool.construct(transport, &mockDriver, opId)
                          ->outMessage;
        message[i]->unsentBytes = (i + 1) * 1000;
    }

    EXPECT_TRUE(sender->readyQueue.empty());

    // Queue([1]) : EXPECT ->[1]->
    {
        SpinLock::UniqueLock lock(sender->mutex);
        SpinLock::Lock lock_message(message[1]->mutex);
        sender->hintMessageReady(message[1], lock, lock_message);
    }
    EXPECT_TRUE(sender->readyQueue.contains(&message[1]->readyQueueNode));
    auto it = sender->readyQueue.begin();
    EXPECT_EQ(message[1], (it++).node->owner);
    EXPECT_EQ(sender->readyQueue.end(), it);

    // Queue([1]) again : EXPECT ->[1]->
    {
        SpinLock::UniqueLock lock(sender->mutex);
        SpinLock::Lock lock_message(message[1]->mutex);
        sender->hintMessageReady(message[1], lock, lock_message);
    }
    EXPECT_TRUE(sender->readyQueue.contains(&message[1]->readyQueueNode));
    it = sender->readyQueue.begin();
    EXPECT_EQ(message[1], (it++).node->owner);
    EXPECT_EQ(sender->readyQueue.end(), it);

    // Queue([0]) : EXPECT ->[0]->[1]->
    {
        SpinLock::UniqueLock lock(sender->mutex);
        SpinLock::Lock lock_message(message[0]->mutex);
        sender->hintMessageReady(message[0], lock, lock_message);
    }
    EXPECT_TRUE(sender->readyQueue.contains(&message[0]->readyQueueNode));
    it = sender->readyQueue.begin();
    EXPECT_EQ(message[0], (it++).node->owner);
    EXPECT_EQ(message[1], (it++).node->owner);
    EXPECT_EQ(sender->readyQueue.end(), it);

    // Queue([2]) : EXPECT ->[0]->[1]->[2]->
    {
        SpinLock::UniqueLock lock(sender->mutex);
        SpinLock::Lock lock_message(message[2]->mutex);
        sender->hintMessageReady(message[2], lock, lock_message);
    }
    EXPECT_TRUE(sender->readyQueue.contains(&message[2]->readyQueueNode));
    it = sender->readyQueue.begin();
    EXPECT_EQ(message[0], (it++).node->owner);
    EXPECT_EQ(message[1], (it++).node->owner);
    EXPECT_EQ(message[2], (it++).node->owner);
    EXPECT_EQ(sender->readyQueue.end(), it);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
