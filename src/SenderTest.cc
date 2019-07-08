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
#include "Transport.h"

namespace Homa {
namespace Core {
namespace {

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
        , transport()
        , sender()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        transport = new Transport(&mockDriver, 22);
        sender = transport->sender.get();
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
    char payload[1028];
    Transport* transport;
    Sender* sender;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;

    static OutboundMessage* addMessage(Sender* sender, Protocol::MessageId id,
                                       Transport::Op* op,
                                       uint16_t grantIndex = 0)
    {
        OutboundMessage* message = &op->outMessage;
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
    OutboundMessage* message = &op->outMessage;
    EXPECT_NE(OutboundMessage::State::COMPLETED, message->state);

    Protocol::Packet::DoneHeader* header =
        static_cast<Protocol::Packet::DoneHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(2);

    sender->handleDonePacket(&mockPacket, &mockDriver);

    EXPECT_NE(OutboundMessage::State::COMPLETED, message->state);
    EXPECT_EQ(0U, message->messageTimeout.expirationCycleTime);

    sender->outboundMessages.insert({id, message});

    sender->handleDonePacket(&mockPacket, &mockDriver);

    EXPECT_EQ(OutboundMessage::State::COMPLETED, message->state);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
}

TEST_F(SenderTest, handleResendPacket_basic)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
    std::vector<Homa::Mock::MockDriver::MockPacket*> packets;
    for (int i = 0; i < 10; ++i) {
        packets.push_back(new Homa::Mock::MockDriver::MockPacket(payload));
        message->setPacket(i, packets[i]);
    }
    message->sentIndex = 5;
    message->grantIndex = 5;
    EXPECT_EQ(10U, message->getNumPackets());

    Protocol::Packet::ResendHeader* resendHdr =
        static_cast<Protocol::Packet::ResendHeader*>(mockPacket.payload);
    resendHdr->common.messageId = id;
    resendHdr->index = 3;
    resendHdr->num = 5;

    EXPECT_CALL(mockDriver, sendPackets(Pointee(packets[3]), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, sendPackets(Pointee(packets[4]), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleResendPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(8U, message->grantIndex);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);

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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
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
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&busyPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&busyPacket), Eq(1)))
        .Times(1);

    // Expect no data to be sent but the RESEND packet to be release.
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&dataPacket), Eq(1))).Times(0);
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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
    message->state.store(OutboundMessage::State::SENT);
    message->sentIndex = 5;
    EXPECT_EQ(5, message->grantIndex);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(OutboundMessage::State::DROPPED, message->state);
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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
    message->state.store(OutboundMessage::State::COMPLETED);
    message->sentIndex = 5;
    EXPECT_EQ(5, message->grantIndex);

    Protocol::Packet::UnknownHeader* header =
        static_cast<Protocol::Packet::UnknownHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->handleUnknownPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(OutboundMessage::State::COMPLETED, message->state);
    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(5U, message->grantIndex);
}

TEST_F(SenderTest, handleErrorPacket)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    OutboundMessage* message = &op->outMessage;
    message->state.store(OutboundMessage::State::IN_PROGRESS);

    Protocol::Packet::ErrorHeader* header =
        static_cast<Protocol::Packet::ErrorHeader*>(mockPacket.payload);
    header->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(2);

    sender->handleErrorPacket(&mockPacket, &mockDriver);

    EXPECT_NE(OutboundMessage::State::FAILED, message->state);

    sender->outboundMessages.insert({id, message});

    sender->handleErrorPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(OutboundMessage::State::FAILED, message->state);
}

TEST_F(SenderTest, sendMessage_basic)
{
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    OutboundMessage* message = &op->outMessage;

    message->setPacket(0, &mockPacket);
    message->messageLength = 420;
    mockPacket.length = message->messageLength + message->PACKET_HEADER_LENGTH;
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_FALSE(sender->outboundMessages.find(id) !=
                 sender->outboundMessages.end());

    sender->sendMessage(message, destination);

    EXPECT_EQ(22U, (uint64_t)mockPacket.address);
    EXPECT_EQ(0U, mockPacket.priority);
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(destination, message->destination);
    EXPECT_EQ(message->messageLength, header->totalLength);
    EXPECT_TRUE(sender->outboundMessages.find(id) !=
                sender->outboundMessages.end());
    EXPECT_EQ(message, sender->outboundMessages.find(id)->second);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->pingTimeout.expirationCycleTime);
    EXPECT_EQ(1U, message->grantIndex);
    EXPECT_EQ(OutboundMessage::State::IN_PROGRESS, message->state);
}

TEST_F(SenderTest, sendMessage_multipacket)
{
    char payload0[1024];
    char payload1[1024];
    NiceMock<Homa::Mock::MockDriver::MockPacket> packet0(payload0);
    NiceMock<Homa::Mock::MockDriver::MockPacket> packet1(payload1);
    Protocol::MessageId id = {sender->transportId,
                              sender->nextMessageSequenceNumber};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    OutboundMessage* message = &op->outMessage;

    message->setPacket(0, &packet0);
    message->setPacket(1, &packet1);
    message->messageLength = 1420;
    packet0.length = 1000 + 24;
    packet1.length = 420 + 24;
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_EQ(24U, sizeof(Protocol::Packet::DataHeader));
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);

    sender->sendMessage(message, destination);

    EXPECT_EQ(id, message->id);

    Protocol::Packet::DataHeader* header = nullptr;
    // Packet0
    EXPECT_EQ(22U, (uint64_t)packet0.address);
    EXPECT_EQ(0U, packet0.priority);
    header = static_cast<Protocol::Packet::DataHeader*>(packet0.payload);
    EXPECT_EQ(message->id, header->common.messageId);
    EXPECT_EQ(message->messageLength, header->totalLength);

    // Packet1
    EXPECT_EQ(22U, (uint64_t)packet1.address);
    EXPECT_EQ(0U, packet1.priority);
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
    OutboundMessage* message = &op->outMessage;
    message->setPacket(1, &mockPacket);

    EXPECT_DEATH(sender->sendMessage(message, nullptr),
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
    OutboundMessage* message = &op->outMessage;
    for (int i = 0; i < 9; ++i) {
        message->setPacket(i, &mockPacket);
    }
    message->messageLength = 9000;
    mockPacket.length = 1000 + sizeof(Protocol::Packet::DataHeader);
    Driver::Address* destination = (Driver::Address*)22;
    EXPECT_EQ(9U, message->getNumPackets());
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);

    EXPECT_CALL(mockDriver, getBandwidth).WillOnce(Return(8000));

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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 5);
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
    OutboundMessage* message[4];
    for (uint64_t i = 0; i < 4; ++i) {
        Protocol::OpId opId = {0, 0};
        Protocol::MessageId id = {42, 10 + i};
        op[i] = transport->opPool.construct(transport, &mockDriver, opId);
        message[i] = SenderTest::addMessage(sender, id, op[i]);
    }

    // Message[0]: Normal timeout: IN_PROGRESS
    message[0]->messageTimeout.expirationCycleTime = 9998;
    message[0]->state = OutboundMessage::State::IN_PROGRESS;
    // Message[1]: Normal timeout: SENT
    message[1]->messageTimeout.expirationCycleTime = 9999;
    message[1]->state = OutboundMessage::State::SENT;
    // Message[2]: Normal timeout: COMPLETED
    message[2]->messageTimeout.expirationCycleTime = 10000;
    message[2]->state = OutboundMessage::State::COMPLETED;
    // Message[1]: No timeout
    message[3]->messageTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    sender->checkMessageTimeouts();

    // Message[0]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(11000, message[0]->messageTimeout.expirationCycleTime);
    EXPECT_EQ(OutboundMessage::State::FAILED, message[0]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[0]));
    // Message[1]: Normal timeout: SENT
    EXPECT_EQ(11000, message[1]->messageTimeout.expirationCycleTime);
    EXPECT_EQ(OutboundMessage::State::FAILED, message[1]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[1]));
    // Message[2]: Normal timeout: COMPLETED
    EXPECT_EQ(11000, message[2]->messageTimeout.expirationCycleTime);
    EXPECT_EQ(OutboundMessage::State::COMPLETED, message[2]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[2]));
    // Message[3]: No timeout
    EXPECT_EQ(10001, message[3]->messageTimeout.expirationCycleTime);
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
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 2);
    Homa::Mock::MockDriver::MockPacket* packet[5];
    for (int i = 0; i < 5; ++i) {
        packet[i] = new Homa::Mock::MockDriver::MockPacket(payload);
        message->setPacket(i, packet[i]);
    }
    message->messageLength = 4000;
    EXPECT_EQ(5U, message->getNumPackets());
    EXPECT_EQ(2U, message->grantIndex);
    EXPECT_EQ(0U, message->sentIndex);
    EXPECT_NE(OutboundMessage::State::SENT, message->state);

    // 2 granted packets to be sent; won't be finished.
    EXPECT_CALL(mockDriver, sendPackets(Pointee(packet[0]), Eq(1)));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(packet[1]), Eq(1)));
    sender->trySend();  // < test call
    EXPECT_EQ(2U, message->grantIndex);
    EXPECT_EQ(2U, message->sentIndex);
    EXPECT_NE(OutboundMessage::State::SENT, message->state);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // No additional grants; no packets sent; won't be finished.
    EXPECT_CALL(mockDriver, sendPackets).Times(0);
    sender->trySend();  // < test call
    EXPECT_EQ(2U, message->grantIndex);
    EXPECT_EQ(2U, message->sentIndex);
    EXPECT_NE(OutboundMessage::State::SENT, message->state);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // 3 more granted packets; will finish.
    message->grantIndex = 5;
    EXPECT_CALL(mockDriver, sendPackets(Pointee(packet[2]), Eq(1)));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(packet[3]), Eq(1)));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(packet[4]), Eq(1)));
    sender->trySend();  // < test call
    EXPECT_EQ(5U, message->grantIndex);
    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(OutboundMessage::State::SENT, message->state);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // Message already finished.
    message->grantIndex = 6;
    EXPECT_CALL(mockDriver, sendPackets).Times(0);
    sender->trySend();  // < test call
    EXPECT_EQ(5U, message->sentIndex);
    EXPECT_EQ(OutboundMessage::State::SENT, message->state);
    Mock::VerifyAndClearExpectations(&mockDriver);

    for (int i = 0; i < 5; ++i) {
        delete packet[i];
    }
}

TEST_F(SenderTest, trySend_multipleMessages)
{
    Transport::Op* op[4];
    OutboundMessage* message[4];
    for (uint64_t i = 0; i < 4; ++i) {
        Protocol::OpId opId = {42, i};
        Protocol::MessageId id = {22, 10 + i};
        op[i] = transport->opPool.construct(transport, &mockDriver, opId);
        message[i] = SenderTest::addMessage(sender, id, op[i], 5);
    }

    // Message 0: All packets sent
    message[0]->messageLength = 5000;
    EXPECT_EQ(5, message[0]->grantIndex);
    message[0]->sentIndex = 5;
    message[0]->state.store(OutboundMessage::State::SENT);
    for (int i = 0; i < 5; ++i) {
        message[0]->setPacket(i, nullptr);
    }

    // Message 1: Waiting for more grants
    message[1]->messageLength = 9000;
    EXPECT_EQ(5, message[1]->grantIndex);
    message[1]->sentIndex = 5;
    for (int i = 0; i < 9; ++i) {
        message[1]->setPacket(i, nullptr);
    }

    // Message 2: New message, send 5 packets
    message[2]->messageLength = 9000;
    EXPECT_EQ(5, message[2]->grantIndex);
    EXPECT_EQ(0, message[2]->sentIndex);
    for (int i = 0; i < 9; ++i) {
        message[2]->setPacket(i, &mockPacket);
    }

    // Message 3: Send 3 packets to complete send.
    message[3]->messageLength = 5000;
    EXPECT_EQ(5, message[3]->grantIndex);
    EXPECT_EQ(0, message[3]->sentIndex);
    for (int i = 0; i < 5; ++i) {
        message[3]->setPacket(i, &mockPacket);
    }

    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(5);

    sender->trySend();

    EXPECT_EQ(5U, message[0]->sentIndex);
    EXPECT_EQ(OutboundMessage::State::SENT, message[0]->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[0]));
    EXPECT_EQ(5U, message[1]->sentIndex);
    EXPECT_NE(OutboundMessage::State::SENT, message[1]->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[1]));
    EXPECT_EQ(5U, message[2]->sentIndex);
    EXPECT_NE(OutboundMessage::State::SENT, message[2]->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[2]));
    EXPECT_EQ(0U, message[3]->sentIndex);
    EXPECT_NE(OutboundMessage::State::SENT, message[3]->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[3]));

    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(5);

    sender->trySend();

    EXPECT_EQ(5U, message[3]->sentIndex);
    EXPECT_EQ(OutboundMessage::State::SENT, message[3]->state);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[3]));
}

TEST_F(SenderTest, trySend_alreadyRunning)
{
    Protocol::MessageId id = {42, 1};
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    OutboundMessage* message = SenderTest::addMessage(sender, id, op, 1);
    message->setPacket(0, &mockPacket);
    message->messageLength = 1000;
    EXPECT_EQ(1U, message->getNumPackets());
    EXPECT_EQ(1, message->grantIndex);
    EXPECT_EQ(0, message->sentIndex);

    sender->sending.test_and_set();

    EXPECT_CALL(mockDriver, sendPackets).Times(0);

    sender->trySend();

    EXPECT_EQ(0, message->sentIndex);
}

TEST_F(SenderTest, trySend_nothingToSend)
{
    EXPECT_TRUE(sender->outboundMessages.empty());
    EXPECT_CALL(mockDriver, sendPackets).Times(0);
    sender->trySend();
}

TEST_F(SenderTest, checkPingTimeouts_basic)
{
    Transport::Op* op[2];
    OutboundMessage* message[2];
    for (uint64_t i = 0; i < 2; ++i) {
        Protocol::OpId opId = {0, 0};
        Protocol::MessageId id = {42, 10 + i};
        op[i] = transport->opPool.construct(transport, &mockDriver, opId);
        message[i] = SenderTest::addMessage(sender, id, op[i]);
    }

    // Message[0]: Normal timeout
    message[0]->pingTimeout.expirationCycleTime = 10000;
    // Message[1]: No timeout
    message[1]->pingTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    sender->checkPingTimeouts();

    // Message[0]: Normal timeout
    EXPECT_EQ(10100, message[0]->pingTimeout.expirationCycleTime);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[0]));
    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::PING, header->opcode);
    EXPECT_EQ(message[0]->id, header->messageId);
    // Message[1]: No timeout
    EXPECT_EQ(10001, message[1]->pingTimeout.expirationCycleTime);
}

TEST_F(SenderTest, checkPingTimeouts_empty)
{
    // Nothing to test except to ensure the call doesn't loop infinitely.
    EXPECT_TRUE(sender->pingTimeouts.list.empty());
    sender->checkPingTimeouts();
}

}  // namespace
}  // namespace Core
}  // namespace Homa
