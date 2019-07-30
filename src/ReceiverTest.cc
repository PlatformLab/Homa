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

#include "Receiver.h"

#include <mutex>

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
using ::testing::InSequence;
using ::testing::Matcher;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;

class ReceiverTest : public ::testing::Test {
  public:
    ReceiverTest()
        : mockDriver()
        , mockPacket(&payload)
        , mockPolicyManager()
        , payload()
        , receiver()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1027));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        transport = new Transport(&mockDriver, 1);
        receiver = transport->receiver.get();
        receiver->policyManager = &mockPolicyManager;
        receiver->messageTimeouts.timeoutIntervalCycles = 1000;
        receiver->resendTimeouts.timeoutIntervalCycles = 100;
        PerfUtils::Cycles::mockTscValue = 10000;
    }

    ~ReceiverTest()
    {
        Mock::VerifyAndClearExpectations(&mockDriver);
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
        PerfUtils::Cycles::mockTscValue = 0;
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    NiceMock<Homa::Mock::MockDriver::MockPacket> mockPacket;
    NiceMock<Homa::Mock::MockPolicyManager> mockPolicyManager;
    char payload[1028];
    Receiver* receiver;
    Transport* transport;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(ReceiverTest, handleDataPacket_basic)
{
    // Initial Messages [0, 1, 2]
    InboundMessage* others[3];
    for (int i = 0; i < 3; ++i) {
        others[i] = receiver->messagePool.construct(
            &mockDriver, sizeof(Protocol::Packet::DataHeader), 10000);
        receiver->scheduledMessages.push_back(&others[i]->scheduledMessageNode);
    }
    others[0]->unreceivedBytes = 1100;
    others[1]->unreceivedBytes = 1500;
    others[2]->unreceivedBytes = 5000;

    InboundMessage* message = nullptr;
    const Protocol::MessageId id(42, 33);
    const uint32_t totalMessageLength = 3500;
    const uint8_t policyVersion = 1;
    const uint16_t HEADER_SIZE = sizeof(Protocol::Packet::DataHeader);

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.opcode = Protocol::Packet::DATA;
    header->common.messageId = id;
    header->totalLength = totalMessageLength;
    header->policyVersion = policyVersion;
    header->unscheduledIndexLimit = 1;
    mockPacket.address = Driver::Address(22);

    // -------------------------------------------------------------------------
    // Receive packet[1]. New message. Scheduled before 2.
    header->index = 1;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockPolicyManager,
                signalNewMessage(Eq(mockPacket.address), Eq(policyVersion),
                                 Eq(totalMessageLength)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    ASSERT_NE(receiver->inboundMessages.end(),
              receiver->inboundMessages.find(id));
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(id, message->id);
    EXPECT_EQ(totalMessageLength, message->messageLength);
    EXPECT_EQ(4U, message->numExpectedPackets);
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message->state);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
    EXPECT_EQ(1U, message->getNumPackets());
    EXPECT_EQ(2500U, message->unreceivedBytes);
    EXPECT_TRUE(
        receiver->scheduledMessages.contains(&message->scheduledMessageNode));
    EXPECT_EQ(&others[1]->scheduledMessageNode,
              message->scheduledMessageNode.prev);
    EXPECT_EQ(&others[2]->scheduledMessageNode,
              message->scheduledMessageNode.next);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[1]. Duplicate.
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    EXPECT_EQ(1U, message->getNumPackets());
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[2]. Scheduled unchanged (before 2).
    header->index = 2;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    EXPECT_EQ(2U, message->getNumPackets());
    EXPECT_EQ(1500U, message->unreceivedBytes);
    EXPECT_TRUE(
        receiver->scheduledMessages.contains(&message->scheduledMessageNode));
    EXPECT_EQ(&others[1]->scheduledMessageNode,
              message->scheduledMessageNode.prev);
    EXPECT_EQ(&others[2]->scheduledMessageNode,
              message->scheduledMessageNode.next);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[3]. Scheduled before 0.
    header->index = 3;
    mockPacket.length = HEADER_SIZE + 500;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    EXPECT_EQ(3U, message->getNumPackets());
    EXPECT_EQ(1000U, message->unreceivedBytes);
    EXPECT_TRUE(
        receiver->scheduledMessages.contains(&message->scheduledMessageNode));
    EXPECT_EQ(&others[0]->scheduledMessageNode,
              message->scheduledMessageNode.next);
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[0]. Finished.
    header->index = 0;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    EXPECT_EQ(4U, message->getNumPackets());
    EXPECT_EQ(0U, message->unreceivedBytes);
    EXPECT_FALSE(
        receiver->scheduledMessages.contains(&message->scheduledMessageNode));
    EXPECT_EQ(InboundMessage::State::COMPLETED, message->state);
    EXPECT_EQ(message, &receiver->receivedMessages.queue.back());
    Mock::VerifyAndClearExpectations(&mockDriver);

    // -------------------------------------------------------------------------
    // Receive packet[0]. Already finished.
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, handleDataPacket_numExpectedPackets)
{
    Protocol::MessageId id(42, 32);
    InboundMessage* message = nullptr;
    const uint16_t HEADER_SIZE = sizeof(Protocol::Packet::DataHeader);

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->index = 0;
    std::string addressStr("remote-location");
    mockPacket.address = Driver::Address(22);

    // 1 partial packet
    header->totalLength = 450;
    mockPacket.length = HEADER_SIZE + 450;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(1U, message->numExpectedPackets);
    EXPECT_EQ(450, message->messageLength);
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);

    receiver->inboundMessages.erase(id);

    // 1 full packet
    header->totalLength = 1000;
    mockPacket.length = HEADER_SIZE + 1000;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(1U, message->numExpectedPackets);
    EXPECT_EQ(1000U, message->messageLength);
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);

    receiver->inboundMessages.erase(id);

    // 1 full packet + 1 partial packet
    header->totalLength = 1450;
    mockPacket.length = HEADER_SIZE + 1000;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(2U, message->numExpectedPackets);
    EXPECT_EQ(1450U, message->messageLength);
    EXPECT_EQ(1000U, message->PACKET_DATA_LENGTH);
}

TEST_F(ReceiverTest, handleDataPacket_unscheduled)
{
    InboundMessage* message = nullptr;
    const Protocol::MessageId id(42, 33);
    const uint32_t totalMessageLength = 3500;
    const uint8_t policyVersion = 1;
    const uint16_t HEADER_SIZE = sizeof(Protocol::Packet::DataHeader);

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.opcode = Protocol::Packet::DATA;
    header->common.messageId = id;
    header->totalLength = totalMessageLength;
    header->policyVersion = policyVersion;
    header->unscheduledIndexLimit = 4;  //<--- Fully unscheduled message
    mockPacket.address = Driver::Address(22);

    header->index = 1;
    mockPacket.length = HEADER_SIZE + 1000;
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);

    // TEST CALL
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    // ---------

    ASSERT_NE(receiver->inboundMessages.end(),
              receiver->inboundMessages.find(id));
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(id, message->id);
    EXPECT_EQ(totalMessageLength, message->messageLength);
    EXPECT_EQ(4U, message->numExpectedPackets);
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message->state);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
    EXPECT_EQ(1U, message->getNumPackets());
    EXPECT_EQ(2500U, message->unreceivedBytes);
    EXPECT_FALSE(
        receiver->scheduledMessages.contains(&message->scheduledMessageNode));
    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, handleBusyPacket_basic)
{
    Protocol::MessageId id(42, 32);
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->id = id;
    receiver->inboundMessages.insert({id, message});

    Protocol::Packet::BusyHeader* busyHeader =
        (Protocol::Packet::BusyHeader*)mockPacket.payload;
    busyHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->handleBusyPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
}

TEST_F(ReceiverTest, handleBusyPacket_unknown)
{
    Protocol::MessageId id(42, 32);

    Protocol::Packet::BusyHeader* busyHeader =
        (Protocol::Packet::BusyHeader*)mockPacket.payload;
    busyHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->handleBusyPacket(&mockPacket, &mockDriver);
}

TEST_F(ReceiverTest, handlePingPacket_basic)
{
    Protocol::MessageId id(42, 32);
    Driver::Address mockAddress = 22;
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->id = id;
    message->grantIndexLimit = 11;
    message->source = mockAddress;
    receiver->inboundMessages.insert({id, message});

    char pingPayload[1028];
    Homa::Mock::MockDriver::MockPacket pingPacket(pingPayload);
    pingPacket.address = mockAddress;
    Protocol::Packet::PingHeader* pingHeader =
        (Protocol::Packet::PingHeader*)pingPacket.payload;
    pingHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&pingPacket), Eq(1)))
        .Times(1);

    receiver->handlePingPacket(&pingPacket, &mockDriver);

    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->resendTimeout.expirationCycleTime);

    EXPECT_EQ(mockAddress, mockPacket.address);
    Protocol::Packet::GrantHeader* header =
        (Protocol::Packet::GrantHeader*)payload;
    EXPECT_EQ(Protocol::Packet::GRANT, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(message->grantIndexLimit, header->indexLimit);
}

TEST_F(ReceiverTest, handlePingPacket_unknown)
{
    Protocol::MessageId id(42, 32);

    char pingPayload[1028];
    Homa::Mock::MockDriver::MockPacket pingPacket(pingPayload);
    pingPacket.address = (Driver::Address)22;
    Protocol::Packet::PingHeader* pingHeader =
        (Protocol::Packet::PingHeader*)pingPacket.payload;
    pingHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&pingPacket), Eq(1)))
        .Times(1);

    receiver->handlePingPacket(&pingPacket, &mockDriver);

    EXPECT_EQ(pingPacket.address, mockPacket.address);
    Protocol::Packet::UnknownHeader* header =
        (Protocol::Packet::UnknownHeader*)payload;
    EXPECT_EQ(Protocol::Packet::UNKNOWN, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
}

TEST_F(ReceiverTest, receiveMessage)
{
    InboundMessage* msg0 = receiver->messagePool.construct(&mockDriver, 0, 0);
    InboundMessage* msg1 = receiver->messagePool.construct(&mockDriver, 0, 0);

    receiver->receivedMessages.queue.push_back(&msg0->receivedMessageNode);
    receiver->receivedMessages.queue.push_back(&msg1->receivedMessageNode);
    EXPECT_FALSE(receiver->receivedMessages.queue.empty());

    EXPECT_EQ(msg0, receiver->receiveMessage());
    EXPECT_FALSE(receiver->receivedMessages.queue.empty());

    EXPECT_EQ(msg1, receiver->receiveMessage());
    EXPECT_TRUE(receiver->receivedMessages.queue.empty());

    EXPECT_EQ(nullptr, receiver->receiveMessage());
    EXPECT_TRUE(receiver->receivedMessages.queue.empty());
}

TEST_F(ReceiverTest, dropMessage)
{
    Protocol::MessageId id = {42, 32};
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->id = id;
    receiver->inboundMessages.insert({id, message});
    receiver->scheduledMessages.push_back(&message->scheduledMessageNode);
    receiver->messageTimeouts.list.push_back(&message->messageTimeout.node);
    receiver->resendTimeouts.list.push_back(&message->resendTimeout.node);
    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(message, receiver->inboundMessages.find(id)->second);
    EXPECT_FALSE(receiver->scheduledMessages.empty());
    EXPECT_FALSE(receiver->messageTimeouts.list.empty());
    EXPECT_FALSE(receiver->resendTimeouts.list.empty());

    receiver->dropMessage(message);

    EXPECT_EQ(0U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(receiver->inboundMessages.end(),
              receiver->inboundMessages.find(id));
    EXPECT_TRUE(receiver->scheduledMessages.empty());
    EXPECT_TRUE(receiver->messageTimeouts.list.empty());
    EXPECT_TRUE(receiver->resendTimeouts.list.empty());
}

TEST_F(ReceiverTest, sendDonePacket)
{
    Protocol::MessageId id = {42, 32};
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->source = (Driver::Address)22;
    message->id = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    Receiver::sendDonePacket(message, &mockDriver);

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::DONE, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::DoneHeader), mockPacket.length);
    EXPECT_EQ(message->source, mockPacket.address);
}

TEST_F(ReceiverTest, sendErrorPacket)
{
    Protocol::MessageId id = {42, 32};
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->source = (Driver::Address)22;
    message->id = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    Receiver::sendErrorPacket(message, &mockDriver);

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::ERROR, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::ErrorHeader), mockPacket.length);
    EXPECT_EQ(message->source, mockPacket.address);
}

TEST_F(ReceiverTest, checkMessageTimeouts_basic)
{
    void* op[3];
    InboundMessage* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        op[i] = reinterpret_cast<void*>(i);
        message[i] = receiver->messagePool.construct(&mockDriver, 0, 0);
        message[i]->id = id;
        receiver->inboundMessages.insert({id, message[i]});
        message[i]->registerOp(op[i]);
        receiver->messageTimeouts.list.push_back(
            &message[i]->messageTimeout.node);
        receiver->resendTimeouts.list.push_back(
            &message[i]->resendTimeout.node);
    }
    EXPECT_EQ(3U, receiver->inboundMessages.size());
    EXPECT_EQ(3U, receiver->messagePool.outstandingObjects);

    // Message[0]: Normal timeout: IN_PROGRESS
    message[0]->messageTimeout.expirationCycleTime = 9998;
    message[0]->state = InboundMessage::State::IN_PROGRESS;
    // Message[1]: Normal timeout: COMPLETED
    message[1]->messageTimeout.expirationCycleTime = 10000;
    message[1]->state = InboundMessage::State::COMPLETED;
    // Message[2]: No timeout
    message[2]->messageTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    receiver->checkMessageTimeouts();

    // Message[0]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(nullptr, message[0]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->resendTimeout.node.list);
    EXPECT_EQ(0U, receiver->inboundMessages.count(message[0]->id));
    EXPECT_EQ(2U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[0]));
    // Message[1]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[1]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[1]->resendTimeout.node.list);
    EXPECT_EQ(InboundMessage::State::DROPPED, message[1]->getState());
    EXPECT_EQ(1U, receiver->inboundMessages.count(message[1]->id));
    EXPECT_EQ(2U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[1]));
    // Message[2]: No timeout
    EXPECT_EQ(&receiver->messageTimeouts.list,
              message[2]->messageTimeout.node.list);
    EXPECT_EQ(&receiver->resendTimeouts.list,
              message[2]->resendTimeout.node.list);
    EXPECT_EQ(1U, receiver->inboundMessages.count(message[2]->id));
    EXPECT_EQ(2U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op[2]));
}

TEST_F(ReceiverTest, checkMessageTimeouts_empty)
{
    // Nothing to test except to ensure the call doesn't loop infinitely.
    EXPECT_TRUE(receiver->messageTimeouts.list.empty());
    receiver->checkMessageTimeouts();
}

TEST_F(ReceiverTest, checkResendTimeouts)
{
    InboundMessage* message[5];
    for (uint64_t i = 0; i < 5; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messagePool.construct(&mockDriver, 0, 0);
        message[i]->id = id;
        receiver->resendTimeouts.list.push_back(
            &message[i]->resendTimeout.node);
    }

    // Message[0]: Fully received
    message[0]->state.store(InboundMessage::State::COMPLETED);
    message[0]->resendTimeout.expirationCycleTime = 10000 - 20;
    // Message[1]: DROPPED
    message[1]->state.store(InboundMessage::State::DROPPED);
    message[1]->resendTimeout.expirationCycleTime = 10000 - 10;
    // Message[2]: Normal timeout: block on grants
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message[2]->state);
    message[2]->resendTimeout.expirationCycleTime = 10000 - 5;
    // Message[3]: Normal timeout: Send Resends.
    // Message Packets
    //  0123456789
    // [1100001100]
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message[3]->state);
    message[3]->resendTimeout.expirationCycleTime = 10000;
    message[3]->source = (Driver::Address)22;
    message[3]->grantIndexLimit = 10;
    for (uint16_t i = 0; i < 2; ++i) {
        message[3]->setPacket(i, &mockPacket);
    }
    for (uint16_t i = 6; i < 8; ++i) {
        message[3]->setPacket(i, &mockPacket);
    }
    // Message[4]: No timeout
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message[4]->state);
    message[4]->resendTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    char buf1[1024];
    char buf2[1024];
    Homa::Mock::MockDriver::MockPacket mockResendPacket1(buf1);
    Homa::Mock::MockDriver::MockPacket mockResendPacket2(buf2);

    EXPECT_CALL(mockDriver, allocPacket())
        .WillOnce(Return(&mockResendPacket1))
        .WillOnce(Return(&mockResendPacket2));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockResendPacket1))).Times(1);
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockResendPacket2))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockResendPacket1), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockResendPacket2), Eq(1)))
        .Times(1);

    receiver->checkResendTimeouts();

    // Message[0]: Fully received
    EXPECT_EQ(nullptr, message[0]->resendTimeout.node.list);
    EXPECT_EQ(10000 - 20, message[0]->resendTimeout.expirationCycleTime);
    // Message[1]: DROPPED
    EXPECT_EQ(nullptr, message[1]->resendTimeout.node.list);
    EXPECT_EQ(10000 - 10, message[1]->resendTimeout.expirationCycleTime);
    // Message[2]: Normal timeout: blocked
    EXPECT_EQ(10100, message[2]->resendTimeout.expirationCycleTime);
    // Message[3]: Normal timeout: resends
    EXPECT_EQ(10100, message[3]->resendTimeout.expirationCycleTime);
    Protocol::Packet::ResendHeader* header1 =
        static_cast<Protocol::Packet::ResendHeader*>(mockResendPacket1.payload);
    EXPECT_EQ(Protocol::Packet::RESEND, header1->common.opcode);
    EXPECT_EQ(message[3]->id, header1->common.messageId);
    EXPECT_EQ(2U, header1->index);
    EXPECT_EQ(4U, header1->num);
    EXPECT_EQ(sizeof(Protocol::Packet::ResendHeader), mockResendPacket1.length);
    EXPECT_EQ(message[3]->source, mockResendPacket1.address);
    Protocol::Packet::ResendHeader* header2 =
        static_cast<Protocol::Packet::ResendHeader*>(mockResendPacket2.payload);
    EXPECT_EQ(Protocol::Packet::RESEND, header2->common.opcode);
    EXPECT_EQ(message[3]->id, header2->common.messageId);
    EXPECT_EQ(8U, header2->index);
    EXPECT_EQ(2U, header2->num);
    EXPECT_EQ(sizeof(Protocol::Packet::ResendHeader), mockResendPacket2.length);
    EXPECT_EQ(message[3]->source, mockResendPacket2.address);
    // Message[4]: No timeout
    EXPECT_EQ(10001, message[4]->resendTimeout.expirationCycleTime);
}

TEST_F(ReceiverTest, checkResendTimeouts_empty)
{
    // Nothing to test except to ensure the call doesn't loop infinitely.
    EXPECT_TRUE(receiver->resendTimeouts.list.empty());
    receiver->checkResendTimeouts();
}

TEST_F(ReceiverTest, schedule)
{
    InboundMessage* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messagePool.construct(
            &mockDriver, sizeof(Protocol::Packet::DataHeader), 3000);
        message[i]->id = id;
        message[i]->priority = 10;  // bogus number that should be reset.
        message[i]->grantIndexLimit = 1;
        message[i]->numExpectedPackets = 3;
        receiver->scheduledMessages.push_back(
            &message[i]->scheduledMessageNode);
    }
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    Policy::Scheduled policy;

    //-------------------------------------------------------------------------
    // Test:
    //      - more grantable packets than needed
    //      - more messages than overcommit level
    policy.maxScheduledPriority = 0;
    policy.degreeOvercommitment = 1;
    policy.scheduledByteLimit = 5000;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->schedule();

    EXPECT_EQ(0, message[0]->priority);
    EXPECT_EQ(3, message[0]->grantIndexLimit);
    EXPECT_EQ(message[0]->id, header->common.messageId);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - fewer grantable packets than needed (message[1])
    //      - no new grants needed (message[0])
    policy.maxScheduledPriority = 1;
    policy.degreeOvercommitment = 2;
    policy.scheduledByteLimit = 1001;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->schedule();

    EXPECT_EQ(1, message[0]->priority);
    EXPECT_EQ(0, message[1]->priority);
    EXPECT_EQ(2, message[1]->grantIndexLimit);
    EXPECT_EQ(message[1]->id, header->common.messageId);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - fewer priorities than overcommit/messages
    policy.maxScheduledPriority = 1;
    policy.degreeOvercommitment = 4;
    policy.scheduledByteLimit = 1;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, sendPacket(_)).Times(0);

    receiver->schedule();

    EXPECT_EQ(1, message[0]->priority);
    EXPECT_EQ(0, message[1]->priority);
    EXPECT_EQ(0, message[2]->priority);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - more priorities than overcommit/messages
    policy.maxScheduledPriority = 5;
    policy.degreeOvercommitment = 6;
    policy.scheduledByteLimit = 1;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, sendPacket(_)).Times(0);

    receiver->schedule();

    EXPECT_EQ(2, message[0]->priority);
    EXPECT_EQ(1, message[1]->priority);
    EXPECT_EQ(0, message[2]->priority);

    Mock::VerifyAndClearExpectations(&mockDriver);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
