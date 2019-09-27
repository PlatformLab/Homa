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
        , mockPolicyManager(&mockDriver)
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
    Receiver::Message* others[3];
    for (int i = 0; i < 3; ++i) {
        others[i] = receiver->messagePool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 10000);
        others[i]->source = Driver::Address(22);
        others[i]->peer = Receiver::schedule(others[i], &receiver->peerTable,
                                             &receiver->scheduledPeers);
    }
    others[0]->unreceivedBytes = 1100;
    others[1]->unreceivedBytes = 1500;
    others[2]->unreceivedBytes = 5000;

    Receiver::Message* message = nullptr;
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
    EXPECT_EQ(Receiver::Message::State::IN_PROGRESS, message->state);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
    EXPECT_EQ(1U, message->getNumPackets());
    EXPECT_EQ(2500U, message->unreceivedBytes);
    EXPECT_EQ(&receiver->peerTable.at(mockPacket.address), message->peer);
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
    EXPECT_EQ(Receiver::Message::State::COMPLETED, message->state);
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
    Receiver::Message* message = nullptr;
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
    Receiver::Message* message = nullptr;
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
    EXPECT_EQ(Receiver::Message::State::IN_PROGRESS, message->state);
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);
    EXPECT_EQ(1U, message->getNumPackets());
    EXPECT_EQ(2500U, message->unreceivedBytes);
    EXPECT_EQ(nullptr, message->peer);
    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, handleBusyPacket_basic)
{
    Protocol::MessageId id(42, 32);
    Receiver::Message* message =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
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
    Receiver::Message* message =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
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
    Receiver::Message* msg0 =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
    Receiver::Message* msg1 =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);

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

TEST_F(ReceiverTest, Message_acknowledge)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
    message->source = (Driver::Address)22;
    message->id = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    message->acknowledge();

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::DONE, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::DoneHeader), mockPacket.length);
    EXPECT_EQ(message->source, mockPacket.address);
}

TEST_F(ReceiverTest, Message_fail)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
    message->source = (Driver::Address)22;
    message->id = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    message->fail();

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::ERROR, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::ErrorHeader), mockPacket.length);
    EXPECT_EQ(message->source, mockPacket.address);
}

TEST_F(ReceiverTest, dropMessage)
{
    Protocol::MessageId id = {42, 32};
    Receiver::Message* message =
        receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
    message->id = id;
    receiver->inboundMessages.insert({id, message});
    receiver->messageTimeouts.list.push_back(&message->messageTimeout.node);
    receiver->resendTimeouts.list.push_back(&message->resendTimeout.node);
    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(message, receiver->inboundMessages.find(id)->second);
    EXPECT_FALSE(receiver->messageTimeouts.list.empty());
    EXPECT_FALSE(receiver->resendTimeouts.list.empty());

    receiver->dropMessage(message);

    EXPECT_EQ(0U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(receiver->inboundMessages.end(),
              receiver->inboundMessages.find(id));
    EXPECT_TRUE(receiver->messageTimeouts.list.empty());
    EXPECT_TRUE(receiver->resendTimeouts.list.empty());
}

TEST_F(ReceiverTest, checkMessageTimeouts_basic)
{
    void* op[3];
    Receiver::Message* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        op[i] = reinterpret_cast<void*>(i);
        message[i] =
            receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
        message[i]->id = id;
        receiver->inboundMessages.insert({id, message[i]});
        receiver->messageTimeouts.list.push_back(
            &message[i]->messageTimeout.node);
        receiver->resendTimeouts.list.push_back(
            &message[i]->resendTimeout.node);
    }
    EXPECT_EQ(3U, receiver->inboundMessages.size());
    EXPECT_EQ(3U, receiver->messagePool.outstandingObjects);

    // Message[0]: Normal timeout: IN_PROGRESS
    message[0]->messageTimeout.expirationCycleTime = 9998;
    message[0]->state = Receiver::Message::State::IN_PROGRESS;
    message[0]->peer = Receiver::schedule(message[0], &receiver->peerTable,
                                          &receiver->scheduledPeers);
    // Message[1]: Normal timeout: COMPLETED
    message[1]->messageTimeout.expirationCycleTime = 10000;
    message[1]->state = Receiver::Message::State::COMPLETED;
    // Message[2]: No timeout
    message[2]->messageTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    receiver->checkMessageTimeouts();

    // Message[0]: Normal timeout: IN_PROGRESS
    EXPECT_EQ(nullptr, message[0]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->resendTimeout.node.list);
    EXPECT_EQ(nullptr, message[0]->peer);
    EXPECT_EQ(0U, receiver->inboundMessages.count(message[0]->id));
    EXPECT_EQ(2U, receiver->messagePool.outstandingObjects);
    // Message[1]: Normal timeout: COMPLETED
    EXPECT_EQ(nullptr, message[1]->messageTimeout.node.list);
    EXPECT_EQ(nullptr, message[1]->resendTimeout.node.list);
    EXPECT_EQ(Receiver::Message::State::DROPPED, message[1]->getState());
    EXPECT_EQ(1U, receiver->inboundMessages.count(message[1]->id));
    EXPECT_EQ(2U, receiver->messagePool.outstandingObjects);
    // Message[2]: No timeout
    EXPECT_EQ(&receiver->messageTimeouts.list,
              message[2]->messageTimeout.node.list);
    EXPECT_EQ(&receiver->resendTimeouts.list,
              message[2]->resendTimeout.node.list);
    EXPECT_EQ(1U, receiver->inboundMessages.count(message[2]->id));
    EXPECT_EQ(2U, receiver->messagePool.outstandingObjects);
}

TEST_F(ReceiverTest, checkMessageTimeouts_empty)
{
    // Nothing to test except to ensure the call doesn't loop infinitely.
    EXPECT_TRUE(receiver->messageTimeouts.list.empty());
    receiver->checkMessageTimeouts();
}

TEST_F(ReceiverTest, checkResendTimeouts)
{
    Receiver::Message* message[5];
    for (uint64_t i = 0; i < 5; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] =
            receiver->messagePool.construct(receiver, &mockDriver, 0, 0);
        message[i]->id = id;
        receiver->resendTimeouts.list.push_back(
            &message[i]->resendTimeout.node);
    }

    // Message[0]: Fully received
    message[0]->state.store(Receiver::Message::State::COMPLETED);
    message[0]->resendTimeout.expirationCycleTime = 10000 - 20;
    // Message[1]: DROPPED
    message[1]->state.store(Receiver::Message::State::DROPPED);
    message[1]->resendTimeout.expirationCycleTime = 10000 - 10;
    // Message[2]: Normal timeout: block on grants
    EXPECT_EQ(Receiver::Message::State::IN_PROGRESS, message[2]->state);
    message[2]->resendTimeout.expirationCycleTime = 10000 - 5;
    // Message[3]: Normal timeout: Send Resends.
    // Message Packets
    //  0123456789
    // [1100001100]
    EXPECT_EQ(Receiver::Message::State::IN_PROGRESS, message[3]->state);
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
    EXPECT_EQ(Receiver::Message::State::IN_PROGRESS, message[4]->state);
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

TEST_F(ReceiverTest, runScheduler)
{
    Receiver::Message* message[4];
    for (uint64_t i = 0; i < 4; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messagePool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader),
            10000 * (i + 1));
        message[i]->id = id;
        message[i]->source = Driver::Address(100 + i);
        message[i]->priority = 10;  // bogus number that should be reset.
        message[i]->grantIndexLimit = 10 * (i + 1) - 5;
        message[i]->numExpectedPackets = 10 * (i + 1);
        message[i]->peer = Receiver::schedule(message[i], &receiver->peerTable,
                                              &receiver->scheduledPeers);
    }
    Protocol::Packet::GrantHeader* header =
        static_cast<Protocol::Packet::GrantHeader*>(mockPacket.payload);
    Policy::Scheduled policy;

    //-------------------------------------------------------------------------
    // Test:
    //      - more grantable packets than needed
    //      - message full granted
    //      - more messages than overcommit level
    policy.maxScheduledPriority = 1;
    policy.degreeOvercommitment = 2;
    policy.scheduledByteLimit = 15000;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->runScheduler();

    EXPECT_EQ(1, message[0]->priority);
    EXPECT_EQ(10, message[0]->grantIndexLimit);
    EXPECT_EQ(nullptr, message[0]->peer);
    EXPECT_EQ(message[0]->id, header->common.messageId);
    EXPECT_EQ(0, message[1]->priority);
    EXPECT_EQ(15, message[1]->grantIndexLimit);

    Mock::VerifyAndClearExpectations(&mockDriver);

    //-------------------------------------------------------------------------
    // Test:
    //      - fewer grantable packets than needed (message[1])
    policy.maxScheduledPriority = 0;
    policy.degreeOvercommitment = 1;
    policy.scheduledByteLimit = 15001;
    EXPECT_CALL(mockPolicyManager, getScheduledPolicy())
        .WillOnce(Return(policy));
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPacket(Eq(&mockPacket))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->runScheduler();

    EXPECT_EQ(0, message[1]->priority);
    EXPECT_EQ(16, message[1]->grantIndexLimit);
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

    receiver->runScheduler();

    EXPECT_EQ(1, message[1]->priority);
    EXPECT_EQ(0, message[2]->priority);
    EXPECT_EQ(0, message[3]->priority);

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

    receiver->runScheduler();

    EXPECT_EQ(2, message[1]->priority);
    EXPECT_EQ(1, message[2]->priority);
    EXPECT_EQ(0, message[3]->priority);

    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, schedule)
{
    Receiver::Message* message[3];
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messagePool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 0);
        message[i]->id = id;
    }

    //--------------------------------------------------------------------------
    message[0]->source = Driver::Address(22);
    message[0]->peer = Receiver::schedule(message[0], &receiver->peerTable,
                                          &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->peerTable.at(22), message[0]->peer);
    EXPECT_EQ(message[0], &message[0]->peer->scheduledMessages.back());
    EXPECT_EQ(message[0]->peer, &receiver->scheduledPeers.back());

    //--------------------------------------------------------------------------
    message[1]->source = Driver::Address(33);
    message[1]->peer = Receiver::schedule(message[1], &receiver->peerTable,
                                          &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->peerTable.at(33), message[1]->peer);
    EXPECT_EQ(message[1], &message[1]->peer->scheduledMessages.back());
    EXPECT_EQ(message[1]->peer, &receiver->scheduledPeers.back());

    //--------------------------------------------------------------------------
    message[2]->source = Driver::Address(22);
    message[2]->peer = Receiver::schedule(message[2], &receiver->peerTable,
                                          &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->peerTable.at(22), message[2]->peer);
    EXPECT_EQ(message[2], &message[2]->peer->scheduledMessages.back());
    EXPECT_EQ(message[2]->peer, &receiver->scheduledPeers.front());
}

TEST_F(ReceiverTest, unschedule)
{
    Receiver::Message* message[5];
    for (uint64_t i = 0; i < 5; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        message[i] = receiver->messagePool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 0);
        message[i]->id = id;
        message[i]->source = Driver::Address((i / 3) + 10);
        message[i]->peer = Receiver::schedule(message[i], &receiver->peerTable,
                                              &receiver->scheduledPeers);
    }
    ASSERT_EQ(Driver::Address(10), message[0]->source);
    ASSERT_EQ(Driver::Address(10), message[1]->source);
    ASSERT_EQ(Driver::Address(10), message[2]->source);
    ASSERT_EQ(Driver::Address(11), message[3]->source);
    ASSERT_EQ(Driver::Address(11), message[4]->source);
    ASSERT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(10));
    ASSERT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(11));
    // 10 : [10][20][30]
    // 11 : [10][20]
    message[0]->unreceivedBytes = 10;
    message[1]->unreceivedBytes = 20;
    message[2]->unreceivedBytes = 30;
    message[3]->unreceivedBytes = 10;
    message[4]->unreceivedBytes = 20;

    auto it = receiver->scheduledPeers.begin();

    //--------------------------------------------------------------------------
    // Remove message[4]; peer already at end.
    // 10 : [10][20][30]
    // 11 : [10]

    it = Receiver::unschedule(message[4], message[4]->peer,
                              &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(10));
    EXPECT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(11));
    EXPECT_EQ(3U, receiver->peerTable.at(10).scheduledMessages.size());
    EXPECT_EQ(1U, receiver->peerTable.at(11).scheduledMessages.size());
    EXPECT_EQ(receiver->scheduledPeers.end(), it);

    //--------------------------------------------------------------------------
    // Remove message[1]; peer in correct position.
    // 10 : [10][30]
    // 11 : [10]

    it = Receiver::unschedule(message[1], message[1]->peer,
                              &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(10));
    EXPECT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(11));
    EXPECT_EQ(2U, receiver->peerTable.at(10).scheduledMessages.size());
    EXPECT_EQ(1U, receiver->peerTable.at(11).scheduledMessages.size());
    EXPECT_EQ(std::next(receiver->scheduledPeers.begin()), it);

    //--------------------------------------------------------------------------
    // Remove message[0]; peer needs to be reordered.
    // 11 : [10]
    // 10 : [30]

    it = Receiver::unschedule(message[0], message[0]->peer,
                              &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(11));
    EXPECT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(10));
    EXPECT_EQ(1U, receiver->peerTable.at(11).scheduledMessages.size());
    EXPECT_EQ(1U, receiver->peerTable.at(10).scheduledMessages.size());
    EXPECT_EQ(receiver->scheduledPeers.begin(), it);

    //--------------------------------------------------------------------------
    // Remove message[3]; peer needs to be removed.
    // 10 : [30]

    it = Receiver::unschedule(message[3], message[3]->peer,
                              &receiver->scheduledPeers);

    EXPECT_FALSE(receiver->scheduledPeers.contains(
        &message[3]->peer->scheduledPeerNode));
    EXPECT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(10));
    EXPECT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(10));
    EXPECT_EQ(1U, receiver->peerTable.at(10).scheduledMessages.size());
    EXPECT_EQ(0U, receiver->peerTable.at(11).scheduledMessages.size());
    EXPECT_EQ(receiver->scheduledPeers.begin(), it);
}

TEST_F(ReceiverTest, updateSchedule)
{
    // 10 : [10]
    // 11 : [20][30]
    Receiver::Message* other[3];
    for (uint64_t i = 0; i < 3; ++i) {
        Protocol::MessageId id = {42, 10 + i};
        other[i] = receiver->messagePool.construct(
            receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 0);
        other[i]->id = id;
        other[i]->source = Driver::Address(((i + 1) / 2) + 10);
        other[i]->peer = Receiver::schedule(other[i], &receiver->peerTable,
                                            &receiver->scheduledPeers);
        other[i]->unreceivedBytes = 10 * (i + 1);
    }
    Receiver::Message* message = receiver->messagePool.construct(
        receiver, &mockDriver, sizeof(Protocol::Packet::DataHeader), 0);
    message->source = Driver::Address(11);
    message->peer = Receiver::schedule(message, &receiver->peerTable,
                                       &receiver->scheduledPeers);
    ASSERT_EQ(&receiver->peerTable.at(10), other[0]->peer);
    ASSERT_EQ(&receiver->peerTable.at(11), other[1]->peer);
    ASSERT_EQ(&receiver->peerTable.at(11), other[2]->peer);
    ASSERT_EQ(&receiver->peerTable.at(11), message->peer);
    ASSERT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(10));
    ASSERT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(11));

    //--------------------------------------------------------------------------
    // Move message up within peer.
    // 10 : [10]
    // 11 : [20][XX][30]
    message->unreceivedBytes = 25;

    Receiver::updateSchedule(message, message->peer, &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(11));
    Receiver::Peer* peer = &receiver->scheduledPeers.back();
    auto it = peer->scheduledMessages.begin();
    EXPECT_TRUE(
        std::next(receiver->peerTable.at(11).scheduledMessages.begin()) ==
        message->peer->scheduledMessages.get(&message->scheduledMessageNode));

    //--------------------------------------------------------------------------
    // Move message to front within peer.  No peer reordering.
    // 10 : [10]
    // 11 : [XX][20][30]
    message->unreceivedBytes = 10;

    Receiver::updateSchedule(message, message->peer, &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->scheduledPeers.back(), &receiver->peerTable.at(11));
    EXPECT_EQ(
        receiver->peerTable.at(11).scheduledMessages.begin(),
        message->peer->scheduledMessages.get(&message->scheduledMessageNode));

    //--------------------------------------------------------------------------
    // Reorder peer.
    // 11 : [XX][20][30]
    // 10 : [10]
    message->unreceivedBytes = 9;

    Receiver::updateSchedule(message, message->peer, &receiver->scheduledPeers);

    EXPECT_EQ(&receiver->scheduledPeers.front(), &receiver->peerTable.at(11));
    EXPECT_EQ(
        receiver->peerTable.at(11).scheduledMessages.begin(),
        message->peer->scheduledMessages.get(&message->scheduledMessageNode));
}

TEST_F(ReceiverTest, prioritize)
{
    struct Foo {
        Foo()
            : val(0)
            , node(this)
        {}
        struct Compare {
            bool operator()(const Foo& a, const Foo& b)
            {
                return a.val < b.val;
            }
        };
        int val;
        Intrusive::List<Foo>::Node node;
    };

    // [2][4][6][8]
    Foo foo[4];
    Intrusive::List<Foo> list;
    for (int i = 0; i < 4; ++i) {
        foo[i].val = i * 2 + 2;
        list.push_back(&foo[i].node);
    }

    auto it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [2][4][6][7]
    foo[3].val = 7;
    Receiver::prioritize<Foo>(&list, &foo[3].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [2][2][4][6]
    foo[3].val = 2;
    Receiver::prioritize<Foo>(&list, &foo[3].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[3], &(*++it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));

    // [0][2][4][6]
    foo[3].val = 0;
    Receiver::prioritize<Foo>(&list, &foo[3].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[3], &(*it));
    EXPECT_EQ(&foo[0], &(*++it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
}

}  // namespace
}  // namespace Core
}  // namespace Homa
