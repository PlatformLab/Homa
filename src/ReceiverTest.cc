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
#include "Transport.h"

namespace Homa {
namespace Core {
namespace {

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
        , payload()
        , receiver()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        transport = new Transport(&mockDriver, 1);
        receiver = transport->receiver.get();
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
    char payload[1028];
    Receiver* receiver;
    Transport* transport;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(ReceiverTest, handleDataPacket_basic)
{
    // Setup registered op
    Protocol::MessageId id(42, 32);
    Protocol::OpId opId = {0, 0};
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, opId);
    InboundMessage* message = nullptr;

    EXPECT_TRUE(receiver->inboundMessages.empty());
    EXPECT_TRUE(receiver->receivedMessages.empty());

    // receive packet 1
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->index = 1;
    header->totalLength = 1420;
    std::string addressStr("remote-location");
    Homa::Mock::MockDriver::MockAddress mockAddress;
    mockPacket.address = &mockAddress;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(3)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .WillOnce(Return(&mockAddress));

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_FALSE(receiver->inboundMessages.empty());
    EXPECT_FALSE(receiver->receivedMessages.empty());
    message = receiver->receiveMessage();
    message->registerOp(op);
    EXPECT_EQ(&mockAddress, message->source);
    EXPECT_EQ(2U, message->numExpectedPackets);
    EXPECT_EQ(1420U, message->message.messageLength);
    EXPECT_EQ(1U, message->message.getNumPackets());
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);
    EXPECT_TRUE(message->newPacket);
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));
    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(10100U, message->resendTimeout.expirationCycleTime);

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 1 again; duplicate packet
    message->newPacket = false;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(2)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_TRUE(receiver->receivedMessages.empty());
    EXPECT_TRUE(message->message.occupied.test(1));
    EXPECT_EQ(1U, message->message.getNumPackets());
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);
    EXPECT_FALSE(message->newPacket);
    EXPECT_EQ(InboundMessage::State::IN_PROGRESS, message->state);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 0; complete the message
    header->index = 0;
    message->newPacket = false;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(2)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_TRUE(receiver->receivedMessages.empty());
    EXPECT_EQ(2U, message->message.getNumPackets());
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);
    EXPECT_TRUE(message->newPacket);
    EXPECT_EQ(InboundMessage::State::COMPLETED, message->state);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 0 again on a complete message
    message->newPacket = false;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .Times(0);
    EXPECT_CALL(mockAddress, toString).Times(0);

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_FALSE(message->newPacket);
    EXPECT_TRUE(receiver->receivedMessages.empty());
    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, handleDataPacket_numExpectedPackets)
{
    Protocol::MessageId id(42, 32);
    InboundMessage* message = nullptr;

    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->index = 0;
    std::string addressStr("remote-location");
    NiceMock<Homa::Mock::MockDriver::MockAddress> mockAddress;
    mockPacket.address = &mockAddress;

    ON_CALL(mockAddress, toString).WillByDefault(Return(addressStr));
    ON_CALL(mockDriver,
            getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .WillByDefault(Return(&mockAddress));

    // 1 partial packet
    header->totalLength = 450;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(1U, message->numExpectedPackets);
    EXPECT_EQ(450, message->message.messageLength);
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);

    receiver->inboundMessages.erase(id);

    // 1 full packet
    header->totalLength = 1000;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(1U, message->numExpectedPackets);
    EXPECT_EQ(1000U, message->message.messageLength);
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);

    receiver->inboundMessages.erase(id);

    // 1 full packet + 1 partial packet
    header->totalLength = 1450;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    message = receiver->inboundMessages.find(id)->second;
    EXPECT_EQ(2U, message->numExpectedPackets);
    EXPECT_EQ(1450U, message->message.messageLength);
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);
}

TEST_F(ReceiverTest, handleBusyPacket_basic)
{
    Protocol::MessageId id(42, 32);
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->id = id;
    message->newPacket = false;
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
    Homa::Mock::MockDriver::MockAddress mockAddress;
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->id = id;
    message->grantIndexLimit = 11;
    message->source = &mockAddress;
    receiver->inboundMessages.insert({id, message});

    char pingPayload[1028];
    Homa::Mock::MockDriver::MockPacket pingPacket(pingPayload);
    pingPacket.address = &mockAddress;
    Protocol::Packet::PingHeader* pingHeader =
        (Protocol::Packet::PingHeader*)pingPacket.payload;
    pingHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&pingPacket), Eq(1)))
        .Times(1);

    receiver->handlePingPacket(&pingPacket, &mockDriver);

    EXPECT_EQ(11000U, message->messageTimeout.expirationCycleTime);
    EXPECT_EQ(0U, message->resendTimeout.expirationCycleTime);

    EXPECT_EQ(&mockAddress, mockPacket.address);
    Protocol::Packet::GrantHeader* header =
        (Protocol::Packet::GrantHeader*)payload;
    EXPECT_EQ(Protocol::Packet::GRANT, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(message->grantIndexLimit, header->indexLimit);
}

TEST_F(ReceiverTest, handlePingPacket_unknown)
{
    Protocol::MessageId id(42, 32);
    Homa::Mock::MockDriver::MockAddress mockAddress;

    char pingPayload[1028];
    Homa::Mock::MockDriver::MockPacket pingPacket(pingPayload);
    pingPacket.address = &mockAddress;
    Protocol::Packet::PingHeader* pingHeader =
        (Protocol::Packet::PingHeader*)pingPacket.payload;
    pingHeader->common.messageId = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&pingPacket), Eq(1)))
        .Times(1);

    receiver->handlePingPacket(&pingPacket, &mockDriver);

    EXPECT_EQ(&mockAddress, mockPacket.address);
    Protocol::Packet::UnknownHeader* header =
        (Protocol::Packet::UnknownHeader*)payload;
    EXPECT_EQ(Protocol::Packet::UNKNOWN, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
}

TEST_F(ReceiverTest, receiveMessage)
{
    InboundMessage* msg0 = receiver->messagePool.construct(&mockDriver, 0, 0);
    InboundMessage* msg1 = receiver->messagePool.construct(&mockDriver, 0, 0);

    receiver->receivedMessages.push_back(msg0);
    receiver->receivedMessages.push_back(msg1);
    EXPECT_EQ(2U, receiver->receivedMessages.size());

    EXPECT_EQ(msg0, receiver->receiveMessage());
    EXPECT_EQ(1U, receiver->receivedMessages.size());

    EXPECT_EQ(msg1, receiver->receiveMessage());
    EXPECT_EQ(0U, receiver->receivedMessages.size());

    EXPECT_EQ(nullptr, receiver->receiveMessage());
    EXPECT_EQ(0U, receiver->receivedMessages.size());
}

TEST_F(ReceiverTest, dropMessage)
{
    Protocol::MessageId id = {42, 32};
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
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

TEST_F(ReceiverTest, poll)
{
    // Nothing to test.
    receiver->poll();
}

TEST_F(ReceiverTest, sendDonePacket)
{
    Protocol::MessageId id = {42, 32};
    Homa::Mock::MockDriver::MockAddress mockAddress;
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->source = &mockAddress;
    message->id = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    Receiver::sendDonePacket(message, &mockDriver);

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::DONE, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::DoneHeader), mockPacket.length);
    EXPECT_EQ(&mockAddress, mockPacket.address);
}

TEST_F(ReceiverTest, sendErrorPacket)
{
    Protocol::MessageId id = {42, 32};
    Homa::Mock::MockDriver::MockAddress mockAddress;
    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 0, 0);
    message->source = &mockAddress;
    message->id = id;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    Receiver::sendErrorPacket(message, &mockDriver);

    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::ERROR, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::ErrorHeader), mockPacket.length);
    EXPECT_EQ(&mockAddress, mockPacket.address);
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
        message[i]->registerOp(op[i]);
        receiver->messageTimeouts.list.push_back(
            &message[i]->messageTimeout.node);
    }

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
    EXPECT_EQ(11000, message[0]->messageTimeout.expirationCycleTime);
    EXPECT_EQ(InboundMessage::State::FAILED, message[0]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[0]));
    // Message[1]: Normal timeout: COMPLETED
    EXPECT_EQ(11000, message[1]->messageTimeout.expirationCycleTime);
    EXPECT_EQ(InboundMessage::State::COMPLETED, message[1]->getState());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op[1]));
    // Message[2]: No timeout
    EXPECT_EQ(10001, message[2]->messageTimeout.expirationCycleTime);
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
    // Message[1]: Failed
    message[1]->state.store(InboundMessage::State::FAILED);
    message[1]->resendTimeout.expirationCycleTime = 10000 - 10;
    // Message[2]: Normal timeout: block on grants
    message[2]->resendTimeout.expirationCycleTime = 10000 - 5;
    // Message[3]: Normal timeout: Send Resends.
    // Message Packets
    //  0123456789
    // [1100001100]
    message[3]->resendTimeout.expirationCycleTime = 10000;
    Homa::Mock::MockDriver::MockAddress mockAddress;
    message[3]->source = &mockAddress;
    message[3]->grantIndexLimit = 10;
    for (uint16_t i = 0; i < 2; ++i) {
        message[3]->message.setPacket(i, &mockPacket);
    }
    for (uint16_t i = 6; i < 8; ++i) {
        message[3]->message.setPacket(i, &mockPacket);
    }
    // Message[4]: No timeout
    message[4]->resendTimeout.expirationCycleTime = 10001;

    EXPECT_EQ(10000U, PerfUtils::Cycles::rdtsc());

    char buf1[1024];
    char buf2[1024];
    Homa::Mock::MockDriver::MockPacket mockResendPacket1(buf1);
    Homa::Mock::MockDriver::MockPacket mockResendPacket2(buf2);

    EXPECT_CALL(mockDriver, allocPacket())
        .WillOnce(Return(&mockResendPacket1))
        .WillOnce(Return(&mockResendPacket2));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockResendPacket1), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockResendPacket2), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockResendPacket1), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockResendPacket2), Eq(1)))
        .Times(1);

    receiver->checkResendTimeouts();

    // Message[0]: Fully received
    EXPECT_EQ(10000 - 20, message[0]->resendTimeout.expirationCycleTime);
    // Message[1]: Failed
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
    EXPECT_EQ(&mockAddress, mockResendPacket1.address);
    Protocol::Packet::ResendHeader* header2 =
        static_cast<Protocol::Packet::ResendHeader*>(mockResendPacket2.payload);
    EXPECT_EQ(Protocol::Packet::RESEND, header2->common.opcode);
    EXPECT_EQ(message[3]->id, header2->common.messageId);
    EXPECT_EQ(8U, header2->index);
    EXPECT_EQ(2U, header2->num);
    EXPECT_EQ(sizeof(Protocol::Packet::ResendHeader), mockResendPacket2.length);
    EXPECT_EQ(&mockAddress, mockResendPacket2.address);
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
    Protocol::MessageId id(42, 32);
    Driver::Address* sourceAddr = (Driver::Address*)22;
    uint32_t TOTAL_MESSAGE_LEN = 9000;

    InboundMessage* message =
        receiver->messagePool.construct(&mockDriver, 24, TOTAL_MESSAGE_LEN);
    message->id = id;
    message->source = sourceAddr;
    message->message.numPackets = 1;
    EXPECT_EQ(1000U, message->message.PACKET_DATA_LENGTH);
    EXPECT_EQ(1U, message->message.getNumPackets());
    EXPECT_FALSE(message->newPacket);

    receiver->inboundMessages.insert({id, message});

    EXPECT_CALL(mockDriver, allocPacket).Times(0);
    EXPECT_CALL(mockDriver, sendPackets).Times(0);
    EXPECT_CALL(mockDriver, releasePackets).Times(0);

    receiver->schedule();

    Mock::VerifyAndClearExpectations(&mockDriver);

    EXPECT_FALSE(message->newPacket);
    message->newPacket = true;

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->schedule();

    Mock::VerifyAndClearExpectations(&mockDriver);

    EXPECT_FALSE(message->newPacket);
}

TEST_F(ReceiverTest, sendGrantPacket)
{
    Protocol::MessageId msgId(42, 32);
    Driver::Address* sourceAddr = (Driver::Address*)22;
    uint32_t TOTAL_MESSAGE_LEN = 9000;

    InboundMessage message(&mockDriver, 24, TOTAL_MESSAGE_LEN);
    message.id = msgId;
    message.source = sourceAddr;
    message.numExpectedPackets = 9;
    EXPECT_EQ(1000U, message.message.PACKET_DATA_LENGTH);

    InSequence _seq;

    {
        // GRANT 5 more packets (up to index 6)
        message.message.numPackets = 1;

        EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
        EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1)))
            .Times(1);
        EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
            .Times(1);

        SpinLock::Lock lock_message(message.mutex);
        receiver->sendGrantPacket(&message, &mockDriver, lock_message);

        Protocol::Packet::GrantHeader* header =
            (Protocol::Packet::GrantHeader*)payload;
        EXPECT_EQ(msgId, header->common.messageId);
        EXPECT_EQ(6U, header->indexLimit);
        EXPECT_EQ(6U, message.grantIndexLimit);
        EXPECT_EQ(sizeof(Protocol::Packet::GrantHeader), mockPacket.length);
        EXPECT_EQ(sourceAddr, mockPacket.address);

        Mock::VerifyAndClearExpectations(&mockDriver);
    }

    {
        // GRANT 1 more packet; MAX packet index 9.
        message.message.numPackets = 8;

        EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
        EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1)))
            .Times(1);
        EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
            .Times(1);

        SpinLock::Lock lock_message(message.mutex);
        receiver->sendGrantPacket(&message, &mockDriver, lock_message);

        Protocol::Packet::GrantHeader* header =
            (Protocol::Packet::GrantHeader*)payload;
        EXPECT_EQ(msgId, header->common.messageId);
        EXPECT_EQ(9U, header->indexLimit);
        EXPECT_EQ(9U, message.grantIndexLimit);
        EXPECT_EQ(sizeof(Protocol::Packet::GrantHeader), mockPacket.length);
        EXPECT_EQ(sourceAddr, mockPacket.address);

        Mock::VerifyAndClearExpectations(&mockDriver);
    }
}

}  // namespace
}  // namespace Core
}  // namespace Homa
