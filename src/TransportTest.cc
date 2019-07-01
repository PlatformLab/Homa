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

#include "Transport.h"

#include "Mock/MockDriver.h"
#include "Mock/MockReceiver.h"
#include "Mock/MockSender.h"
#include "Protocol.h"

#include <Homa/Debug.h>

namespace Homa {
namespace Core {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Matcher;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;

class TransportTest : public ::testing::Test {
  public:
    TransportTest()
        : mockDriver()
        , transport(new Transport(&mockDriver, 22))
        , mockSender(new NiceMock<Homa::Mock::MockSender>(transport, 0, 0))
        , mockReceiver(new NiceMock<Homa::Mock::MockReceiver>(transport, 0, 0))
        , savedLogPolicy(Debug::getLogPolicy())
    {
        transport->sender.reset(mockSender);
        transport->receiver.reset(mockReceiver);
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~TransportTest()
    {
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    Transport* transport;
    NiceMock<Homa::Mock::MockSender>* mockSender;
    NiceMock<Homa::Mock::MockReceiver>* mockReceiver;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(TransportTest, Op_drop)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0));

    EXPECT_FALSE(op->destroy);
    EXPECT_TRUE(transport->unusedOps.queue.empty());

    {
        SpinLock::Lock lock(op->mutex);
        op->drop(lock);
    }

    EXPECT_TRUE(op->destroy);
    EXPECT_EQ(1U, transport->unusedOps.queue.size());
    EXPECT_EQ(op, transport->unusedOps.queue.front());
    transport->unusedOps.queue.pop_front();

    {
        SpinLock::Lock lock(op->mutex);
        op->drop(lock);
    }

    EXPECT_TRUE(op->destroy);
    EXPECT_TRUE(transport->unusedOps.queue.empty());
}

TEST_F(TransportTest, Op_processUpdates_destroy)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0));
    op->state.store(OpContext::State::IN_PROGRESS);
    op->destroy = true;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }
    // Nothing to test.
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_NOT_STARTED)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    InboundMessage inMessage(&mockDriver, 0, 0);
    op->inMessage = &inMessage;
    EXPECT_EQ(OpContext::State::NOT_STARTED, op->state.load());
    EXPECT_FALSE(op->inMessage->isReady());
    EXPECT_EQ(0U, op->inMessage->get()->MESSAGE_HEADER_LENGTH);
    EXPECT_TRUE(transport->pendingServerOps.queue.empty());

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::NOT_STARTED, op->state.load());
    EXPECT_EQ(0U, op->inMessage->get()->MESSAGE_HEADER_LENGTH);
    EXPECT_TRUE(transport->pendingServerOps.queue.empty());
    EXPECT_FALSE(op->destroy);

    inMessage.fullMessageReceived = true;

    char payload[1028];
    NiceMock<Homa::Mock::MockDriver::MockPacket> mockPacket(payload);
    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
    EXPECT_EQ(sizeof(Protocol::Message::Header),
              op->inMessage->get()->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(1U, transport->pendingServerOps.queue.size());
    EXPECT_EQ(op, transport->pendingServerOps.queue.front());
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_IN_PROGRESS_notDone)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::IN_PROGRESS);
    EXPECT_FALSE(op->outMessage.isAcked());
    EXPECT_FALSE(op->outMessage.isSent());
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_IN_PROGRESS_notDone_reply)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::IN_PROGRESS);
    op->outMessage.sent = false;
    op->outMessage.id.tag = Protocol::MessageId::ULTIMATE_RESPONSE_TAG;
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_IN_PROGRESS_done_acked)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::IN_PROGRESS);
    op->outMessage.acknowledged = true;
    InboundMessage inMessage(&mockDriver, 0, 0);
    op->inMessage = &inMessage;
    inMessage.id.tag = Protocol::MessageId::INITIAL_REQUEST_TAG;
    EXPECT_TRUE(op->outMessage.isAcked());
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_IN_PROGRESS_done_reply_sent)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::IN_PROGRESS);
    op->outMessage.acknowledged = false;
    op->outMessage.sent = true;
    op->outMessage.id.tag = Protocol::MessageId::ULTIMATE_RESPONSE_TAG;
    InboundMessage inMessage(&mockDriver, 0, 0);
    op->inMessage = &inMessage;
    inMessage.id.tag = Protocol::MessageId::INITIAL_REQUEST_TAG;
    EXPECT_TRUE(op->outMessage.isSent());
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_IN_PROGRESS_done_noSendDone)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::IN_PROGRESS);
    op->outMessage.sent = true;
    InboundMessage inMessage(&mockDriver, 0, 0);
    op->inMessage = &inMessage;
    inMessage.id.tag = Protocol::MessageId::INITIAL_REQUEST_TAG;
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_IN_PROGRESS_done_sendDone)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::IN_PROGRESS);
    op->outMessage.sent = true;
    InboundMessage inMessage(&mockDriver, 0, 0);
    op->inMessage = &inMessage;
    inMessage.id.tag = Protocol::MessageId::INITIAL_REQUEST_TAG + 1;
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    char payload[1028];
    NiceMock<Homa::Mock::MockDriver::MockPacket> mockPacket(payload);
    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    Mock::VerifyAndClearExpectations(&mockDriver);
    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_COMPLETED)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::COMPLETED);
    op->retained = true;
    EXPECT_FALSE(op->destroy);

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_FALSE(op->destroy);

    op->retained = false;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_TRUE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_ServerOp_FAILED)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    op->state.store(OpContext::State::FAILED);
    op->retained = true;
    EXPECT_FALSE(op->destroy);

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::FAILED, op->state.load());
    EXPECT_FALSE(op->destroy);

    op->retained = false;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::FAILED, op->state.load());
    EXPECT_TRUE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_RemoteOp_not_retained)
{
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), false);
    op->retained = true;
    EXPECT_FALSE(op->destroy);

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_FALSE(op->destroy);

    op->retained = false;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_TRUE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_RemoteOp_NOT_STARTED)
{
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), false);
    op->state.store(OpContext::State::NOT_STARTED);
    op->retained = true;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::NOT_STARTED, op->state.load());
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_RemoteOp_IN_PROGRESS)
{
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), false);
    InboundMessage inMessage(&mockDriver, 0, 0);
    op->inMessage = &inMessage;
    op->state.store(OpContext::State::IN_PROGRESS);
    op->retained = true;
    EXPECT_FALSE(op->inMessage->isReady());
    EXPECT_EQ(0U, op->inMessage->get()->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
    EXPECT_EQ(0U, op->inMessage->get()->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);

    inMessage.fullMessageReceived = true;

    char payload[1028];
    NiceMock<Homa::Mock::MockDriver::MockPacket> mockPacket(payload);
    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_EQ(sizeof(Protocol::Message::Header),
              op->inMessage->get()->MESSAGE_HEADER_LENGTH);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_RemoteOp_COMPLETED)
{
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), false);
    op->state.store(OpContext::State::COMPLETED);
    op->retained = true;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::COMPLETED, op->state.load());
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, Op_processUpdates_RemoteOp_FAILED)
{
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), false);
    op->state.store(OpContext::State::FAILED);
    op->retained = true;

    {
        SpinLock::Lock lock(op->mutex);
        op->processUpdates(lock);
    }

    EXPECT_EQ(OpContext::State::FAILED, op->state.load());
    EXPECT_FALSE(op->destroy);
}

TEST_F(TransportTest, allocOp)
{
    char payload[1024];
    Homa::Mock::MockDriver::MockPacket packet(payload);
    Homa::Mock::MockDriver::MockAddress mockAddress;

    EXPECT_EQ(0U, transport->opPool.outstandingObjects);
    EXPECT_TRUE(transport->activeOps.empty());

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet));
    EXPECT_CALL(mockDriver, getLocalAddress).WillOnce(Return(&mockAddress));
    EXPECT_CALL(mockAddress, toRaw).Times(1);

    OpContext* context = transport->allocOp();

    Transport::Op* op = static_cast<Transport::Op*>(context);
    EXPECT_EQ(1U, transport->opPool.outstandingObjects);
    EXPECT_EQ(1U, transport->activeOps.count(op));
    EXPECT_EQ(sizeof(Protocol::Message::Header),
              op->outMessage.message.rawLength());
    EXPECT_TRUE(op->retained.load());
}

TEST_F(TransportTest, receiveOp)
{
    char payload0[1024];
    char payload1[1024];
    Homa::Mock::MockDriver::MockPacket packet0(payload0);
    Homa::Mock::MockDriver::MockPacket packet1(payload1);
    Driver::Address::Raw rawAddress;
    rawAddress.bytes[0] = 22;

    Transport::Op* serverOp = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), true);

    InboundMessage inMessage(transport->driver,
                             sizeof(Protocol::Packet::DataHeader), 0);
    inMessage.message.setPacket(0, &packet0);
    Protocol::Message::Header* header =
        inMessage.message.defineHeader<Protocol::Message::Header>();
    header->replyAddress = rawAddress;
    serverOp->inMessage = &inMessage;

    transport->pendingServerOps.queue.push_back(serverOp);
    EXPECT_EQ(OpContext::State::NOT_STARTED, serverOp->state.load());
    EXPECT_EQ(1U, transport->pendingServerOps.queue.size());

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet1));

    OpContext* context = transport->receiveOp();

    Transport::Op* op = static_cast<Transport::Op*>(context);
    EXPECT_EQ(serverOp, op);
    EXPECT_EQ(sizeof(Protocol::Message::Header),
              op->outMessage.message.rawLength());
    EXPECT_TRUE(transport->pendingServerOps.queue.empty());
    EXPECT_EQ(rawAddress.bytes[0], op->outMessage.get()
                                       ->getHeader<Protocol::Message::Header>()
                                       ->replyAddress.bytes[0]);
    EXPECT_TRUE(op->retained.load());
    EXPECT_EQ(0U, transport->pendingServerOps.queue.size());
}

TEST_F(TransportTest, receiveOp_empty)
{
    EXPECT_TRUE(transport->pendingServerOps.queue.empty());
    EXPECT_CALL(mockDriver, allocPacket).Times(0);

    OpContext* context = transport->receiveOp();

    Transport::Op* op = static_cast<Transport::Op*>(context);
    EXPECT_EQ(nullptr, op);
}

TEST_F(TransportTest, releaseOp)
{
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(0, 0), false);
    op->retained.store(true);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    transport->releaseOp(op);

    EXPECT_FALSE(op->retained.load());
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
}

TEST_F(TransportTest, sendRequest_ServerOp)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    InboundMessage message(&mockDriver, 0, 0);
    Protocol::MessageId expectedId = {transport->transportId, 42, 3};
    op->inMessage = &message;
    op->inMessage->id = expectedId;
    op->inMessage->id.tag--;
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_CALL(*mockSender, sendMessage(Eq(expectedId), Eq(destination),
                                         Eq(&op->outMessage)));

    transport->sendRequest(op, destination);
}

TEST_F(TransportTest, sendRequest_RemoteOp)
{
    Protocol::OpId expectedOpId = {transport->transportId,
                                   transport->nextOpSequenceNumber};
    Driver::Address* destination = (Driver::Address*)22;
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    expectedOpId, false);

    EXPECT_CALL(*mockSender,
                sendMessage(Eq(Protocol::MessageId(
                                expectedOpId,
                                Protocol::MessageId::INITIAL_REQUEST_TAG)),
                            Eq(destination), Eq(&op->outMessage)));

    transport->sendRequest(op, destination);

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
}

TEST_F(TransportTest, sendReply)
{
    char payload[1024];
    Homa::Mock::MockDriver::MockPacket packet(payload);
    Driver::Address* replyAddress = (Driver::Address*)22;
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0), true);
    Protocol::OpId expectedOpId = {42, 32};
    InboundMessage message(transport->driver,
                           sizeof(Protocol::Packet::DataHeader), 0);
    message.id = Protocol::MessageId(expectedOpId, 2);
    message.message.setPacket(0, &packet);
    Protocol::Message::Header* header =
        message.message.defineHeader<Protocol::Message::Header>();
    op->inMessage = &message;

    EXPECT_CALL(mockDriver, getAddress(Matcher<Driver::Address::Raw const*>(
                                Eq(&header->replyAddress))))
        .WillOnce(Return(replyAddress));
    EXPECT_CALL(*mockSender,
                sendMessage(Eq(Protocol::MessageId(
                                expectedOpId,
                                Protocol::MessageId::ULTIMATE_RESPONSE_TAG)),
                            Eq(replyAddress), Eq(&op->outMessage)));

    transport->sendReply(op);

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
}

TEST_F(TransportTest, poll)
{
    EXPECT_CALL(mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(*mockSender, poll);
    EXPECT_CALL(*mockReceiver, poll);
    EXPECT_CALL(*mockReceiver, receiveMessage).WillOnce(Return(nullptr));

    transport->poll();
}

TEST_F(TransportTest, hintUpdatedOp)
{
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver,
                                                    Protocol::OpId(0, 0));

    EXPECT_EQ(0U, transport->updateHints.ops.count(op));
    EXPECT_TRUE(transport->updateHints.order.empty());

    transport->hintUpdatedOp(op);

    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_EQ(1U, transport->updateHints.order.size());
    EXPECT_EQ(op, transport->updateHints.order.front());

    transport->hintUpdatedOp(op);

    EXPECT_EQ(1U, transport->updateHints.ops.count(op));
    EXPECT_EQ(1U, transport->updateHints.order.size());
    EXPECT_EQ(op, transport->updateHints.order.front());
}

TEST_F(TransportTest, processPackets)
{
    char payload[8][1024];
    Homa::Driver::Packet* packets[8];

    // Set DATA packet
    Homa::Mock::MockDriver::MockPacket dataPacket(payload[0], 1024);
    static_cast<Protocol::Packet::DataHeader*>(dataPacket.payload)
        ->common.opcode = Protocol::Packet::DATA;
    packets[0] = &dataPacket;
    EXPECT_CALL(*mockReceiver,
                handleDataPacket(Eq(&dataPacket), Eq(&mockDriver)));

    // Set GRANT packet
    Homa::Mock::MockDriver::MockPacket grantPacket(payload[1], 1024);
    static_cast<Protocol::Packet::GrantHeader*>(grantPacket.payload)
        ->common.opcode = Protocol::Packet::GRANT;
    packets[1] = &grantPacket;
    EXPECT_CALL(*mockSender,
                handleGrantPacket(Eq(&grantPacket), Eq(&mockDriver)));

    // Set DONE packet
    Homa::Mock::MockDriver::MockPacket donePacket(payload[2], 1024);
    static_cast<Protocol::Packet::DoneHeader*>(donePacket.payload)
        ->common.opcode = Protocol::Packet::DONE;
    packets[2] = &donePacket;
    EXPECT_CALL(*mockSender,
                handleDonePacket(Eq(&donePacket), Eq(&mockDriver)));

    // Set RESEND packet
    Homa::Mock::MockDriver::MockPacket resendPacket(payload[3], 1024);
    static_cast<Protocol::Packet::ResendHeader*>(resendPacket.payload)
        ->common.opcode = Protocol::Packet::RESEND;
    packets[3] = &resendPacket;
    EXPECT_CALL(*mockSender,
                handleResendPacket(Eq(&resendPacket), Eq(&mockDriver)));

    // Set BUSY packet
    Homa::Mock::MockDriver::MockPacket busyPacket(payload[4], 1024);
    static_cast<Protocol::Packet::PingHeader*>(busyPacket.payload)
        ->common.opcode = Protocol::Packet::BUSY;
    packets[4] = &busyPacket;
    EXPECT_CALL(*mockReceiver,
                handleBusyPacket(Eq(&busyPacket), Eq(&mockDriver)));

    // Set PING packet
    Homa::Mock::MockDriver::MockPacket pingPacket(payload[5], 1024);
    static_cast<Protocol::Packet::PingHeader*>(pingPacket.payload)
        ->common.opcode = Protocol::Packet::PING;
    packets[5] = &pingPacket;
    EXPECT_CALL(*mockReceiver,
                handlePingPacket(Eq(&pingPacket), Eq(&mockDriver)));

    // Set UNKNOWN packet
    Homa::Mock::MockDriver::MockPacket unknownPacket(payload[6], 1024);
    static_cast<Protocol::Packet::UnknownHeader*>(unknownPacket.payload)
        ->common.opcode = Protocol::Packet::UNKNOWN;
    packets[6] = &unknownPacket;
    EXPECT_CALL(*mockSender,
                handleUnknownPacket(Eq(&unknownPacket), Eq(&mockDriver)));

    // Set ERROR packet
    Homa::Mock::MockDriver::MockPacket errorPacket(payload[7], 1024);
    static_cast<Protocol::Packet::ErrorHeader*>(errorPacket.payload)
        ->common.opcode = Protocol::Packet::ERROR;
    packets[7] = &errorPacket;
    EXPECT_CALL(*mockSender,
                handleErrorPacket(Eq(&errorPacket), Eq(&mockDriver)));

    EXPECT_CALL(mockDriver, receivePackets)
        .WillOnce(DoAll(SetArrayArgument<1>(packets, packets + 8), Return(8)));

    transport->processPackets();
}

TEST_F(TransportTest, processInboundMessages_response)
{
    Protocol::MessageId id(42, 32, Protocol::MessageId::ULTIMATE_RESPONSE_TAG);
    Transport::Op* op =
        transport->opPool.construct(transport, &mockDriver, id, false);
    transport->remoteOps.insert({id, op});
    InboundMessage message(&mockDriver, 0, 0);
    message.id = id;

    EXPECT_EQ(1U, transport->remoteOps.count(id));
    EXPECT_EQ(nullptr, message.op);
    EXPECT_EQ(nullptr, op->inMessage);
    EXPECT_EQ(0U, transport->updateHints.ops.size());

    EXPECT_CALL(*mockReceiver, receiveMessage)
        .WillOnce(Return(&message))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockReceiver, dropMessage).Times(0);

    transport->processInboundMessages();

    EXPECT_EQ(op, message.op);
    EXPECT_EQ(&message, op->inMessage);
    EXPECT_EQ(1U, transport->updateHints.ops.size());
}

TEST_F(TransportTest, processInboundMessages_responseDrop)
{
    Protocol::MessageId id(42, 32, Protocol::MessageId::ULTIMATE_RESPONSE_TAG);
    InboundMessage message(&mockDriver, 0, 0);
    message.id = id;

    EXPECT_CALL(*mockReceiver, receiveMessage)
        .WillOnce(Return(&message))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockReceiver, dropMessage(Eq(&message)));

    transport->processInboundMessages();
}

TEST_F(TransportTest, processInboundMessages_request)
{
    Protocol::MessageId id(42, 32, Protocol::MessageId::INITIAL_REQUEST_TAG);
    InboundMessage message(&mockDriver, 0, 0);
    message.id = id;

    EXPECT_EQ(nullptr, message.op);
    EXPECT_EQ(0U, transport->opPool.outstandingObjects);
    EXPECT_TRUE(transport->activeOps.empty());
    EXPECT_EQ(0U, transport->updateHints.ops.size());

    EXPECT_CALL(*mockReceiver, receiveMessage)
        .WillOnce(Return(&message))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockReceiver, dropMessage).Times(0);

    transport->processInboundMessages();

    EXPECT_NE(nullptr, message.op);
    EXPECT_EQ(&message, static_cast<Transport::Op*>(message.op)->inMessage);
    EXPECT_EQ(1U, transport->opPool.outstandingObjects);
    EXPECT_FALSE(transport->activeOps.empty());
    EXPECT_EQ(1U, transport->updateHints.ops.size());

    Mock::VerifyAndClearExpectations(mockReceiver);
}

TEST_F(TransportTest, checkForUpdates)
{
    Transport::Op* staleOp = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(1, 1), false);
    transport->hintUpdatedOp(staleOp);
    Transport::Op* op = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(1, 2), false);
    transport->hintUpdatedOp(op);
    transport->activeOps.insert(op);

    EXPECT_FALSE(staleOp->destroy);
    EXPECT_FALSE(op->destroy);
    EXPECT_EQ(2U, transport->updateHints.ops.size());
    EXPECT_EQ(2U, transport->updateHints.order.size());
    EXPECT_EQ(1U, transport->activeOps.size());

    transport->checkForUpdates();

    EXPECT_FALSE(staleOp->destroy);
    EXPECT_TRUE(op->destroy);
    EXPECT_EQ(0U, transport->updateHints.ops.size());
    EXPECT_EQ(0U, transport->updateHints.order.size());
    EXPECT_EQ(1U, transport->activeOps.size());
    EXPECT_EQ(op, transport->unusedOps.queue.front());
}

TEST_F(TransportTest, cleanupOps)
{
    // Stale Op
    Transport::Op* staleOp = transport->opPool.construct(transport, &mockDriver,
                                                         Protocol::OpId(1, 1));
    // Server Op
    Transport::Op* serverOp = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(2, 1));
    serverOp->outMessage.id = {42, 32, 2};
    transport->activeOps.insert(serverOp);
    InboundMessage message(&mockDriver, 0, 0);
    serverOp->inMessage = &message;
    // Remote Op
    Transport::Op* remoteOp = transport->opPool.construct(
        transport, &mockDriver, Protocol::OpId(1, 2), false);
    remoteOp->outMessage.id = {42, 32, 1};
    transport->activeOps.insert(remoteOp);
    transport->remoteOps.insert({remoteOp->opId, remoteOp});

    EXPECT_EQ(0U, transport->activeOps.count(staleOp));
    EXPECT_EQ(1U, transport->activeOps.count(serverOp));
    EXPECT_EQ(1U, transport->activeOps.count(remoteOp));
    EXPECT_EQ(1U, transport->remoteOps.count(remoteOp->opId));

    {
        SpinLock::Lock lock(staleOp->mutex);
        staleOp->drop(lock);
    }
    {
        SpinLock::Lock lock(serverOp->mutex);
        serverOp->drop(lock);
    }
    EXPECT_EQ(2U, transport->unusedOps.queue.size());

    EXPECT_CALL(*mockSender, dropMessage(Eq(&serverOp->outMessage))).Times(1);
    EXPECT_CALL(*mockReceiver, dropMessage(Eq(serverOp->inMessage))).Times(1);

    transport->cleanupOps();

    EXPECT_EQ(0U, transport->unusedOps.queue.size());
    EXPECT_EQ(0U, transport->activeOps.count(staleOp));
    EXPECT_EQ(0U, transport->activeOps.count(serverOp));
    EXPECT_EQ(1U, transport->activeOps.count(remoteOp));
    EXPECT_EQ(1U, transport->remoteOps.count(remoteOp->opId));

    {
        SpinLock::Lock lock(remoteOp->mutex);
        remoteOp->drop(lock);
    }
    EXPECT_EQ(1U, transport->unusedOps.queue.size());

    EXPECT_CALL(*mockSender, dropMessage(Eq(&remoteOp->outMessage))).Times(1);
    EXPECT_CALL(*mockReceiver, dropMessage).Times(0);

    transport->cleanupOps();

    EXPECT_EQ(0U, transport->unusedOps.queue.size());
    EXPECT_EQ(0U, transport->activeOps.count(staleOp));
    EXPECT_EQ(0U, transport->activeOps.count(serverOp));
    EXPECT_EQ(0U, transport->activeOps.count(remoteOp));
    EXPECT_EQ(0U, transport->remoteOps.count(remoteOp->opId));
}

}  // namespace
}  // namespace Core
}  // namespace Homa
