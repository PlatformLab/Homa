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

#include <Homa/Debug.h>

namespace Homa {
namespace Core {
namespace {

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
        , mockSender()
        , mockReceiver()
        , transport(new Transport(&mockDriver, 22))
        , savedLogPolicy(Debug::getLogPolicy())
    {
        transport->sender.reset(&mockSender);
        transport->receiver.reset(&mockReceiver);
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~TransportTest()
    {
        // Release the Mock object so delete won't be called on them
        transport->receiver.release();
        transport->sender.release();
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    Homa::Mock::MockSender mockSender;
    Homa::Mock::MockReceiver mockReceiver;
    Transport* transport;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(TransportTest, allocOp)
{
    char payload[1024];
    Homa::Mock::MockDriver::MockPacket packet(payload);

    EXPECT_EQ(0U, transport->opContextPool.pool.outstandingObjects);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet));

    OpContext* op = transport->allocOp();

    EXPECT_EQ(1U, transport->opContextPool.pool.outstandingObjects);
    EXPECT_EQ(sizeof(Protocol::Message::Header),
              op->outMessage.message.rawLength());
    EXPECT_TRUE(op->retained.load());
}

TEST_F(TransportTest, receiveOp)
{
    char payload[1024];
    Homa::Mock::MockDriver::MockPacket packet(payload);

    OpContext* serverOp = transport->opContextPool.construct();
    transport->serverOpQueue.queue.push_back(serverOp);
    EXPECT_EQ(OpContext::State::NOT_STARTED, serverOp->state.load());

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet));

    OpContext* op = transport->receiveOp();

    EXPECT_EQ(serverOp, op);
    EXPECT_EQ(sizeof(Protocol::Message::Header),
              op->outMessage.message.rawLength());
    EXPECT_TRUE(transport->serverOpQueue.queue.empty());
    EXPECT_TRUE(op->retained.load());
}

TEST_F(TransportTest, receiveOp_empty)
{
    EXPECT_TRUE(transport->serverOpQueue.queue.empty());
    EXPECT_CALL(mockDriver, allocPacket).Times(0);

    OpContext* op = transport->receiveOp();

    EXPECT_EQ(nullptr, op);
}

TEST_F(TransportTest, releaseOp)
{
    OpContext* op = transport->opContextPool.construct(false);
    op->retained.store(true);

    transport->releaseOp(op);

    EXPECT_FALSE(op->retained.load());
}

TEST_F(TransportTest, sendRequest_ServerOp)
{
    OpContext* op = transport->opContextPool.construct(true);
    Protocol::MessageId expectedId = {transport->transportId, 42, 3};
    op->inMessage.id = expectedId;
    op->inMessage.id.tag--;
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_CALL(mockSender,
                sendMessage(Eq(expectedId), Eq(destination), Eq(op)));

    transport->sendRequest(op, destination);
}

TEST_F(TransportTest, sendRequest_RemoteOp)
{
    OpContext* op = transport->opContextPool.construct(false);

    Protocol::OpId expectedOpId = {transport->transportId,
                                   transport->nextOpSequenceNumber};
    Driver::Address* destination = (Driver::Address*)22;

    EXPECT_CALL(
        mockReceiver,
        registerMessage(
            Eq(Protocol::MessageId(expectedOpId,
                                   Protocol::MessageId::ULTIMATE_RESPONSE_TAG)),
            Eq(op)));
    EXPECT_CALL(mockSender,
                sendMessage(Eq(Protocol::MessageId(
                                expectedOpId,
                                Protocol::MessageId::INITIAL_REQUEST_TAG)),
                            Eq(destination), Eq(op)));

    transport->sendRequest(op, destination);

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
}

TEST_F(TransportTest, sendReply)
{
    char payload[1024];
    Homa::Mock::MockDriver::MockPacket packet(payload);
    Driver::Address* replyAddress = (Driver::Address*)22;
    OpContext* op = transport->opContextPool.construct(true);
    Protocol::OpId expectedOpId = {42, 32};

    op->inMessage.id = Protocol::MessageId(expectedOpId, 2);
    op->inMessage.message.construct(transport->driver,
                                    sizeof(Protocol::Packet::DataHeader), 0);
    op->inMessage.message->setPacket(0, &packet);
    Protocol::Message::Header* header =
        op->inMessage.message->defineHeader<Protocol::Message::Header>();

    EXPECT_CALL(mockDriver, getAddress(Matcher<Driver::Address::Raw const*>(
                                Eq(&header->replyAddress))))
        .WillOnce(Return(replyAddress));
    EXPECT_CALL(mockSender,
                sendMessage(Eq(Protocol::MessageId(
                                expectedOpId,
                                Protocol::MessageId::ULTIMATE_RESPONSE_TAG)),
                            Eq(replyAddress), Eq(op)));

    transport->sendReply(op);

    EXPECT_EQ(OpContext::State::IN_PROGRESS, op->state.load());
}

// TEST_F(TransportTest, newMessage)
// {
//     EXPECT_EQ(0U, transport->messagePool.pool.outstandingObjects);

//     Message message = transport->newMessage();

//     EXPECT_EQ(1U, transport->messagePool.pool.outstandingObjects);
//     EXPECT_EQ(transport, message.transportImpl);
// }

// TEST_F(TransportTest, receiveMessage)
// {
//     EXPECT_EQ(24U, sizeof(Protocol::Packet::DataHeader));
//     Protocol::MessageId msgId = {42, 1};
//     MessageContext* context =
//         transport->receiver.contextPool->construct(msgId, 24, &mockDriver);
//     transport->receiver.messageMap.insert(
//         {msgId, transport->receiver.inboundPool.construct(context)});
//     transport->receiver.messageQueue.push_back(context);

//     EXPECT_EQ(1U, context->refCount);

//     Message message = transport->receiveMessage();

//     EXPECT_EQ(0U, transport->receiver.messageQueue.size());
//     EXPECT_EQ(context, message.context);
//     EXPECT_EQ(transport, message.transportImpl);
// }

// TEST_F(TransportTest, sendMessage)
// {
//     char payload[1024];
//     MockDriver::MockPacket mockPacket(payload);
//     Message message = transport->newMessage();
//     message.context->setPacket(0, &mockPacket);
//     message.context->messageLength = 420;
//     mockPacket.length =
//         message.context->messageLength + message.context->DATA_HEADER_LENGTH;
//     message.context->address = (Driver::Address*)22;

//     EXPECT_EQ(0U, transport->sender.sendQueue.size());
//     EXPECT_EQ(0U, transport->sender.outboundPool.outstandingObjects);

//     transport->sendMessage(&message);

//     EXPECT_EQ(22U, (uint64_t)mockPacket.address);
//     EXPECT_EQ(0U, mockPacket.priority);
//     Protocol::Packet::DataHeader* header =
//         static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
//     EXPECT_EQ(message.context->msgId, header->common.msgId);
//     EXPECT_EQ(message.context->messageLength, header->totalLength);
//     EXPECT_EQ(1U, transport->sender.sendQueue.size());
//     EXPECT_EQ(1U, transport->sender.outboundPool.outstandingObjects);
// }

TEST_F(TransportTest, poll)
{
    EXPECT_CALL(mockDriver, receivePackets).WillOnce(Return(0));
    EXPECT_CALL(mockSender, poll);
    EXPECT_CALL(mockReceiver, poll);
    EXPECT_CALL(mockReceiver, receiveMessage).WillOnce(Return(nullptr));

    transport->poll();
}

TEST_F(TransportTest, processPackets)
{
    char payload[2][1024];
    Homa::Driver::Packet* packets[2];

    // Set DATA packet
    Homa::Mock::MockDriver::MockPacket dataPacket(payload[0], 1024);
    static_cast<Protocol::Packet::DataHeader*>(dataPacket.payload)
        ->common.opcode = Protocol::Packet::DATA;
    packets[0] = &dataPacket;
    EXPECT_CALL(mockReceiver,
                handleDataPacket(Eq(&dataPacket), Eq(&mockDriver)));

    // Set GRANT packet
    Homa::Mock::MockDriver::MockPacket grantPacket(payload[1], 1024);
    static_cast<Protocol::Packet::GrantHeader*>(grantPacket.payload)
        ->common.opcode = Protocol::Packet::GRANT;
    packets[1] = &grantPacket;
    EXPECT_CALL(mockSender,
                handleGrantPacket(Eq(&grantPacket), Eq(&mockDriver)));

    EXPECT_CALL(mockDriver, receivePackets)
        .WillOnce(DoAll(SetArrayArgument<1>(packets, packets + 2), Return(2)));

    transport->processPackets();
}

TEST_F(TransportTest, processMessages)
{
    OpContext* serverOp = transport->opContextPool.construct();
    OpContext* remoteOp = transport->opContextPool.construct(false);
    EXPECT_TRUE(transport->serverOpQueue.queue.empty());
    EXPECT_EQ(OpContext::State::NOT_STARTED, remoteOp->state.load());

    EXPECT_CALL(mockReceiver, receiveMessage)
        .WillOnce(Return(serverOp))
        .WillOnce(Return(remoteOp))
        .WillOnce(Return(nullptr));

    transport->processMessages();

    EXPECT_EQ(serverOp, transport->serverOpQueue.queue.front());
    EXPECT_EQ(OpContext::State::COMPLETED, remoteOp->state.load());
}

}  // namespace
}  // namespace Core
}  // namespace Homa
