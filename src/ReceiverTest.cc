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
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1028));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        receiver = new Receiver();
        transport = new Transport(&mockDriver, 1);
    }

    ~ReceiverTest()
    {
        delete receiver;
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
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
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    Protocol::MessageId id(42, 32, 22);
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    op->inMessage = message;
    receiver->registeredOps.insert({id, op});
    op->inMessage->newPacket = false;

    EXPECT_TRUE(receiver->unregisteredMessages.empty());
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

    EXPECT_TRUE(receiver->unregisteredMessages.empty());
    EXPECT_TRUE(receiver->receivedMessages.empty());
    EXPECT_TRUE(op->inMessage->message);
    EXPECT_EQ(&mockAddress, op->inMessage->source);
    EXPECT_EQ(2U, message->numExpectedPackets);
    EXPECT_EQ(1420U, op->inMessage->message->messageLength);
    EXPECT_TRUE(op->inMessage->message->occupied.test(1));
    EXPECT_EQ(1U, op->inMessage->message->getNumPackets());
    EXPECT_EQ(1000U, op->inMessage->message->PACKET_DATA_LENGTH);
    EXPECT_TRUE(op->inMessage->newPacket);
    EXPECT_FALSE(op->inMessage->fullMessageReceived);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 1 again; duplicate packet
    op->inMessage->newPacket = false;

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

    EXPECT_TRUE(receiver->unregisteredMessages.empty());
    EXPECT_TRUE(receiver->receivedMessages.empty());
    EXPECT_TRUE(op->inMessage->message->occupied.test(1));
    EXPECT_EQ(1U, op->inMessage->message->getNumPackets());
    EXPECT_EQ(1000U, op->inMessage->message->PACKET_DATA_LENGTH);
    EXPECT_FALSE(op->inMessage->newPacket);
    EXPECT_FALSE(op->inMessage->fullMessageReceived);
    EXPECT_EQ(0U, transport->updateHints.ops.count(op));

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 0; complete the message
    header->index = 0;
    op->inMessage->newPacket = false;

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

    EXPECT_TRUE(receiver->unregisteredMessages.empty());
    EXPECT_TRUE(receiver->receivedMessages.empty());
    EXPECT_TRUE(op->inMessage->message->occupied.test(0));
    EXPECT_EQ(2U, op->inMessage->message->getNumPackets());
    EXPECT_EQ(1000U, op->inMessage->message->PACKET_DATA_LENGTH);
    EXPECT_TRUE(op->inMessage->newPacket);
    EXPECT_TRUE(op->inMessage->fullMessageReceived);
    EXPECT_EQ(1U, transport->updateHints.ops.count(op));

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 0 again on a complete message
    op->inMessage->newPacket = false;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .Times(0);
    EXPECT_CALL(mockAddress, toString).Times(0);

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_FALSE(op->inMessage->newPacket);
    EXPECT_TRUE(receiver->unregisteredMessages.empty());
    EXPECT_TRUE(receiver->receivedMessages.empty());
    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, handleDataPacket_existingUnregistered)
{
    Protocol::MessageId id(42, 32, 22);
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->index = 1;
    header->totalLength = 1420;
    std::string addressStr("remote-location");
    Homa::Mock::MockDriver::MockAddress mockAddress;
    mockPacket.address = &mockAddress;

    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    receiver->unregisteredMessages.insert({id, message});
    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(1U, receiver->unregisteredMessages.size());
    EXPECT_TRUE(receiver->receivedMessages.empty());

    EXPECT_CALL(mockAddress, toString)
        .Times(3)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .WillOnce(Return(&mockAddress));

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(1U, receiver->unregisteredMessages.size());
    EXPECT_EQ(message, receiver->unregisteredMessages.find(id)->second);
    EXPECT_TRUE(receiver->receivedMessages.empty());
}

TEST_F(ReceiverTest, handleDataPacket_newUnregistered)
{
    Protocol::MessageId id(42, 32, 22);
    Protocol::Packet::DataHeader* header =
        static_cast<Protocol::Packet::DataHeader*>(mockPacket.payload);
    header->common.messageId = id;
    header->index = 1;
    header->totalLength = 1420;
    std::string addressStr("remote-location");
    Homa::Mock::MockDriver::MockAddress mockAddress;
    mockPacket.address = &mockAddress;

    EXPECT_EQ(0U, receiver->messagePool.outstandingObjects);
    EXPECT_TRUE(receiver->unregisteredMessages.empty());
    EXPECT_TRUE(receiver->receivedMessages.empty());

    EXPECT_CALL(mockAddress, toString)
        .Times(3)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver,
                getAddress(Matcher<std::string const*>(Pointee(addressStr))))
        .WillOnce(Return(&mockAddress));

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(id, receiver->unregisteredMessages.find(id)->second->getId());
    EXPECT_EQ(id, receiver->receivedMessages.front()->getId());
}

TEST_F(ReceiverTest, handleDataPacket_numExpectedPackets)
{
    // Register op
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    Protocol::MessageId id(42, 32, 22);
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    op->inMessage = message;
    receiver->registeredOps.insert({id, op});

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
    EXPECT_EQ(1U, message->numExpectedPackets);
    EXPECT_EQ(450, op->inMessage->message->messageLength);
    EXPECT_EQ(1000U, op->inMessage->message->PACKET_DATA_LENGTH);

    op->inMessage->message.destroy();

    // 1 full packet
    header->totalLength = 1000;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    EXPECT_EQ(1U, message->numExpectedPackets);
    EXPECT_EQ(1000U, op->inMessage->message->messageLength);
    EXPECT_EQ(1000U, op->inMessage->message->PACKET_DATA_LENGTH);

    op->inMessage->message.destroy();

    // 1 full packet + 1 partial packet
    header->totalLength = 1450;
    receiver->handleDataPacket(&mockPacket, &mockDriver);
    EXPECT_EQ(2U, message->numExpectedPackets);
    EXPECT_EQ(1450U, op->inMessage->message->messageLength);
    EXPECT_EQ(1000U, op->inMessage->message->PACKET_DATA_LENGTH);
}

TEST_F(ReceiverTest, handlePingPacket_basic)
{
    // Setup registered op
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    Protocol::MessageId id(42, 32, 22);
    Homa::Mock::MockDriver::MockAddress mockAddress;
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    message->grantIndexLimit = 11;
    message->source = &mockAddress;
    op->inMessage = message;
    receiver->registeredOps.insert({id, op});
    op->inMessage->newPacket = false;

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
    Protocol::Packet::GrantHeader* header =
        (Protocol::Packet::GrantHeader*)payload;
    EXPECT_EQ(Protocol::Packet::GRANT, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(message->grantIndexLimit, header->indexLimit);
}

TEST_F(ReceiverTest, handlePingPacket_unregisteredMessage)
{
    // Setup unregistered message
    Protocol::MessageId id(42, 32, 22);
    Homa::Mock::MockDriver::MockAddress mockAddress;
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    message->grantIndexLimit = 11;
    message->source = &mockAddress;
    receiver->unregisteredMessages.insert({id, message});

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
    Protocol::Packet::GrantHeader* header =
        (Protocol::Packet::GrantHeader*)payload;
    EXPECT_EQ(Protocol::Packet::GRANT, header->common.opcode);
    EXPECT_EQ(id, header->common.messageId);
    EXPECT_EQ(message->grantIndexLimit, header->indexLimit);
}

TEST_F(ReceiverTest, handlePingPacket_unknown)
{
    Protocol::MessageId id(42, 32, 22);
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
    InboundMessage* msg0 = receiver->messagePool.construct();
    InboundMessage* msg1 = receiver->messagePool.construct();

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
    Protocol::MessageId id = {42, 32, 0};
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    receiver->unregisteredMessages.insert({id, message});
    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(message, receiver->unregisteredMessages.find(id)->second);

    receiver->dropMessage(message);

    EXPECT_EQ(0U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(receiver->unregisteredMessages.end(),
              receiver->unregisteredMessages.find(id));
}

TEST_F(ReceiverTest, registerOp_existingMessage)
{
    Protocol::MessageId id = {42, 32, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    receiver->unregisteredMessages.insert({id, message});

    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(receiver->registeredOps.end(), receiver->registeredOps.find(id));
    EXPECT_EQ(message, receiver->unregisteredMessages.find(id)->second);

    receiver->registerOp(id, op);

    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(op, receiver->registeredOps.find(id)->second);
    EXPECT_EQ(id, receiver->registeredOps.find(id)->second->inMessage->getId());
    EXPECT_EQ(receiver->unregisteredMessages.end(),
              receiver->unregisteredMessages.find(id));
}

TEST_F(ReceiverTest, registerOp_newMessage)
{
    Protocol::MessageId id = {42, 32, 0};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);

    EXPECT_EQ(0U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(receiver->registeredOps.end(), receiver->registeredOps.find(id));

    receiver->registerOp(id, op);

    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(op, receiver->registeredOps.find(id)->second);
    EXPECT_EQ(id, receiver->registeredOps.find(id)->second->inMessage->getId());
}

TEST_F(ReceiverTest, dropOp)
{
    Protocol::MessageId id = {42, 32, 1};
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    op->inMessage = message;
    receiver->registeredOps.insert({id, op});

    EXPECT_EQ(1U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(op, receiver->registeredOps.find(id)->second);
    EXPECT_EQ(id, receiver->registeredOps.find(id)->second->inMessage->getId());

    receiver->dropOp(op);

    EXPECT_EQ(0U, receiver->messagePool.outstandingObjects);
    EXPECT_EQ(receiver->registeredOps.end(), receiver->registeredOps.find(id));
}

TEST_F(ReceiverTest, poll)
{
    // Nothing to test.
    receiver->poll();
}

TEST_F(ReceiverTest, sendDonePacket)
{
    Protocol::MessageId id = {42, 32, 1};
    Homa::Mock::MockDriver::MockAddress mockAddress;
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    InboundMessage* message = receiver->messagePool.construct();
    message->source = &mockAddress;
    message->id = id;
    op->inMessage = message;

    EXPECT_CALL(mockDriver, allocPacket()).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    {
        SpinLock::Lock lock(op->mutex);
        Receiver::sendDonePacket(op, &mockDriver, lock);
    }
    Protocol::Packet::CommonHeader* header =
        static_cast<Protocol::Packet::CommonHeader*>(mockPacket.payload);
    EXPECT_EQ(Protocol::Packet::DONE, header->opcode);
    EXPECT_EQ(id, header->messageId);
    EXPECT_EQ(sizeof(Protocol::Packet::DoneHeader), mockPacket.length);
    EXPECT_EQ(&mockAddress, mockPacket.address);
}

TEST_F(ReceiverTest, sendGrantPacket)
{
    Protocol::MessageId msgId(42, 32, 22);
    Driver::Address* sourceAddr = (Driver::Address*)22;
    uint32_t TOTAL_MESSAGE_LEN = 9000;

    InboundMessage message;
    message.id = msgId;
    message.source = sourceAddr;
    message.message.construct(&mockDriver, 28, TOTAL_MESSAGE_LEN);
    message.numExpectedPackets = 9;
    EXPECT_EQ(1000U, message.message->PACKET_DATA_LENGTH);

    InSequence _seq;

    {
        // GRANT 5 more packets (up to index 6)
        message.message->numPackets = 1;

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
        message.message->numPackets = 8;

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

TEST_F(ReceiverTest, schedule)
{
    Protocol::MessageId id(42, 32, 22);
    Driver::Address* sourceAddr = (Driver::Address*)22;
    uint32_t TOTAL_MESSAGE_LEN = 9000;

    InboundMessage* message = receiver->messagePool.construct();
    message->id = id;
    message->source = sourceAddr;
    message->message.construct(&mockDriver, 28, TOTAL_MESSAGE_LEN);
    message->message->numPackets = 1;
    EXPECT_EQ(1000U, message->message->PACKET_DATA_LENGTH);
    EXPECT_EQ(1U, message->message->getNumPackets());
    EXPECT_FALSE(message->newPacket);

    receiver->unregisteredMessages.insert({id, message});

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
    Transport::Op* op = transport->opPool.construct(transport, &mockDriver);
    op->inMessage = message;
    receiver->registeredOps.insert({id, op});
    receiver->unregisteredMessages.erase(id);

    message->newPacket = true;

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&mockPacket));
    EXPECT_CALL(mockDriver, sendPackets(Pointee(&mockPacket), Eq(1))).Times(1);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    receiver->schedule();

    Mock::VerifyAndClearExpectations(&mockDriver);

    EXPECT_FALSE(message->newPacket);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
