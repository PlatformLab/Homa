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

#include "Receiver.h"

#include "MockDriver.h"

#include <Homa/Debug.h>

#include <mutex>

namespace Homa {
namespace Core {
namespace {

using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;

class ReceiverTest : public ::testing::Test {
  public:
    ReceiverTest()
        : mockDriver()
        , mockPacket(&payload)
        , messagePool()
        , scheduler()
        , receiver()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        messagePool = new MessagePool();
        scheduler = new Scheduler(&mockDriver);
        receiver = new Receiver(scheduler, messagePool);
    }

    ~ReceiverTest()
    {
        delete receiver;
        delete scheduler;
        delete messagePool;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    NiceMock<MockDriver::MockPacket> mockPacket;
    char payload[1024];
    MessagePool* messagePool;
    Scheduler* scheduler;
    Receiver* receiver;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(ReceiverTest, destructor)
{
    void* receiver;  // Don't use the test fixtures "receiver" variable
    Receiver* localReceiver = new Receiver(scheduler, messagePool);

    MessageContext* context[3];
    for (uint64_t i = 0; i < 3; ++i) {
        context[i] = messagePool->construct({42, 10 + i}, 24, &mockDriver);
        Receiver::InboundMessage* message =
            localReceiver->inboundPool.construct(context[i]);
        localReceiver->messageMap.insert({context[i]->msgId, message});
    }

    EXPECT_EQ(3U, messagePool->pool.outstandingObjects);

    delete localReceiver;

    EXPECT_EQ(0U, messagePool->pool.outstandingObjects);
}

MATCHER_P(PtrStrEq, addressString, "")
{
    return addressString == *arg;
}

TEST_F(ReceiverTest, handleDataPacket)
{
    // receive packet 1
    Protocol::DataHeader* header =
        static_cast<Protocol::DataHeader*>(mockPacket.payload);
    header->common.msgId = {42, 1};
    header->index = 1;
    header->totalLength = 1420;
    std::string addressStr("remote-location");
    MockDriver::MockAddress mockAddress;
    mockPacket.address = &mockAddress;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(3)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver, getAddress(PtrStrEq(addressStr)))
        .WillOnce(Return(&mockAddress));
    char grantPayload[1024];
    MockDriver::MockPacket grantPacket(grantPayload);
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&grantPacket));
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&grantPacket), Eq(1)))
        .Times(1);

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    auto it = receiver->messageMap.find(header->common.msgId);
    EXPECT_FALSE(it == receiver->messageMap.end());
    Receiver::InboundMessage* message = it->second;
    EXPECT_EQ(&mockAddress, message->context->address);
    EXPECT_EQ(1420U, message->context->messageLength);
    EXPECT_TRUE(message->context->occupied.test(1));
    EXPECT_EQ(1U, message->context->getNumPackets());
    EXPECT_EQ(1000U, message->context->PACKET_DATA_LENGTH);
    Protocol::GrantHeader* grantHeader =
        static_cast<Protocol::GrantHeader*>(grantPacket.payload);
    EXPECT_EQ(header->common.msgId, grantHeader->common.msgId);
    EXPECT_EQ(6000U, grantHeader->offset);
    EXPECT_EQ(sizeof(Protocol::GrantHeader), grantPacket.length);
    EXPECT_EQ(&mockAddress, grantPacket.address);
    EXPECT_FALSE(message->fullMessageReceived);

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 1 again; duplicate packet

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, getAddress(PtrStrEq(addressStr))).Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(2)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver, allocPacket).Times(0);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&grantPacket), Eq(1)))
        .Times(0);
    EXPECT_EQ(0U, receiver->messageQueue.size());

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_TRUE(message->context->occupied.test(1));
    EXPECT_EQ(1U, message->context->getNumPackets());
    EXPECT_EQ(1000U, message->context->PACKET_DATA_LENGTH);
    EXPECT_FALSE(message->fullMessageReceived);

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 0; complete the message
    header->index = 0;

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);
    EXPECT_CALL(mockDriver, getAddress(PtrStrEq(addressStr))).Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(2)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&grantPacket));
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&grantPacket), Eq(1)))
        .Times(1);
    EXPECT_EQ(0U, receiver->messageQueue.size());

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    EXPECT_TRUE(message->context->occupied.test(0));
    EXPECT_EQ(2U, message->context->getNumPackets());
    EXPECT_EQ(1000U, message->context->PACKET_DATA_LENGTH);
    EXPECT_EQ(header->common.msgId, grantHeader->common.msgId);
    EXPECT_EQ(7000U, grantHeader->offset);
    EXPECT_EQ(sizeof(Protocol::GrantHeader), grantPacket.length);
    EXPECT_EQ(&mockAddress, grantPacket.address);
    EXPECT_TRUE(message->fullMessageReceived);
    EXPECT_EQ(1U, receiver->messageQueue.size());
    EXPECT_EQ(message->context, receiver->messageQueue.front());

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);

    // receive packet 0 again on a complete message
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);
    EXPECT_CALL(mockDriver, getAddress(PtrStrEq(addressStr))).Times(0);
    EXPECT_CALL(mockAddress, toString).Times(0);
    EXPECT_CALL(mockDriver, allocPacket).Times(0);
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&grantPacket), Eq(1)))
        .Times(0);
    EXPECT_TRUE(message->fullMessageReceived);

    receiver->handleDataPacket(&mockPacket, &mockDriver);

    Mock::VerifyAndClearExpectations(&mockDriver);
}

TEST_F(ReceiverTest, receiveMessage)
{
    EXPECT_EQ(24U, sizeof(Protocol::DataHeader));
    Protocol::MessageId msgId = {42, 1};
    MessageContext* context =
        receiver->contextPool->construct(msgId, 24, &mockDriver);
    Receiver::InboundMessage* message =
        receiver->inboundPool.construct(context);
    receiver->messageMap.insert({msgId, message});
    receiver->messageQueue.push_back(message->context);

    EXPECT_EQ(1U, context->refCount);

    MessageContext* retContext = receiver->receiveMessage();

    EXPECT_EQ(context, retContext);
    EXPECT_EQ(1U, receiver->contextPool->pool.outstandingObjects);
    EXPECT_EQ(1U, receiver->inboundPool.outstandingObjects);
    EXPECT_EQ(0U, receiver->messageMap.size());
    EXPECT_EQ(0U, receiver->messageQueue.size());
    EXPECT_EQ(1U, context->refCount);
}

TEST_F(ReceiverTest, receiveMessage_empty)
{
    EXPECT_EQ(0U, receiver->messageQueue.size());

    MessageContext* retContext = receiver->receiveMessage();

    EXPECT_EQ(nullptr, retContext);
}

}  // namespace
}  // namespace Core
}  // namespace Homa
