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

#include "TransportImpl.h"

#include "MockDriver.h"

#include <Homa/Debug.h>

namespace Homa {
namespace Core {
namespace {

using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;

class TransportImplTest : public ::testing::Test {
  public:
    TransportImplTest()
        : mockDriver()
        , transport(new TransportImpl(&mockDriver, 22))
        , savedLogPolicy(Debug::getLogPolicy())
    {
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~TransportImplTest()
    {
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    TransportImpl* transport;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(TransportImplTest, newMessage)
{
    EXPECT_EQ(0U, transport->messagePool.pool.outstandingObjects);

    Message message = transport->newMessage();

    EXPECT_EQ(1U, transport->messagePool.pool.outstandingObjects);
    EXPECT_EQ(transport, message.transportImpl);
}

TEST_F(TransportImplTest, receiveMessage)
{
    EXPECT_EQ(24U, sizeof(Protocol::DataHeader));
    Protocol::MessageId msgId = {42, 1};
    MessageContext* context =
        transport->receiver.contextPool->construct(msgId, 24, &mockDriver);
    transport->receiver.messageMap.insert(
        {msgId, transport->receiver.inboundPool.construct(context)});
    transport->receiver.messageQueue.push_back(context);

    EXPECT_EQ(1U, context->refCount);

    Message message = transport->receiveMessage();

    EXPECT_EQ(0U, transport->receiver.messageQueue.size());
    EXPECT_EQ(context, message.context);
    EXPECT_EQ(transport, message.transportImpl);
}

TEST_F(TransportImplTest, sendMessage)
{
    char payload[1024];
    MockDriver::MockPacket mockPacket(payload, 0);
    Message message = transport->newMessage();
    message.context->setPacket(0, &mockPacket);
    message.context->messageLength = 420;
    mockPacket.len =
        message.context->messageLength + message.context->DATA_HEADER_LENGTH;
    message.context->address = (Driver::Address*)22;

    EXPECT_EQ(0U, transport->sender.sendQueue.size());
    EXPECT_EQ(0U, transport->sender.outboundPool.outstandingObjects);

    transport->sendMessage(&message);

    EXPECT_EQ(22U, (uint64_t)mockPacket.address);
    EXPECT_EQ(0U, mockPacket.priority);
    Protocol::DataHeader* header =
        static_cast<Protocol::DataHeader*>(mockPacket.payload);
    EXPECT_EQ(message.context->msgId, header->common.msgId);
    EXPECT_EQ(message.context->messageLength, header->totalLength);
    EXPECT_EQ(1U, transport->sender.sendQueue.size());
    EXPECT_EQ(1U, transport->sender.outboundPool.outstandingObjects);
}

TEST_F(TransportImplTest, poll_handleDataPacket)
{
    char payload[1024];
    MockDriver::MockPacket mockPacket(payload, 0);
    Protocol::DataHeader* header =
        static_cast<Protocol::DataHeader*>(mockPacket.payload);
    header->common.opcode = Protocol::DATA;
    header->common.msgId = {42, 1};
    header->index = 1;
    header->totalLength = 1420;
    std::string addressStr("remote-location");
    MockDriver::MockAddress mockAddress;
    mockPacket.address = &mockAddress;
    mockPacket.len = sizeof(Protocol::DataHeader);

    EXPECT_CALL(mockDriver, receivePackets)
        .WillOnce(DoAll(SetArgPointee<1>(&mockPacket), Return(1)));

    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(0);
    EXPECT_CALL(mockAddress, toString)
        .Times(3)
        .WillRepeatedly(Return(addressStr))
        .RetiresOnSaturation();
    EXPECT_CALL(mockDriver, getAddress).WillOnce(Return(&mockAddress));
    char grantPayload[1024];
    MockDriver::MockPacket grantPacket(grantPayload, 0);
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&grantPacket));
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&grantPacket), Eq(1)))
        .Times(1);

    transport->poll();

    auto it = transport->receiver.messageMap.find(header->common.msgId);
    EXPECT_FALSE(it == transport->receiver.messageMap.end());

    Mock::VerifyAndClearExpectations(&mockDriver);
    Mock::VerifyAndClearExpectations(&mockAddress);
}

TEST_F(TransportImplTest, poll_handleGrantPacket)
{
    char payload[1024];
    MockDriver::MockPacket mockPacket(payload, 0);
    Protocol::MessageId msgId = {42, 1};
    Protocol::GrantHeader* header =
        static_cast<Protocol::GrantHeader*>(mockPacket.payload);
    header->common.opcode = Protocol::GRANT;
    header->common.msgId = msgId;
    header->offset = 6500;
    mockPacket.len = sizeof(Protocol::GrantHeader);

    EXPECT_CALL(mockDriver, receivePackets)
        .WillOnce(DoAll(SetArgPointee<1>(&mockPacket), Return(1)));
    EXPECT_CALL(mockDriver, releasePackets(Pointee(&mockPacket), Eq(1)))
        .Times(1);

    transport->poll();
}

}  // namespace
}  // namespace Core
}  // namespace Homa
