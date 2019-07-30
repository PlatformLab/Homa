/**
 * Copyright (c) 2018, Stanford University
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

#include <Homa/Homa.h>

#include "Mock/MockDriver.h"
#include "Mock/MockReceiver.h"
#include "Mock/MockSender.h"
#include "Transport.h"

namespace Homa {
namespace {

using ::testing::NiceMock;
using ::testing::Return;

class HomaTest : public ::testing::Test {
  public:
    HomaTest()
        : mockDriver()
        , transport(new Transport(&mockDriver, 22))
        , mockSender(new NiceMock<Homa::Mock::MockSender>(
              transport->internal.get(), 22, 0, 0))
        , mockReceiver(new NiceMock<Homa::Mock::MockReceiver>(
              transport->internal.get(), 0, 0))
        , buf()
        , packet0(buf + 0)
        , packet1(buf + 2048)
        , savedLogPolicy(Debug::getLogPolicy())
    {
        transport->internal->sender.reset(mockSender);
        transport->internal->receiver.reset(mockReceiver);
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~HomaTest()
    {
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<Homa::Mock::MockDriver> mockDriver;
    Transport* transport;
    NiceMock<Homa::Mock::MockSender>* mockSender;
    NiceMock<Homa::Mock::MockReceiver>* mockReceiver;
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0;
    Homa::Mock::MockDriver::MockPacket packet1;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(HomaTest, RemoteOp_constructor)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    RemoteOp op(transport);

    EXPECT_EQ(op.op->getOutMessage(), op.request);
}

TEST_F(HomaTest, RemoteOp_destructor)
{
    // Nothing to test.
}

TEST_F(HomaTest, RemoteOp_setDestination)
{
    // Nothing to test.
}

TEST_F(HomaTest, RemoteOp_send)
{
    // Nothing to test.
}

TEST_F(HomaTest, RemoteOp_isReady_NOT_STARTED)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    RemoteOp op(transport);
    op.request = nullptr;
    op.response = nullptr;

    op.op->state = Core::OpContext::State::NOT_STARTED;
    EXPECT_FALSE(op.isReady());
    EXPECT_EQ(nullptr, op.request);
    EXPECT_EQ(nullptr, op.response);
}

TEST_F(HomaTest, RemoteOp_isReady_IN_PROGRESS)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    RemoteOp op(transport);
    op.request = nullptr;
    op.response = nullptr;

    op.op->state = Core::OpContext::State::IN_PROGRESS;
    EXPECT_FALSE(op.isReady());
    EXPECT_EQ(nullptr, op.request);
    EXPECT_EQ(nullptr, op.response);
}

TEST_F(HomaTest, RemoteOp_isReady_FAILED)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    RemoteOp op(transport);
    op.request = nullptr;
    op.response = nullptr;

    op.op->state = Core::OpContext::State::FAILED;
    EXPECT_TRUE(op.isReady());
    EXPECT_EQ(op.op->getOutMessage(), op.request);
    EXPECT_EQ(nullptr, op.response);
}

TEST_F(HomaTest, RemoteOp_isReady_COMPLETED)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));
    RemoteOp op(transport);
    op.request = nullptr;
    op.response = nullptr;
    Core::Receiver::Message inMessage(&mockDriver, 28, 0);
    inMessage.id = Protocol::MessageId(42, 32);
    static_cast<Core::Transport::Op*>(op.op)->inMessage = &inMessage;

    op.op->state = Core::OpContext::State::COMPLETED;
    EXPECT_TRUE(op.isReady());
    EXPECT_EQ(op.op->getOutMessage(), op.request);
    EXPECT_EQ(op.op->getInMessage(), op.response);
}

TEST_F(HomaTest, RemoteOp_wait)
{
    // Nothing to test.
}

TEST_F(HomaTest, ServerOp_constructor)
{
    ServerOp op;
    EXPECT_EQ(nullptr, op.request);
    EXPECT_EQ(nullptr, op.response);
    EXPECT_EQ(nullptr, op.op);
}

TEST_F(HomaTest, ServerOp_constructor_move)
{
    ServerOp srcOp;
    srcOp.request = (const Message*)41;
    srcOp.response = (Message*)42;
    srcOp.op = (Core::OpContext*)43;

    ServerOp destOp(std::move(srcOp));

    EXPECT_EQ(nullptr, srcOp.request);
    EXPECT_EQ(nullptr, srcOp.response);
    EXPECT_EQ(nullptr, srcOp.op);

    EXPECT_EQ((const Message*)41, destOp.request);
    EXPECT_EQ((Message*)42, destOp.response);
    EXPECT_EQ((Core::OpContext*)43, destOp.op);

    destOp.op = nullptr;
}

TEST_F(HomaTest, ServerOp_destructor)
{
    // Nothing to test.
}

TEST_F(HomaTest, ServerOp_assignment_move)
{
    ServerOp srcOp;
    srcOp.request = (const Message*)41;
    srcOp.response = (Message*)42;
    srcOp.op = (Core::OpContext*)43;

    ServerOp destOp;

    destOp = std::move(srcOp);

    EXPECT_EQ(nullptr, srcOp.request);
    EXPECT_EQ(nullptr, srcOp.response);
    EXPECT_EQ(nullptr, srcOp.op);

    EXPECT_EQ((const Message*)41, destOp.request);
    EXPECT_EQ((Message*)42, destOp.response);
    EXPECT_EQ((Core::OpContext*)43, destOp.op);

    destOp.op = nullptr;
}

TEST_F(HomaTest, Transport_receiveServerOp)
{
    char payload[1024];
    Homa::Mock::MockDriver::MockPacket packet(payload);
    Protocol::OpId opId(42, 1);
    Protocol::MessageId msgId(42, 1);
    Core::Transport::Op* op = transport->internal->opPool.construct(
        transport->internal.get(), transport->internal->driver, opId);
    Core::Receiver::Message inMessage(&mockDriver,
                                   sizeof(Protocol::Packet::DataHeader), 0);
    inMessage.id = msgId;
    op->inMessage = &inMessage;
    transport->internal->pendingServerOps.queue.push_back(op);

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet));

    ServerOp serverOp = transport->receiveServerOp();

    EXPECT_TRUE(serverOp);
    EXPECT_EQ(op, serverOp.op);
    EXPECT_EQ(serverOp.request, serverOp.op->getInMessage());
    EXPECT_EQ(serverOp.response, serverOp.op->getOutMessage());
}

TEST_F(HomaTest, Transport_receiveServerOp_empty)
{
    ServerOp serverOp = transport->receiveServerOp();
    EXPECT_FALSE(serverOp);
    EXPECT_EQ(nullptr, serverOp.op);
}

}  // namespace
}  // namespace Homa
