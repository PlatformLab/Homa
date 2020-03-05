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

/*
#include <gtest/gtest.h>

#include "Mock/MockDriver.h"
#include "Mock/MockMessage.h"
#include "Mock/MockReceiver.h"
#include "Mock/MockSender.h"

namespace Homa {
namespace {

using ::testing::_;
using ::testing::A;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;

class HomaTest : public ::testing::Test {
  public:
    HomaTest()
        : mockDriver()
        , transport(new OpManager(&mockDriver, 22))
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
    OpManager* transport;
    NiceMock<Homa::Mock::MockSender>* mockSender;
    NiceMock<Homa::Mock::MockReceiver>* mockReceiver;
    char buf[4096];
    Homa::Mock::MockDriver::MockPacket packet0;
    Homa::Mock::MockDriver::MockPacket packet1;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(HomaTest, RemoteOp_constructor)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    EXPECT_CALL(*mockSender, allocMessage).WillOnce(Return(&mockOutMessage));
    EXPECT_CALL(mockOutMessage, reserve(Eq(sizeof(Protocol::Message::Header))));
    RemoteOp op(transport);

    EXPECT_EQ(&mockOutMessage, op.request);
    EXPECT_EQ(nullptr, op.response);
    EXPECT_EQ(transport, op.transport);
    EXPECT_EQ(RemoteOp::State::NOT_STARTED, op.state.load());
}

TEST_F(HomaTest, RemoteOp_destructor)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    ON_CALL(*mockSender, allocMessage).WillByDefault(Return(&mockOutMessage));

    EXPECT_CALL(mockOutMessage, release);
    EXPECT_CALL(mockInMessage, release);
    {
        RemoteOp op(transport);
        op.opId = Protocol::OpId(42, 22);
        transport->members->remoteOps.insert({op.opId, &op});
        op.response = &mockInMessage;
    }
    EXPECT_TRUE(transport->members->remoteOps.empty());

    EXPECT_CALL(mockOutMessage, release);
    {
        RemoteOp op(transport);
    }
}

TEST_F(HomaTest, RemoteOp_send)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    ON_CALL(*mockSender, allocMessage).WillByDefault(Return(&mockOutMessage));
    RemoteOp op(transport);

    Protocol::OpId opId(transport->members->transportId,
                        transport->members->nextOpSequenceNumber);
    Homa::Driver::Address localAddress = 22;
    Homa::Driver::Address destination = 42;

    EXPECT_FALSE(transport->members->remoteOps.end() !=
                 transport->members->remoteOps.find(opId));

    EXPECT_CALL(mockDriver, getLocalAddress).WillOnce(Return(localAddress));
    EXPECT_CALL(mockDriver, addressToWireFormat(Eq(localAddress), _));
    EXPECT_CALL(mockOutMessage, prepend(_, sizeof(Protocol::Message::Header)));
    EXPECT_CALL(mockOutMessage, send(Eq(destination)));

    op.send(destination);

    EXPECT_TRUE(transport->members->remoteOps.end() !=
                transport->members->remoteOps.find(opId));
    EXPECT_EQ(&op, transport->members->remoteOps.find(opId)->second);
}

TEST_F(HomaTest, RemoteOp_isReady_NOT_STARTED)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    ON_CALL(*mockSender, allocMessage).WillByDefault(Return(&mockOutMessage));
    RemoteOp op(transport);
    op.state.store(RemoteOp::State::NOT_STARTED);

    EXPECT_FALSE(op.isReady());
}

TEST_F(HomaTest, RemoteOp_isReady_IN_PROGRESS)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    ON_CALL(*mockSender, allocMessage).WillByDefault(Return(&mockOutMessage));
    RemoteOp op(transport);
    op.state.store(RemoteOp::State::IN_PROGRESS);

    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::SENT));
    EXPECT_FALSE(op.isReady());
    EXPECT_EQ(RemoteOp::State::IN_PROGRESS, op.state.load());

    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::FAILED));
    EXPECT_TRUE(op.isReady());
    EXPECT_EQ(RemoteOp::State::FAILED, op.state.load());
}

TEST_F(HomaTest, RemoteOp_isReady_COMPLETED)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    ON_CALL(*mockSender, allocMessage).WillByDefault(Return(&mockOutMessage));
    RemoteOp op(transport);
    op.state.store(RemoteOp::State::COMPLETED);

    EXPECT_TRUE(op.isReady());
}

TEST_F(HomaTest, RemoteOp_isReady_FAILED)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    ON_CALL(*mockSender, allocMessage).WillByDefault(Return(&mockOutMessage));
    RemoteOp op(transport);
    op.state.store(RemoteOp::State::FAILED);

    EXPECT_TRUE(op.isReady());
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
    EXPECT_EQ(nullptr, op.transport);
    EXPECT_EQ(ServerOp::State::NOT_STARTED, op.state.load());
    EXPECT_EQ(false, op.detached.load());
    EXPECT_EQ(false, op.delegated);
}

TEST_F(HomaTest, ServerOp_constructor_move)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    Protocol::OpId opId(42, 21);

    ServerOp srcOp;
    srcOp.request = &mockInMessage;
    srcOp.response = &mockOutMessage;
    srcOp.transport = transport;
    srcOp.state = ServerOp::State::IN_PROGRESS;
    srcOp.detached = true;
    srcOp.opId = opId;
    srcOp.stageId = 33;
    srcOp.replyAddress = 99;
    srcOp.delegated = true;

    ServerOp destOp(std::move(srcOp));

    EXPECT_EQ(nullptr, srcOp.request);
    EXPECT_EQ(nullptr, srcOp.response);
    EXPECT_EQ(nullptr, srcOp.transport);
    EXPECT_EQ(ServerOp::State::NOT_STARTED, srcOp.state.load());
    EXPECT_EQ(false, srcOp.detached.load());
    EXPECT_EQ(Protocol::OpId(), srcOp.opId);
    EXPECT_EQ(0U, srcOp.stageId);
    EXPECT_EQ(0U, srcOp.replyAddress);
    EXPECT_EQ(false, srcOp.delegated);

    EXPECT_EQ(&mockInMessage, destOp.request);
    EXPECT_EQ(&mockOutMessage, destOp.response);
    EXPECT_EQ(transport, destOp.transport);
    EXPECT_EQ(ServerOp::State::IN_PROGRESS, destOp.state.load());
    EXPECT_EQ(true, destOp.detached.load());
    EXPECT_EQ(opId, destOp.opId);
    EXPECT_EQ(33U, destOp.stageId);
    EXPECT_EQ(99U, destOp.replyAddress);
    EXPECT_EQ(true, destOp.delegated);
}

TEST_F(HomaTest, ServerOp_destructor_detach)
{
    EXPECT_TRUE(transport->members->detachedServerOps.empty());
    {
        ServerOp op;
        op.transport = transport;
        op.detached = false;
        op.state = ServerOp::State::IN_PROGRESS;
    }
    EXPECT_FALSE(transport->members->detachedServerOps.empty());
}

TEST_F(HomaTest, ServerOp_destructor_release)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;

    EXPECT_CALL(mockInMessage, release);
    EXPECT_CALL(mockOutMessage, release);
    {
        ServerOp op;
        op.request = &mockInMessage;
        op.response = &mockOutMessage;
        op.transport = transport;
        op.detached = false;
        op.state = ServerOp::State::NOT_STARTED;
    }

    EXPECT_CALL(mockInMessage, release).Times(0);
    EXPECT_CALL(mockOutMessage, release);
    {
        ServerOp op;
        op.request = nullptr;
        op.response = &mockOutMessage;
        op.transport = transport;
        op.detached = true;
        op.state = ServerOp::State::IN_PROGRESS;
    }

    EXPECT_CALL(mockInMessage, release);
    EXPECT_CALL(mockOutMessage, release).Times(0);
    {
        ServerOp op;
        op.request = &mockInMessage;
        op.response = nullptr;
        op.transport = nullptr;
        op.detached = false;
        op.state = ServerOp::State::IN_PROGRESS;
    }
}

TEST_F(HomaTest, ServerOp_assignment_move)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    Protocol::OpId opId(42, 21);

    ServerOp srcOp;
    srcOp.request = &mockInMessage;
    srcOp.response = &mockOutMessage;
    srcOp.transport = transport;
    srcOp.state = ServerOp::State::IN_PROGRESS;
    srcOp.detached = true;
    srcOp.opId = opId;
    srcOp.stageId = 33;
    srcOp.replyAddress = 99;
    srcOp.delegated = true;

    ServerOp destOp;
    destOp = std::move(srcOp);

    EXPECT_EQ(nullptr, srcOp.request);
    EXPECT_EQ(nullptr, srcOp.response);
    EXPECT_EQ(nullptr, srcOp.transport);
    EXPECT_EQ(ServerOp::State::NOT_STARTED, srcOp.state.load());
    EXPECT_EQ(false, srcOp.detached.load());
    EXPECT_EQ(Protocol::OpId(), srcOp.opId);
    EXPECT_EQ(0U, srcOp.stageId);
    EXPECT_EQ(0U, srcOp.replyAddress);
    EXPECT_EQ(false, srcOp.delegated);

    EXPECT_EQ(&mockInMessage, destOp.request);
    EXPECT_EQ(&mockOutMessage, destOp.response);
    EXPECT_EQ(transport, destOp.transport);
    EXPECT_EQ(ServerOp::State::IN_PROGRESS, destOp.state.load());
    EXPECT_EQ(true, destOp.detached.load());
    EXPECT_EQ(opId, destOp.opId);
    EXPECT_EQ(33U, destOp.stageId);
    EXPECT_EQ(99U, destOp.replyAddress);
    EXPECT_EQ(true, destOp.delegated);
}

TEST_F(HomaTest, ServerOp_operator_bool)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    ServerOp op;
    op.request = &mockInMessage;

    EXPECT_TRUE(op);

    op.request = nullptr;

    EXPECT_FALSE(op);
}

TEST_F(HomaTest, ServerOp_makeProgress_NOT_STARTED)
{
    ServerOp op;
    op.state.store(ServerOp::State::NOT_STARTED);

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::NOT_STARTED, retState);
    EXPECT_EQ(ServerOp::State::NOT_STARTED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_DROPPED)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(true));

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::DROPPED, retState);
    EXPECT_EQ(ServerOp::State::DROPPED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_notDone)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(false));

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::IN_PROGRESS, retState);
    EXPECT_EQ(ServerOp::State::IN_PROGRESS, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_notDone_reply)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;
    op.response = &mockOutMessage;
    op.delegated = false;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(false));
    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::IN_PROGRESS));

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::IN_PROGRESS, retState);
    EXPECT_EQ(ServerOp::State::IN_PROGRESS, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_done_acked)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;
    op.response = &mockOutMessage;
    op.stageId = Protocol::Message::INITIAL_REQUEST_ID;
    op.delegated = true;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(false));
    EXPECT_CALL(mockInMessage, acknowledge).Times(0);
    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::COMPLETED));

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::COMPLETED, retState);
    EXPECT_EQ(ServerOp::State::COMPLETED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_done_reply_sent)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;
    op.response = &mockOutMessage;
    op.stageId = Protocol::Message::INITIAL_REQUEST_ID;
    op.delegated = false;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(false));
    EXPECT_CALL(mockInMessage, acknowledge).Times(0);
    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::SENT));

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::COMPLETED, retState);
    EXPECT_EQ(ServerOp::State::COMPLETED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_done_acknowledgeRequest)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;
    op.response = &mockOutMessage;
    op.stageId = Protocol::Message::INITIAL_REQUEST_ID + 1;
    op.delegated = false;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(false));
    EXPECT_CALL(mockInMessage, acknowledge).Times(1);
    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::SENT));

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::COMPLETED, retState);
    EXPECT_EQ(ServerOp::State::COMPLETED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_IN_PROGRESS_FAILED)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;

    ServerOp op;
    op.state.store(ServerOp::State::IN_PROGRESS);
    op.request = &mockInMessage;
    op.response = &mockOutMessage;

    EXPECT_CALL(mockInMessage, dropped).WillOnce(Return(false));
    EXPECT_CALL(mockOutMessage, getStatus)
        .WillOnce(Return(OutMessage::Status::FAILED));
    EXPECT_CALL(mockOutMessage, cancel).Times(1);

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::FAILED, retState);
    EXPECT_EQ(ServerOp::State::FAILED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_COMPLETED)
{
    ServerOp op;
    op.state.store(ServerOp::State::COMPLETED);

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::COMPLETED, retState);
    EXPECT_EQ(ServerOp::State::COMPLETED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_DROPPED)
{
    ServerOp op;
    op.state.store(ServerOp::State::DROPPED);

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::DROPPED, retState);
    EXPECT_EQ(ServerOp::State::DROPPED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_FAILED)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;

    ServerOp op;
    op.request = &mockInMessage;
    op.state.store(ServerOp::State::FAILED);
    op.detached = false;

    EXPECT_CALL(mockInMessage, fail).Times(0);

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::FAILED, retState);
    EXPECT_EQ(ServerOp::State::FAILED, op.state.load());
}

TEST_F(HomaTest, ServerOp_makeProgress_FAILED_detached)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;

    ServerOp op;
    op.request = &mockInMessage;
    op.state.store(ServerOp::State::FAILED);
    op.detached = true;

    EXPECT_CALL(mockInMessage, fail).Times(1);

    ServerOp::State retState = op.makeProgress();

    EXPECT_EQ(ServerOp::State::FAILED, retState);
    EXPECT_EQ(ServerOp::State::FAILED, op.state.load());
}

TEST_F(HomaTest, ServerOp_reply)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    Homa::Driver::Address replyAddress = 22;

    ServerOp op;
    op.request = &mockInMessage;
    op.response = &mockOutMessage;
    op.transport = transport;
    op.replyAddress = replyAddress;

    EXPECT_CALL(mockDriver, addressToWireFormat(Eq(replyAddress), _)).Times(1);
    EXPECT_CALL(mockOutMessage,
                prepend(_, Eq(sizeof(Protocol::Message::Header))));
    EXPECT_CALL(mockOutMessage, send(Eq(replyAddress)));

    op.reply();
}

TEST_F(HomaTest, ServerOp_delegate)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    Homa::Driver::Address replyAddress = 22;
    Homa::Driver::Address destination = 33;

    ServerOp op;
    op.request = &mockInMessage;
    op.response = &mockOutMessage;
    op.transport = transport;
    op.replyAddress = replyAddress;

    EXPECT_CALL(mockDriver, addressToWireFormat(Eq(replyAddress), _)).Times(1);
    EXPECT_CALL(mockOutMessage,
                prepend(_, Eq(sizeof(Protocol::Message::Header))));
    EXPECT_CALL(mockOutMessage, send(Eq(destination)));

    op.delegate(destination);

    EXPECT_TRUE(op.delegated);
}

TEST_F(HomaTest, Transport_receiveServerOp)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    Protocol::OpId opId(42, 22);

    {
        ServerOp op;
        op.request = &mockInMessage;
        op.opId = opId;
        op.stageId = 33;
        op.replyAddress = 99;
        transport->members->pendingServerOps.emplace_back(std::move(op));
    }

    ServerOp op;

    EXPECT_FALSE(op);

    EXPECT_CALL(*mockSender, allocMessage).WillOnce(Return(&mockOutMessage));
    EXPECT_CALL(mockOutMessage, reserve(Eq(sizeof(Protocol::Message::Header))));

    op = transport->receiveServerOp();

    EXPECT_TRUE(op);
    EXPECT_EQ(&mockInMessage, op.request);
    EXPECT_EQ(&mockOutMessage, op.response);
    EXPECT_EQ(transport, op.transport);
    EXPECT_EQ(ServerOp::State::IN_PROGRESS, op.state.load());
    EXPECT_EQ(false, op.detached);
    EXPECT_EQ(opId, op.opId);
    EXPECT_EQ(33U, op.stageId);
    EXPECT_EQ(99U, op.replyAddress);
    EXPECT_EQ(false, op.delegated);

    op.transport = nullptr;
}

TEST_F(HomaTest, Transport_receiveServerOp_empty)
{
    ServerOp op = transport->receiveServerOp();
    EXPECT_FALSE(op);
}

ACTION_TEMPLATE(SetArgBuffer, HAS_1_TEMPLATE_PARAMS(int, k),
                AND_2_VALUE_PARAMS(source, num))
{
    void* destination = ::std::get<k>(args);
    ::std::memcpy(destination, source, num);
}

TEST_F(HomaTest, Transport_poll_processIncomingMessage_response)
{
    NiceMock<Homa::Mock::MockOutMessage> mockOutMessage;
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    Protocol::OpId opId(42, 32);
    uint32_t tag = Protocol::Message::ULTIMATE_RESPONSE_ID;
    Protocol::Message::Header header(opId, tag);

    EXPECT_CALL(*mockSender, allocMessage).WillOnce(Return(&mockOutMessage));
    RemoteOp op(transport);
    op.state.store(RemoteOp::State::IN_PROGRESS);
    op.opId = opId;
    transport->members->remoteOps.insert({op.opId, &op});

    EXPECT_CALL(*mockReceiver, receiveMessage)
        .WillOnce(Return(&mockInMessage))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(mockInMessage, get)
        .WillOnce(SetArgBuffer<1>(&header, sizeof(header)));
    EXPECT_CALL(mockInMessage, strip(Eq(sizeof(Protocol::Message::Header))));
    EXPECT_CALL(mockInMessage, release).Times(0);

    transport->poll();

    EXPECT_EQ(&mockInMessage, op.response);
    EXPECT_EQ(RemoteOp::State::COMPLETED, op.state.load());
    Mock::VerifyAndClearExpectations(&mockInMessage);
}

TEST_F(HomaTest, Transport_poll_processIncomingMessage_response_drop)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    Protocol::OpId opId(42, 32);
    uint32_t tag = Protocol::Message::ULTIMATE_RESPONSE_ID;
    Protocol::Message::Header header(opId, tag);

    EXPECT_CALL(*mockReceiver, receiveMessage)
        .WillOnce(Return(&mockInMessage))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(mockInMessage, get)
        .WillOnce(SetArgBuffer<1>(&header, sizeof(header)));
    EXPECT_CALL(mockInMessage, strip(Eq(sizeof(Protocol::Message::Header))));
    EXPECT_CALL(mockInMessage, release).Times(1);

    transport->poll();

    Mock::VerifyAndClearExpectations(&mockInMessage);
}

TEST_F(HomaTest, Transport_poll_processIncomingMessage_request)
{
    NiceMock<Homa::Mock::MockInMessage> mockInMessage;
    Protocol::OpId opId(42, 32);
    uint32_t tag = Protocol::Message::INITIAL_REQUEST_ID;
    Protocol::Message::Header header(opId, tag);
    Driver::Address address = 99;

    EXPECT_CALL(*mockReceiver, receiveMessage)
        .WillOnce(Return(&mockInMessage))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(mockInMessage, get)
        .WillOnce(SetArgBuffer<1>(&header, sizeof(header)));
    EXPECT_CALL(mockInMessage, strip(Eq(sizeof(Protocol::Message::Header))));
    EXPECT_CALL(mockDriver, getAddress(A<Driver::WireFormatAddress const*>()))
        .WillOnce(Return(address));

    transport->poll();

    EXPECT_FALSE(transport->members->pendingServerOps.empty());
    ServerOp* op = &transport->members->pendingServerOps.back();
    EXPECT_EQ(&mockInMessage, op->request);
    EXPECT_EQ(opId, op->opId);
    EXPECT_EQ(tag, op->stageId);
    EXPECT_EQ(address, op->replyAddress);

    // cleanup
    transport->members->pendingServerOps.clear();
}

TEST_F(HomaTest, Transport_poll_checkDetachedServerOps)
{
    ON_CALL(*mockReceiver, receiveMessage).WillByDefault(Return(nullptr));

    NiceMock<Homa::Mock::MockInMessage> mockInMessage1;
    NiceMock<Homa::Mock::MockInMessage> mockInMessage2;

    transport->members->detachedServerOps.emplace_back();
    transport->members->detachedServerOps.emplace_back();

    ServerOp* op1 = &transport->members->detachedServerOps.front();
    ServerOp* op2 = &transport->members->detachedServerOps.back();

    op1->opId.sequence = 1;
    op1->request = &mockInMessage1;
    op1->detached = true;
    op1->state.store(ServerOp::State::IN_PROGRESS);
    op2->opId.sequence = 2;
    op2->request = &mockInMessage2;
    op2->detached = true;
    op2->state.store(ServerOp::State::IN_PROGRESS);

    EXPECT_EQ(2U, transport->members->detachedServerOps.size());

    EXPECT_CALL(mockInMessage1, dropped).WillOnce(Return(false));
    EXPECT_CALL(mockInMessage2, dropped).WillOnce(Return(false));

    transport->poll();

    EXPECT_EQ(2U, transport->members->detachedServerOps.size());

    EXPECT_CALL(mockInMessage1, dropped).WillOnce(Return(true));
    EXPECT_CALL(mockInMessage1, release).Times(1);
    EXPECT_CALL(mockInMessage2, dropped).WillOnce(Return(false));

    transport->poll();

    EXPECT_EQ(1U, transport->members->detachedServerOps.size());

    EXPECT_CALL(mockInMessage2, dropped).WillOnce(Return(true));
    EXPECT_CALL(mockInMessage2, release).Times(1);

    transport->poll();

    EXPECT_EQ(0U, transport->members->detachedServerOps.size());
}

}  // namespace
}  // namespace Homa
*/