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

#include "RpcManagerImpl.h"

#include <Homa/Debug.h>
#include <Homa/Homa.h>
#include <Homa/Rpc.h>
#include <Homa/ServerRpc.h>
#include "MessageContext.h"
#include "MockDriver.h"
#include "Receiver.h"
#include "TransportImpl.h"

namespace Homa {
namespace {

using ::testing::Assign;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::NiceMock;
using ::testing::Return;

class RpcManagerImplTest : public ::testing::Test {
  public:
    RpcManagerImplTest()
        : mockDriver()
        , transport(new Transport(&mockDriver, 10))
        , rpcManager(new RpcManagerImpl(transport, 20))
        , buf()
        , packet0(buf + 0)
        , packet1(buf + 1024)
        , savedLogPolicy(Debug::getLogPolicy())
    {
        std::memset(buf, 0, sizeof(buf));
        ON_CALL(mockDriver, getBandwidth).WillByDefault(Return(8000));
        ON_CALL(mockDriver, getMaxPayloadSize).WillByDefault(Return(1024));
        ON_CALL(packet0, getMaxPayloadSize).WillByDefault(Return(1024));
        ON_CALL(packet1, getMaxPayloadSize).WillByDefault(Return(1024));
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~RpcManagerImplTest()
    {
        delete rpcManager;
        delete transport;
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockDriver> mockDriver;
    // MockDriver mockDriver;
    Transport* transport;
    RpcManagerImpl* rpcManager;
    char buf[2048];
    NiceMock<MockDriver::MockPacket> packet0;
    NiceMock<MockDriver::MockPacket> packet1;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(RpcManagerImplTest, receiveServerRpc)
{
    ServerRpc rpc;
    RpcProtocol::RpcHeader hdr0;
    RpcProtocol::RpcHeader hdr1;

    rpc = rpcManager->receiveServerRpc();

    EXPECT_FALSE(rpc);

    EXPECT_CALL(mockDriver, allocPacket)
        .WillOnce(Return(&packet0))
        .WillOnce(Return(&packet1));

    RpcProtocol::RpcHeader header;
    header.fromClient = true;
    header.rpcId = {11, 42};
    Message msg = transport->newMessage();
    msg.set(0, &header, sizeof(header));
    EXPECT_EQ(10U, msg.context->msgId.transportId);
    EXPECT_EQ(1U, msg.context->msgId.sequence);

    rpcManager->requestQueue.push_back(std::move(msg));

    rpc = rpcManager->receiveServerRpc();

    EXPECT_TRUE(rpc);

    rpc.request.get(0, &hdr0, sizeof(hdr0));
    rpc.response.get(0, &hdr1, sizeof(hdr1));

    EXPECT_TRUE(hdr0.fromClient);
    EXPECT_FALSE(hdr1.fromClient);
    EXPECT_EQ(header.rpcId, hdr0.rpcId);
    EXPECT_EQ(header.rpcId, hdr1.rpcId);

    rpc = rpcManager->receiveServerRpc();

    EXPECT_FALSE(rpc);
}

TEST_F(RpcManagerImplTest, poll)
{
    // Actual logic is tested as part of processMessage()
    rpcManager->poll();
}

TEST_F(RpcManagerImplTest, newRequest)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    Message request = rpcManager->newRequest((Driver::Address*)22);

    RpcProtocol::RpcHeader header;
    request.get(0, &header, sizeof(header));
    EXPECT_EQ(20U, header.rpcId.managerId);
    EXPECT_EQ(1U, header.rpcId.sequence);
    EXPECT_EQ(22U, (uint64_t)request.getAddress());

    EXPECT_EQ(2U, rpcManager->nextRpcId);
}

// Used to capture log output.
struct VectorHandler {
    VectorHandler()
        : messages()
    {}
    void operator()(Debug::DebugMessage message)
    {
        messages.push_back(message);
    }
    std::vector<Debug::DebugMessage> messages;
};

TEST_F(RpcManagerImplTest, sendRpc)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    Driver::Address* address = (Driver::Address*)22;
    Rpc rpc(rpcManager, address);
    RpcProtocol::RpcHeader header;
    rpc.request.get(0, &header, sizeof(header));
    EXPECT_EQ(20U, header.rpcId.managerId);
    EXPECT_EQ(1U, header.rpcId.sequence);
    EXPECT_TRUE(header.fromClient);

    EXPECT_TRUE(rpcManager->rpcMap.empty());

    rpcManager->sendRpc(&rpc);

    EXPECT_EQ(1U, rpcManager->rpcMap.size());
    auto it = rpcManager->rpcMap.find(header.rpcId);
    EXPECT_TRUE(it != rpcManager->rpcMap.end());

    EXPECT_EQ(0U, handler.messages.size());

    rpcManager->sendRpc(&rpc);

    EXPECT_EQ(1U, rpcManager->rpcMap.size());
    it = rpcManager->rpcMap.find(header.rpcId);
    EXPECT_TRUE(it != rpcManager->rpcMap.end());

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/RpcManagerImpl.cc", m.filename);
    EXPECT_STREQ("sendRpc", m.function);
    EXPECT_EQ(int(Debug::LogLevel::WARNING), m.logLevel);
    EXPECT_EQ("duplicate call to sendRpc for id (20:1); request dropped.",
              m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST_F(RpcManagerImplTest, sendServerRpcResponse)
{
    // TODO(cstlee): Add test: the code is pretty simple at the moment (3 lines)
    //               so it doesn't need a lot of testing.  It mostly just calls
    //               "send" on the RPCs response message.  There isn't a good
    //               way to check that send gets called because it's not mocked.
    ServerRpc rpc;

    EXPECT_CALL(mockDriver, allocPacket)
        .WillOnce(Return(&packet0))
        .WillOnce(Return(&packet1));

    RpcProtocol::RpcHeader header;
    header.fromClient = true;
    header.rpcId = {11, 42};
    Message msg = transport->newMessage();
    msg.set(0, &header, sizeof(header));
    msg.context->address = (Driver::Address*)22;
    rpcManager->requestQueue.push_back(std::move(msg));

    rpc = rpcManager->receiveServerRpc();

    rpcManager->sendServerRpcResponse(&rpc);
}

TEST_F(RpcManagerImplTest, processMessage_None)
{
    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());

    Message msg;

    EXPECT_FALSE(msg);

    rpcManager->processMessage(std::move(msg));

    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());
}

TEST_F(RpcManagerImplTest, processMessage_fromClient)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    RpcProtocol::RpcHeader header;
    header.fromClient = true;
    header.rpcId = {11, 42};
    Message msg = transport->newMessage();
    msg.set(0, &header, sizeof(header));

    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());

    rpcManager->processMessage(std::move(msg));

    EXPECT_EQ(1U, rpcManager->requestQueue.size());
    EXPECT_TRUE(rpcManager->rpcMap.empty());
}

TEST_F(RpcManagerImplTest, processMessage_fromServer)
{
    EXPECT_CALL(mockDriver, allocPacket)
        .WillOnce(Return(&packet0))
        .WillOnce(Return(&packet1));

    // Rpc that will be "sent"
    Driver::Address* address = (Driver::Address*)22;
    Rpc rpc(rpcManager, address);
    RpcProtocol::RpcHeader header;
    rpc.request.get(0, &header, sizeof(header));

    // Response to be recieved
    header.fromClient = false;
    Message msg = transport->newMessage();
    msg.set(0, &header, sizeof(header));

    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());

    // Have an RPC waiting
    rpcManager->sendRpc(&rpc);
    EXPECT_EQ(1U, rpcManager->rpcMap.size());
    EXPECT_TRUE(rpc.request);
    EXPECT_FALSE(rpc.response);
    EXPECT_FALSE(rpc.isReady());

    rpcManager->processMessage(std::move(msg));

    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());
    EXPECT_TRUE(rpc.request);
    EXPECT_TRUE(rpc.response);
    EXPECT_TRUE(rpc.isReady());
}

TEST_F(RpcManagerImplTest, processMessage_fromServer_drop)
{
    EXPECT_CALL(mockDriver, allocPacket).WillOnce(Return(&packet0));

    RpcProtocol::RpcHeader header;
    header.fromClient = false;
    header.rpcId = {20, 42};
    Message msg = transport->newMessage();
    msg.set(0, &header, sizeof(header));

    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());

    // Recieve respose without a pending rpc; drop
    rpcManager->processMessage(std::move(msg));

    EXPECT_TRUE(rpcManager->requestQueue.empty());
    EXPECT_TRUE(rpcManager->rpcMap.empty());
}

}  // namespace
}  // namespace Homa
