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

#include <Homa/ServerRpc.h>

#include "MockRpcManager.h"

#include <Homa/Debug.h>
#include <Homa/Homa.h>

namespace Homa {
namespace {

using ::testing::Eq;
using ::testing::NiceMock;

class ServerRpcTest : public ::testing::Test {
  public:
    ServerRpcTest()
        : mockRpcManager()
        , rpc()
        , request()
        , response()
        , savedLogPolicy(Debug::getLogPolicy())
    {
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
        request.transportImpl = (Core::TransportImpl*)(12);
        response.transportImpl = (Core::TransportImpl*)(22);
        rpc.request = std::move(request);
        rpc.response = std::move(response);
        rpc.manager = &mockRpcManager;
    }

    ~ServerRpcTest()
    {
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockRpcManager> mockRpcManager;
    ServerRpc rpc;
    Message request;
    Message response;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(ServerRpcTest, construct_move)
{
    EXPECT_TRUE((Core::TransportImpl*)(12) == rpc.request.transportImpl);
    EXPECT_TRUE((Core::TransportImpl*)(22) == rpc.response.transportImpl);
    EXPECT_TRUE(&mockRpcManager == rpc.manager);

    ServerRpc newRpc(std::move(rpc));

    EXPECT_FALSE((Core::TransportImpl*)(12) == rpc.request.transportImpl);
    EXPECT_FALSE((Core::TransportImpl*)(22) == rpc.response.transportImpl);
    EXPECT_FALSE(&mockRpcManager == rpc.manager);

    EXPECT_TRUE((Core::TransportImpl*)(12) == newRpc.request.transportImpl);
    EXPECT_TRUE((Core::TransportImpl*)(22) == newRpc.response.transportImpl);
    EXPECT_TRUE(&mockRpcManager == newRpc.manager);
}

TEST_F(ServerRpcTest, assignment_move)
{
    EXPECT_TRUE((Core::TransportImpl*)(12) == rpc.request.transportImpl);
    EXPECT_TRUE((Core::TransportImpl*)(22) == rpc.response.transportImpl);
    EXPECT_TRUE(&mockRpcManager == rpc.manager);

    ServerRpc newRpc = std::move(rpc);

    EXPECT_FALSE((Core::TransportImpl*)(12) == rpc.request.transportImpl);
    EXPECT_FALSE((Core::TransportImpl*)(22) == rpc.response.transportImpl);
    EXPECT_FALSE(&mockRpcManager == rpc.manager);

    EXPECT_TRUE((Core::TransportImpl*)(12) == newRpc.request.transportImpl);
    EXPECT_TRUE((Core::TransportImpl*)(22) == newRpc.response.transportImpl);
    EXPECT_TRUE(&mockRpcManager == newRpc.manager);
}

TEST_F(ServerRpcTest, operator_bool)
{
    rpc.request.context = (Core::MessageContext*)(42);

    EXPECT_TRUE(rpc);

    rpc.request.context = nullptr;

    EXPECT_FALSE(rpc);
}

TEST_F(ServerRpcTest, sendResponse)
{
    EXPECT_CALL(mockRpcManager, sendServerRpcResponse(Eq(&rpc))).Times(1);

    rpc.sendResponse();
}

}  // namespace
}  // namespace Homa
