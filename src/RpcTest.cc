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

#include <Homa/Rpc.h>

#include "MockRpcManager.h"

#include <Homa/Debug.h>
#include <Homa/Driver.h>

namespace Homa {
namespace {

using ::testing::Assign;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::NiceMock;
using ::testing::Return;

class RpcTest : public ::testing::Test {
  public:
    RpcTest()
        : mockRpcManager()
        , address((Driver::Address*)42)
        , rpc(&mockRpcManager, address)
        , savedLogPolicy(Debug::getLogPolicy())
    {
        Debug::setLogPolicy(
            Debug::logPolicyFromString("src/ObjectPool@SILENT"));
    }

    ~RpcTest()
    {
        Debug::setLogPolicy(savedLogPolicy);
    }

    NiceMock<MockRpcManager> mockRpcManager;
    Driver::Address* address;
    Rpc rpc;
    std::vector<std::pair<std::string, std::string>> savedLogPolicy;
};

TEST_F(RpcTest, constructor)
{
    EXPECT_CALL(mockRpcManager, newRequest(Eq(address))).Times(1);
    Rpc rpc(&mockRpcManager, address);
}

TEST_F(RpcTest, send)
{
    EXPECT_CALL(mockRpcManager, sendRpc(Eq(&rpc))).Times(1);
    rpc.send();
}

TEST_F(RpcTest, isReady)
{
    EXPECT_NE(Rpc::FINISHED, rpc.state);
    EXPECT_FALSE(rpc.isReady());
    rpc.state = Rpc::FINISHED;
    EXPECT_TRUE(rpc.isReady());
}

TEST_F(RpcTest, wait)
{
    InSequence _seq;

    EXPECT_CALL(mockRpcManager, poll).Times(1);
    EXPECT_CALL(mockRpcManager, poll)
        .WillOnce(Assign(&rpc.state, Rpc::FINISHED));

    rpc.wait();
}

TEST_F(RpcTest, completed)
{
    EXPECT_NE(Rpc::FINISHED, rpc.state);
    rpc.completed();
    EXPECT_EQ(Rpc::FINISHED, rpc.state);
}

}  // namespace
}  // namespace Homa
