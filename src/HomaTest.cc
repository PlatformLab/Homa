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

namespace Homa {
namespace {

TEST(RemoteOpTest, constructor)
{
    RemoteOp op;
    EXPECT_EQ(nullptr, op.request);
    EXPECT_EQ(nullptr, op.response);
    EXPECT_EQ(nullptr, op.op);
}

TEST(RemoteOpTest, constructor_move)
{
    RemoteOp srcOp;
    srcOp.request = (Message*)41;
    srcOp.response = (const Message*)42;
    srcOp.op = (Core::OpContext*)43;

    RemoteOp destOp(std::move(srcOp));

    EXPECT_EQ(nullptr, srcOp.request);
    EXPECT_EQ(nullptr, srcOp.response);
    EXPECT_EQ(nullptr, srcOp.op);

    EXPECT_EQ((Message*)41, destOp.request);
    EXPECT_EQ((const Message*)42, destOp.response);
    EXPECT_EQ((Core::OpContext*)43, destOp.op);
}

TEST(RemoteOpTest, assignment_move)
{
    RemoteOp srcOp;
    srcOp.request = (Message*)41;
    srcOp.response = (const Message*)42;
    srcOp.op = (Core::OpContext*)43;

    RemoteOp destOp;

    destOp = std::move(srcOp);

    EXPECT_EQ(nullptr, srcOp.request);
    EXPECT_EQ(nullptr, srcOp.response);
    EXPECT_EQ(nullptr, srcOp.op);

    EXPECT_EQ((Message*)41, destOp.request);
    EXPECT_EQ((const Message*)42, destOp.response);
    EXPECT_EQ((Core::OpContext*)43, destOp.op);
}

TEST(ServerOpTest, constructor)
{
    ServerOp op;
    EXPECT_EQ(nullptr, op.request);
    EXPECT_EQ(nullptr, op.response);
    EXPECT_EQ(nullptr, op.op);
}

TEST(ServerOpTest, constructor_move)
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
}

TEST(ServerOpTest, assignment_move)
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
}

}  // namespace
}  // namespace Homa
