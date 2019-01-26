/* Copyright (c) 2011-2018, Stanford University
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

/**
 * \file
 * Unit tests for ObjectPool.
 */

#include "ObjectPool.h"

#include "CodeLocation.h"
#include "Debug.h"

#include <Homa/Util.h>

#include <gtest/gtest.h>

#include <cstdlib>
#include <ctime>

namespace Homa {
namespace {

class TestObject {
  public:
    explicit TestObject(bool throwException = false)
        : destroyed(NULL)
    {
        if (throwException)
            throw Exception(HERE_STR, "Yes, me Lord.");
    }

    explicit TestObject(bool* destroyed)
        : destroyed(destroyed)
    {}

    ~TestObject()
    {
        if (destroyed)
            *destroyed = true;
    }

  private:
    bool* destroyed;
};
}  // anonymous namespace

TEST(ObjectPoolTest, constructor)
{
    ObjectPool<TestObject> pool;
    EXPECT_EQ(0U, pool.outstandingObjects);
}

TEST(ObjectPoolTest, destructor)
{
    {
        ObjectPool<TestObject> pool;
        TestObject* a = pool.construct();
        TestObject* b = pool.construct();
        pool.destroy(a);
        pool.destroy(b);
    }

    {
        ObjectPool<TestObject> pool;
        TestObject* a = pool.construct();
        TestObject* b = pool.construct();
        pool.destroy(b);
        pool.destroy(a);
    }
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

TEST(ObjectPoolTest, destructor_objectsStillAllocated)
{
    VectorHandler handler;
    Debug::setLogHandler(std::ref(handler));

    ObjectPool<TestObject>* pool = new ObjectPool<TestObject>();
    TestObject* a = pool->construct();
    (void)a;

    delete pool;

    EXPECT_EQ(1U, handler.messages.size());
    const Debug::DebugMessage& m = handler.messages.at(0);
    EXPECT_STREQ("src/ObjectPool.h", m.filename);
    EXPECT_STREQ("~ObjectPool", m.function);
    EXPECT_EQ(int(Debug::LogLevel::ERROR), m.logLevel);
    EXPECT_EQ("Pool destroyed with 1 objects still outstanding!", m.message);

    Debug::setLogHandler(std::function<void(Debug::DebugMessage)>());
}

TEST(ObjectPoolTest, construct)
{
    ObjectPool<TestObject> pool;
    EXPECT_THROW(pool.construct(true), Exception);
    EXPECT_EQ(1U, pool.pool.size());
    TestObject* a = pool.construct();
    EXPECT_NE(static_cast<TestObject*>(NULL), a);
    EXPECT_EQ(1U, pool.outstandingObjects);
    pool.destroy(a);
}

TEST(ObjectPoolTest, destroy)
{
    ObjectPool<TestObject> pool;
    bool destroyed = false;
    pool.destroy(pool.construct(&destroyed));
    EXPECT_TRUE(destroyed);
    EXPECT_EQ(0U, pool.outstandingObjects);
    EXPECT_EQ(1U, pool.pool.size());
}

TEST(ObjectPoolTest, destroy_inOrder)
{
    ObjectPool<TestObject> pool;
    int count = 100;
    TestObject* toDestroy[count];

    for (int i = 0; i < count; i++) toDestroy[i] = pool.construct();
    for (int i = 0; i < count; i++) pool.destroy(toDestroy[i]);
}

TEST(ObjectPoolTest, destroy_reverseOrder)
{
    ObjectPool<TestObject> pool;
    int count = 100;
    TestObject* toDestroy[count];

    for (int i = 0; i < count; i++) toDestroy[i] = pool.construct();
    for (int i = count - 1; i >= 0; i--) pool.destroy(toDestroy[i]);
}

TEST(ObjectPoolTest, destroy_randomOrder)
{
    ObjectPool<TestObject> pool;
    int count = 100;
    TestObject* toDestroy[count];
    std::srand(std::time(0));

    for (int i = 0; i < count; i++) toDestroy[i] = pool.construct();

    int destroyed = 0;
    while (destroyed < count) {
        int i = std::rand() % count;
        while (toDestroy[i] == NULL) i = (i + 1) % count;
        pool.destroy(toDestroy[i]);
        toDestroy[i] = NULL;
        destroyed++;
    }
}

}  // namespace Homa
