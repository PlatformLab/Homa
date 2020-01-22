/* Copyright (c) 2019-2020, Stanford University
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

#include "Intrusive.h"

namespace Homa {
namespace Core {
namespace {

struct Foo {
    Foo()
        : data()
        , listNode(this)
    {}

    char data[100];
    Intrusive::List<Foo>::Node listNode;
};

class IntrusiveListTest : public ::testing::Test {
  public:
    IntrusiveListTest()
        : foo()
        , list()
    {}

    void populateList()
    {
        for (int i = 0; i < 3; ++i) {
            list.push_back(&foo[i].listNode);
        }
    }

    Foo foo[3];
    Intrusive::List<Foo> list;
};

TEST_F(IntrusiveListTest, Node_constructor)
{
    Foo foo;
    EXPECT_EQ(&foo, foo.listNode.owner);
    EXPECT_EQ(&foo.listNode, foo.listNode.next);
    EXPECT_EQ(&foo.listNode, foo.listNode.prev);
    EXPECT_EQ(nullptr, foo.listNode.list);
}

TEST_F(IntrusiveListTest, Node_unlink)
{
    Foo foo;
    list.push_back(&foo.listNode);

    foo.listNode.unlink();

    EXPECT_EQ(&list.root, list.root.next);
    EXPECT_EQ(&list.root, list.root.prev);
    EXPECT_EQ(&foo.listNode, foo.listNode.next);
    EXPECT_EQ(&foo.listNode, foo.listNode.prev);
    EXPECT_EQ(nullptr, foo.listNode.list);
}

TEST_F(IntrusiveListTest, Iterator_constructor)
{
    Intrusive::List<Foo>::Iterator it;
    EXPECT_EQ(nullptr, it.node);
}

TEST_F(IntrusiveListTest, Iterator_dereference)
{
    Foo foo;
    Intrusive::List<Foo>::Iterator it(&foo.listNode);

    EXPECT_EQ(&foo, &(*it));
}

TEST_F(IntrusiveListTest, Iterator_structureDereference)
{
    Foo foo;
    Intrusive::List<Foo>::Iterator it(&foo.listNode);

    EXPECT_EQ(&foo.data, &(it->data));
}

TEST_F(IntrusiveListTest, Iterator_preincrement)
{
    populateList();
    Intrusive::List<Foo>::Iterator it(&foo[0].listNode);

    EXPECT_EQ(&foo[1].listNode, (++it).node);
    EXPECT_EQ(&foo[1].listNode, it.node);
}

TEST_F(IntrusiveListTest, Iterator_predecrement)
{
    populateList();
    Intrusive::List<Foo>::Iterator it(&foo[1].listNode);

    EXPECT_EQ(&foo[0].listNode, (--it).node);
    EXPECT_EQ(&foo[0].listNode, it.node);
}

TEST_F(IntrusiveListTest, Iterator_postincrement)
{
    populateList();
    Intrusive::List<Foo>::Iterator it(&foo[0].listNode);

    EXPECT_EQ(&foo[0].listNode, (it++).node);
    EXPECT_EQ(&foo[1].listNode, it.node);
}

TEST_F(IntrusiveListTest, Iterator_postdecrement)
{
    populateList();
    Intrusive::List<Foo>::Iterator it(&foo[1].listNode);

    EXPECT_EQ(&foo[1].listNode, (it--).node);
    EXPECT_EQ(&foo[0].listNode, it.node);
}

TEST_F(IntrusiveListTest, Iterator_equal)
{
    Intrusive::List<Foo>::Iterator it(&foo[0].listNode);
    Intrusive::List<Foo>::Iterator it0(&foo[0].listNode);
    Intrusive::List<Foo>::Iterator it1(&foo[1].listNode);

    EXPECT_TRUE(it == it0);
    EXPECT_FALSE(it == it1);
}

TEST_F(IntrusiveListTest, Iterator_notEqual)
{
    Intrusive::List<Foo>::Iterator it(&foo[0].listNode);
    Intrusive::List<Foo>::Iterator it0(&foo[0].listNode);
    Intrusive::List<Foo>::Iterator it1(&foo[1].listNode);

    EXPECT_FALSE(it != it0);
    EXPECT_TRUE(it != it1);
}

TEST_F(IntrusiveListTest, Iterator_constructorPrivate)
{
    Foo foo;
    Intrusive::List<Foo>::Iterator it(&foo.listNode);

    EXPECT_EQ(&foo.listNode, it.node);
}

TEST_F(IntrusiveListTest, constructor)
{
    // Nothing to test.
    Intrusive::List<Foo> list;
}

TEST_F(IntrusiveListTest, destructor)
{
    Intrusive::List<Foo>* list = new Intrusive::List<Foo>();
    Foo foo;
    list->push_back(&foo.listNode);

    delete list;

    EXPECT_EQ(&foo.listNode, foo.listNode.next);
    EXPECT_EQ(&foo.listNode, foo.listNode.prev);
}

TEST_F(IntrusiveListTest, front)
{
    populateList();
    EXPECT_EQ(&foo[0], &list.front());
}

TEST_F(IntrusiveListTest, back)
{
    populateList();
    EXPECT_EQ(&foo[2], &list.back());
}

TEST_F(IntrusiveListTest, begin)
{
    Intrusive::List<Foo>::Iterator it = list.begin();
    EXPECT_EQ(&list.root, it.node);

    populateList();

    it = list.begin();
    EXPECT_EQ(&foo[0].listNode, it.node);
}

TEST_F(IntrusiveListTest, end)
{
    populateList();
    Intrusive::List<Foo>::Iterator it = list.end();
    EXPECT_EQ(&list.root, it.node);
    EXPECT_EQ(&foo[2].listNode, (--it).node);
}

TEST_F(IntrusiveListTest, get)
{
    Intrusive::List<Foo>::Iterator it = list.get(&foo[0].listNode);
    EXPECT_EQ(list.end(), it);

    list.push_back(&foo[0].listNode);

    it = list.get(&foo[0].listNode);

    EXPECT_EQ(&foo[0].listNode, it.node);
}

TEST_F(IntrusiveListTest, empty)
{
    populateList();
    EXPECT_FALSE(list.empty());
    list.pop_front();
    EXPECT_FALSE(list.empty());
    list.pop_front();
    EXPECT_FALSE(list.empty());
    list.pop_front();
    EXPECT_TRUE(list.empty());
}

TEST_F(IntrusiveListTest, clear)
{
    populateList();

    list.clear();

    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(&foo[i].listNode, foo[i].listNode.next);
        EXPECT_EQ(&foo[i].listNode, foo[i].listNode.prev);
    }
    EXPECT_EQ(&list.root, list.root.next);
    EXPECT_EQ(&list.root, list.root.prev);
    EXPECT_EQ(0U, list.size());
}

TEST_F(IntrusiveListTest, insert)
{
    Intrusive::List<Foo>::Iterator it = list.begin();

    EXPECT_EQ(&list.root, list.root.next);
    EXPECT_EQ(&list.root, list.root.prev);

    it = list.insert(it, &foo[1].listNode);

    EXPECT_EQ(&foo[1].listNode, it.node);
    EXPECT_EQ(&foo[1].listNode, list.root.next);
    EXPECT_EQ(&list.root, foo[1].listNode.next);
    EXPECT_EQ(&foo[1].listNode, list.root.prev);
    EXPECT_EQ(&list.root, foo[1].listNode.prev);
    EXPECT_EQ(1U, list.size());

    it = list.insert(it, &foo[0].listNode);

    EXPECT_EQ(&foo[0].listNode, it.node);
    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.next);
    EXPECT_EQ(&list.root, foo[1].listNode.next);
    EXPECT_EQ(&foo[1].listNode, list.root.prev);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);
    EXPECT_EQ(2U, list.size());

    it = list.end();

    it = list.insert(it, &foo[2].listNode);

    EXPECT_EQ(&foo[2].listNode, it.node);
    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.next);
    EXPECT_EQ(&foo[2].listNode, foo[1].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[1].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);
    EXPECT_EQ(3U, list.size());
}

TEST_F(IntrusiveListTest, remove_iterator)
{
    populateList();

    Intrusive::List<Foo>::Iterator it = ++list.begin();
    EXPECT_EQ(&foo[1].listNode, it.node);
    EXPECT_EQ(3U, list.size());

    it = list.remove(it);

    EXPECT_EQ(&foo[2].listNode, it.node);

    EXPECT_EQ(&foo[1].listNode, foo[1].listNode.next);
    EXPECT_EQ(&foo[1].listNode, foo[1].listNode.prev);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[2].listNode, foo[0].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[0].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);

    EXPECT_EQ(2U, list.size());
}

TEST_F(IntrusiveListTest, remove_node)
{
    populateList();
    EXPECT_EQ(3U, list.size());

    list.remove(&foo[1].listNode);

    EXPECT_EQ(&foo[1].listNode, foo[1].listNode.next);
    EXPECT_EQ(&foo[1].listNode, foo[1].listNode.prev);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[2].listNode, foo[0].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[0].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);

    EXPECT_EQ(2U, list.size());
}

TEST_F(IntrusiveListTest, push_back)
{
    EXPECT_EQ(&list.root, list.root.next);
    EXPECT_EQ(&list.root, list.root.prev);

    list.push_back(&foo[0].listNode);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&list.root, foo[0].listNode.next);
    EXPECT_EQ(&foo[0].listNode, list.root.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);
    EXPECT_EQ(1U, list.size());

    list.push_back(&foo[1].listNode);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.next);
    EXPECT_EQ(&list.root, foo[1].listNode.next);
    EXPECT_EQ(&foo[1].listNode, list.root.prev);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);
    EXPECT_EQ(2U, list.size());

    list.push_back(&foo[2].listNode);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.next);
    EXPECT_EQ(&foo[2].listNode, foo[1].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[1].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);
    EXPECT_EQ(3U, list.size());
}

TEST_F(IntrusiveListTest, pop_back)
{
    populateList();
    EXPECT_EQ(3U, list.size());

    list.pop_back();

    EXPECT_EQ(&foo[2].listNode, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, foo[2].listNode.prev);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.next);
    EXPECT_EQ(&list.root, foo[1].listNode.next);
    EXPECT_EQ(&foo[1].listNode, list.root.prev);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);

    EXPECT_EQ(2U, list.size());
}

TEST_F(IntrusiveListTest, push_front)
{
    EXPECT_EQ(&list.root, list.root.next);
    EXPECT_EQ(&list.root, list.root.prev);

    list.push_front(&foo[2].listNode);

    EXPECT_EQ(&foo[2].listNode, list.root.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&list.root, foo[2].listNode.prev);
    EXPECT_EQ(1U, list.size());

    list.push_front(&foo[1].listNode);

    EXPECT_EQ(&foo[1].listNode, list.root.next);
    EXPECT_EQ(&foo[2].listNode, foo[1].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[1].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&list.root, foo[1].listNode.prev);
    EXPECT_EQ(2U, list.size());

    list.push_front(&foo[0].listNode);

    EXPECT_EQ(&foo[0].listNode, list.root.next);
    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.next);
    EXPECT_EQ(&foo[2].listNode, foo[1].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[1].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&list.root, foo[0].listNode.prev);
    EXPECT_EQ(3U, list.size());
}

TEST_F(IntrusiveListTest, pop_front)
{
    populateList();
    EXPECT_EQ(3U, list.size());

    list.pop_front();

    EXPECT_EQ(&foo[0].listNode, foo[0].listNode.next);
    EXPECT_EQ(&foo[0].listNode, foo[0].listNode.prev);

    EXPECT_EQ(&foo[1].listNode, list.root.next);
    EXPECT_EQ(&foo[2].listNode, foo[1].listNode.next);
    EXPECT_EQ(&list.root, foo[2].listNode.next);
    EXPECT_EQ(&foo[2].listNode, list.root.prev);
    EXPECT_EQ(&foo[1].listNode, foo[2].listNode.prev);
    EXPECT_EQ(&list.root, foo[1].listNode.prev);

    EXPECT_EQ(2U, list.size());
}

TEST_F(IntrusiveListTest, contains)
{
    populateList();
    Foo* foo = &list.front();

    EXPECT_TRUE(list.contains(&foo->listNode));

    list.pop_front();

    EXPECT_FALSE(list.contains(&foo->listNode));
}

TEST_F(IntrusiveListTest, __insert)
{
    Intrusive::List<Foo>::__insert(&foo[0].listNode, &foo[1].listNode);
    Intrusive::List<Foo>::__insert(&foo[1].listNode, &foo[2].listNode);

    EXPECT_EQ(&foo[1].listNode, foo[0].listNode.prev);
    EXPECT_EQ(&foo[2].listNode, foo[1].listNode.prev);
    EXPECT_EQ(&foo[0].listNode, foo[2].listNode.prev);

    EXPECT_EQ(&foo[1].listNode, foo[2].listNode.next);
    EXPECT_EQ(&foo[0].listNode, foo[1].listNode.next);
    EXPECT_EQ(&foo[2].listNode, foo[0].listNode.next);

    // Cleanup after the test.
    for (int i = 0; i < 3; ++i) {
        foo[i].listNode.unlink();
    }
}

TEST(IntrusiveTest, prioritize)
{
    struct Foo {
        Foo()
            : val(0)
            , node(this)
        {}
        struct Compare {
            bool operator()(const Foo& a, const Foo& b)
            {
                return a.val < b.val;
            }
        };
        int val;
        Intrusive::List<Foo>::Node node;
    };

    // [2][4][6][8]
    Foo foo[4];
    Intrusive::List<Foo> list;
    for (int i = 0; i < 4; ++i) {
        foo[i].val = i * 2 + 2;
        list.push_back(&foo[i].node);
    }

    auto it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [2][4][6][7]
    foo[3].val = 7;
    Intrusive::prioritize<Foo>(&list, &foo[3].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [2][2][4][6]
    foo[3].val = 2;
    Intrusive::prioritize<Foo>(&list, &foo[3].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[3], &(*++it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));

    // [0][2][4][6]
    foo[3].val = 0;
    Intrusive::prioritize<Foo>(&list, &foo[3].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[3], &(*it));
    EXPECT_EQ(&foo[0], &(*++it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
}

TEST(IntrusiveTest, deprioritize)
{
    struct Foo {
        Foo()
            : val(0)
            , node(this)
        {}
        struct Compare {
            bool operator()(const Foo& a, const Foo& b)
            {
                return a.val < b.val;
            }
        };
        int val;
        Intrusive::List<Foo>::Node node;
    };

    // [2][4][6][8]
    Foo foo[4];
    Intrusive::List<Foo> list;
    for (int i = 0; i < 4; ++i) {
        foo[i].val = i * 2 + 2;
        list.push_back(&foo[i].node);
    }

    auto it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [3][4][6][8]
    foo[0].val = 3;
    Intrusive::deprioritize<Foo>(&list, &foo[0].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[0], &(*it));
    EXPECT_EQ(&foo[1], &(*++it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [4][6][6][8]
    foo[0].val = 6;
    Intrusive::deprioritize<Foo>(&list, &foo[0].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[1], &(*it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[0], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));

    // [4][6][8][9]
    foo[0].val = 9;
    Intrusive::deprioritize<Foo>(&list, &foo[0].node, Foo::Compare());

    it = list.begin();
    EXPECT_EQ(&foo[1], &(*it));
    EXPECT_EQ(&foo[2], &(*++it));
    EXPECT_EQ(&foo[3], &(*++it));
    EXPECT_EQ(&foo[0], &(*++it));
}

}  // namespace
}  // namespace Core
}  // namespace Homa
