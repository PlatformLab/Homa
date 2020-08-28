/* Copyright (c) 2019, Stanford University
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

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <list>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "Cycles.h"
#include "Homa/Drivers/Util/QueueEstimator.h"
#include "Intrusive.h"
#include "ObjectPool.h"
#include "docopt.h"

static const char USAGE[] = R"(Performance Nano-Benchmark

Usage:
    Perf run [TEST ...]
    Perf list
    Perf info TEST ...

Arguments:
    TEST

Commands:
    run     Execute a set of benchmark tests
    list    Print the available benchmark tests
    info    Show the long description of a test

Options:
    -h --help       Show this screen
)";

// This struct contains information about a particular test that can be
// displayed to the user.
struct TestInfo {
    const char* name;         // Name of the performance test; this is what gets
                              // typed on the command line to run the test.
    const char* description;  // Short description of this test (not more than
                              // about 40 characters, so the entire test output
                              // fits on a single line).
    const char* docs;         // Longer more detailed documentation for this
                              // test (can contain multiple lines but each line
                              // should be less than 72 characters long).
};

TestInfo atomicLoadTestInfo = {
    "atomicLoad", "Read an std::atomic",
    R"(Measure the cost of reading an std::atomic value.)"};
double
atomicLoadTest()
{
    int count = 1000000;
    uint64_t temp;
    std::atomic<uint64_t> val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        temp = val[i].load();
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo atomicStoreTestInfo = {
    "atomicStore", "Write an std::atomic",
    R"(Measure the cost of writing an std::atomic value.)"};
double
atomicStoreTest()
{
    int count = 1000000;
    uint64_t temp = std::rand();
    std::atomic<uint64_t> val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        val[i].store(temp);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo atomicStoreRelaxedTestInfo = {
    "atomicStoreRelaxed", "Write an std::atomic (std::memory_order_relaxed)",
    R"(Measure the cost of a relaxed atomic write.)"};
double
atomicStoreRelaxedTest()
{
    int count = 1000000;
    uint64_t temp = std::rand();
    std::atomic<uint64_t> val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        val[i].store(temp, std::memory_order_relaxed);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo atomicIncTestInfo = {
    "atomicInc", "Increment an std::atomic",
    R"(Measure the cost of incrementing an std::atomic value.)"};
double
atomicIncTest()
{
    int count = 1000000;
    uint64_t temp = std::rand() % 100;
    std::atomic<uint64_t> val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        val[i].fetch_add(temp);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo atomicIncRelaxedTestInfo = {
    "atomicIncRelaxed", "Increment an std::atomic (std::memory_order_relaxed)",
    R"(Measure the cost of a relaxed atomic incrementing.)"};
double
atomicIncRelaxedTest()
{
    int count = 1000000;
    uint64_t temp = std::rand() % 100;
    std::atomic<uint64_t> val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        val[i].fetch_add(temp, std::memory_order_relaxed);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo atomicIncUnsafeTestInfo = {
    "atomicIncUnsafe", "Increment an std::atomic using read-modify-write",
    R"(Measure the cost of a thread unsafe increment of an std::atomic.)"};
double
atomicIncUnsafeTest()
{
    int count = 1000000;
    uint64_t temp = std::rand() % 100;
    std::atomic<uint64_t> val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        val[i].store(val[i].load(std::memory_order_relaxed) + temp,
                     std::memory_order_relaxed);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo intReadWriteTestInfo = {
    "intReadWrite", "Read and write a uint64_t",
    R"(Measure the cost the baseline read/write.)"};
double
intReadWriteTest()
{
    int count = 1000000;
    uint64_t temp = std::rand();
    uint64_t val[count];
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        val[i] = temp;
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo branchTestInfo = {
    "branch", "If-else statement",
    R"(The cost of choosing a branch in an if-else statement)"};
double
branchTest()
{
    int count = 1000000;
    uint64_t temp = std::rand();
    uint64_t a[0xFF + 1];
    uint64_t b[0xFF + 1];
    for (int i = 0; i < 0xFF + 1; i++) {
        a[i] = std::rand();
        b[i] = std::rand();
    }
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        int index = i & 0xFF;
        if (a[index] < b[index]) {
            b[index] = a[index];
        } else {
            a[index] = b[index];
        }
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo defaultAllocatorTestInfo = {
    "defaultAllocator", "Test new and delete of a simple structure",
    R"(Measure the cost of allocation and deallocation using new and delete.)"};
double
defaultAllocatorTest()
{
    struct Foo {
        Foo()
            : i()
            , buf()
        {}

        uint64_t i;
        char buf[100];
    };
    Foo* foo[0xFFFF + 1];
    for (int i = 0; i < 0xFFFF + 1; ++i) {
        foo[i] = new Foo;
    }
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        delete foo[i & 0xFFFF];
        foo[i & 0xFFFF] = new Foo;
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < 0xFFFF + 1; ++i) {
        delete foo[i];
    }
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo objectPoolTestInfo = {
    "objectPool", "Test ObjectPool allocation of a simple structure",
    R"(Measure the cost of allocation and deallocation using an ObjectPool.)"};
double
objectPoolTest()
{
    struct Foo {
        Foo()
            : i()
            , buf()
        {}
        uint64_t i;
        char buf[100];
    };
    Homa::ObjectPool<Foo> pool;
    Foo* foo[0xFFFF + 1];
    for (int i = 0; i < 0xFFFF + 1; ++i) {
        foo[i] = pool.construct();
    }
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        pool.destroy(foo[i & 0xFFFF]);
        foo[i & 0xFFFF] = pool.construct();
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < 0xFFFF + 1; ++i) {
        pool.destroy(foo[i]);
    }
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo listSearchTestInfo = {
    "listSearch", "Linear search an intrusive list",
    R"(Measure the cost (per entry) of searching through an intrusive list)"};
double
listSearchTest()
{
    struct Foo {
        Foo()
            : val(0)
            , node(this)
        {}

        uint64_t val;
        Homa::Core::Intrusive::List<Foo>::Node node;
    };
    std::array<Foo, 1000> foos;
    Homa::Core::Intrusive::List<Foo> list;
    for (int i = 0; i < 1000; ++i) {
        foos[i].val = std::rand() % 1000;
        list.push_back(&foos[i].node);
    }

    int count = 1000000;

    uint64_t sum = 0;

    int run = 0;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    while (run < count) {
        for (auto it = list.begin(); it != list.end(); ++it, ++run) {
            if (it->val > 500) {
                sum += it->val;
            } else {
                sum -= it->val;
            }
        }
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / run;
}

TestInfo mapFindTestInfo = {
    "mapFind", "std::unordered_map::find()",
    R"(Measure the cost of std::unordered_map<uint64_t, uint64_t>::find() for a
map containing 10k elements.)"};
double
mapFindTest()
{
    std::unordered_map<uint64_t, uint64_t> map;

    int count = 1000000;
    int numKeys = 10000;
    uint64_t keys[numKeys];
    for (int i = 0; i < numKeys; ++i) {
        keys[i] = std::rand();
        map.insert({keys[i], 1234});
    }
    uint64_t sum = 0;

    int run = 0;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    while (run < count) {
        for (int i = 0; i < numKeys; ++i, ++run) {
            auto it = map.find(keys[i]);
            if (it != map.end()) {
                sum += it->second;
            }
        }
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / run;
}

TestInfo mapLookupTestInfo = {
    "mapLookup", "std::unordered_map::at()",
    R"(Measure the lookup cost for a std::unordered_map<uint64_t, uint64_t>
containing 10k elements.)"};
double
mapLookupTest()
{
    std::unordered_map<uint64_t, uint64_t> map;

    int count = 1000000;
    int numKeys = 10000;
    uint64_t keys[numKeys];
    for (int i = 0; i < numKeys; ++i) {
        keys[i] = std::rand();
        map.insert({keys[i], 1234});
    }
    uint64_t sum = 0;

    int run = 0;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    while (run < count) {
        for (int i = 0; i < numKeys; ++i, ++run) {
            sum += map.at(keys[i]);
        }
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / run;
}

TestInfo mapNullInsertTestInfo = {
    "mapNullInsert", "std::unordered_map::insert() with existing key",
    R"(Measure the cost to insert an existing element with an existing key into
an std::unordered_map<uint64_t, uint64_t> containing 10k elements.)"};
double
mapNullInsertTest()
{
    std::unordered_map<uint64_t, uint64_t> map;

    int count = 1000000;
    int numKeys = 10000;
    uint64_t keys[numKeys];
    for (int i = 0; i < numKeys; ++i) {
        keys[i] = std::rand();
        map.insert({keys[i], 1234});
    }
    uint64_t sum = 0;

    int run = 0;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    while (run < count) {
        for (int i = 0; i < numKeys; ++i, ++run) {
            auto it = map.insert({keys[i], 0});
            sum += it.first->second;
        }
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / run;
}

TestInfo dequeConstructInfo = {
    "dequeConstruct", "Construct an std::deque",
    R"(Measure the cost of constructing (and destructing) an std::deque.)"};
double
dequeConstruct()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        std::deque<uint64_t> deque;
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo dequePushPopTestInfo = {
    "dequePushPop", "std::deque operations",
    R"(Measure the cost of pushing/popping an element to/from an std::deque.)"};
double
dequePushPopTest()
{
    std::deque<uint64_t> deque;
    for (int i = 0; i < 10000; ++i) {
        deque.push_back(std::rand());
    }

    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        uint64_t temp = deque.front();
        deque.pop_front();
        deque.push_back(temp);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (2 * count);
}

TestInfo vectorConstructInfo = {
    "vectorConstruct", "Construct an std::vector",
    R"(Measure the cost of constructing (and destructing) an std::vector.)"};
double
vectorConstruct()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        std::vector<uint64_t> vector;
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo vectorReserveTestInfo = {
    "vectorReserve", "Reserve capacity in an std::vector",
    R"(Measure the cost of reserving capacity an std::vector.)"};
double
vectorReserveTest()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        std::vector<uint64_t> vector;
        vector.reserve(32);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo vectorPushTestInfo = {
    "vectorPush", "std::vector push",
    R"(Measure the cost of pushing a new element to an std::vector.)"};
double
vectorPushTest()
{
    std::vector<uint64_t> vector;
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        vector.push_back(i);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo vectorPushPopTestInfo = {
    "vectorPushPop", "std::vector operations",
    R"(Measure the cost of pushing/popping an element to/from an std::vector.)"};
double
vectorPushPopTest()
{
    std::vector<uint64_t> vector;
    for (int i = 0; i < 10000; ++i) {
        vector.push_back(std::rand());
    }

    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        uint64_t temp = vector.back();
        vector.pop_back();
        vector.push_back(temp);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (2 * count);
}

TestInfo listConstructInfo = {
    "listConstruct", "Construct an std::list",
    R"(Measure the cost of constructing (and destructing) an std::list.)"};
double
listConstruct()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        std::list<uint64_t> list;
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo listPushTestInfo = {
    "listPush", "std::list push",
    R"(Measure the cost of pushing a new element to an std::list.)"};
double
listPushTest()
{
    std::list<uint64_t> list;
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        list.push_back(i);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo listPushPopTestInfo = {
    "listPushPop", "std::list operations",
    R"(Measure the cost of pushing/popping an element to/from an std::list.)"};
double
listPushPopTest()
{
    std::list<uint64_t> list;
    for (int i = 0; i < 10000; ++i) {
        list.push_back(std::rand());
    }

    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        uint64_t temp = list.front();
        list.pop_front();
        list.push_back(temp);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (2 * count);
}

TestInfo ilistConstructInfo = {
    "ilistConstruct", "Construct an Intrusive::list",
    R"(Measure the cost of constructing (and destructing) an Intrusive::list.)"};
double
ilistConstruct()
{
    struct Foo {
        Foo()
            : node(this)
        {}

        Homa::Core::Intrusive::List<Foo>::Node node;
    };

    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        Homa::Core::Intrusive::List<Foo> list;
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (count);
}

TestInfo ilistPushPopTestInfo = {
    "ilistPushPop", "Intrusive::list operations",
    R"(Measure the cost of pushing/popping an element to/from an Intrusive::list.)"};
double
ilistPushPopTest()
{
    struct Foo {
        Foo()
            : node(this)
        {}

        Homa::Core::Intrusive::List<Foo>::Node node;
    };

    Homa::Core::Intrusive::List<Foo> list;
    for (int i = 0; i < 10000; ++i) {
        Foo* foo = new Foo;
        list.push_back(&foo->node);
    }
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        Foo* foo = &list.front();
        list.pop_front();
        list.push_front(&foo->node);
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    while (!list.empty()) {
        Foo* foo = &list.front();
        list.pop_front();
        delete foo;
    }
    return PerfUtils::Cycles::toSeconds(stop - start) / (2 * count);
}

TestInfo heapTestInfo = {
    "heap", "std heap operations",
    R"(Measure the cost of pushing/popping an element to/from an std heap.)"};
double
heapTest()
{
    std::vector<uint64_t> heap;
    for (uint64_t i = 0; i < 10000; ++i) {
        heap.push_back(i);
    }
    std::make_heap(heap.begin(), heap.end(), std::greater<>{});

    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        uint64_t temp = heap.front();
        std::pop_heap(heap.begin(), heap.end(), std::greater<>{});
        heap.pop_back();
        heap.push_back(temp + 5000);
        std::push_heap(heap.begin(), heap.end(), std::greater<>{});
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (2 * count);
}

TestInfo queueEstimatorTestInfo = {
    "queueEstimator", "Update a QueueEstimator",
    R"(Measure the cost of updating a Homa::Drivers::Util::QueueEstimator.)"};
double
queueEstimatorTest()
{
    int count = 1000000;
    Homa::Drivers::Util::QueueEstimator<std::chrono::high_resolution_clock>
        queueEstimator(10000);
    uint32_t bytes = 0;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        queueEstimator.signalBytesSent(100);
        bytes += queueEstimator.getQueuedBytes();
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / (2 * count);
}

TestInfo rdtscTestInfo = {
    "rdtsc", "Read the fine-grain cycle counter",
    R"(Measure the cost of reading the fine-grain cycle counter.)"};
double
rdtscTest()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    uint64_t total = 0;
    for (int i = 0; i < count; i++) {
        total += PerfUtils::Cycles::rdtscp();
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo rdhrcTestInfo = {
    "rdhrc", "Read std::chrono::high_resolution_clock",
    R"(Measure the cost of reading the std::chrono::high_resolution_clock.)"};
double
rdhrcTest()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        auto timestamp = std::chrono::high_resolution_clock::now();
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

TestInfo rdcscTestInfo = {
    "rdcsc", "Read std::chrono::steady_clock",
    R"(Measure the cost of reading the std::chrono::steady_clock.)"};
double
rdcscTest()
{
    int count = 1000000;
    uint64_t start = PerfUtils::Cycles::rdtscp();
    for (int i = 0; i < count; i++) {
        auto timestamp = std::chrono::steady_clock::now();
    }
    uint64_t stop = PerfUtils::Cycles::rdtscp();
    return PerfUtils::Cycles::toSeconds(stop - start) / count;
}

// The following struct and table define each performance test in terms of
// function that implements the test and collection of string information about
// the test like the test's string name.
struct TestCase {
    double (*func)();      // Function that implements the test; returns the
                           // time (in seconds) for each iteration of that
                           // test.
    const TestInfo* info;  // Contains string information about the test
                           // including the test's string name.
};
TestCase tests[] = {
    {atomicLoadTest, &atomicLoadTestInfo},
    {atomicStoreTest, &atomicStoreTestInfo},
    {atomicStoreRelaxedTest, &atomicStoreRelaxedTestInfo},
    {atomicIncTest, &atomicIncTestInfo},
    {atomicIncRelaxedTest, &atomicIncRelaxedTestInfo},
    {atomicIncUnsafeTest, &atomicIncUnsafeTestInfo},
    {branchTest, &branchTestInfo},
    {intReadWriteTest, &intReadWriteTestInfo},
    {defaultAllocatorTest, &defaultAllocatorTestInfo},
    {objectPoolTest, &objectPoolTestInfo},
    {listSearchTest, &listSearchTestInfo},
    {mapFindTest, &mapFindTestInfo},
    {mapLookupTest, &mapLookupTestInfo},
    {mapNullInsertTest, &mapNullInsertTestInfo},
    {dequeConstruct, &dequeConstructInfo},
    {dequePushPopTest, &dequePushPopTestInfo},
    {vectorConstruct, &vectorConstructInfo},
    {vectorReserveTest, &vectorReserveTestInfo},
    {vectorPushTest, &vectorPushTestInfo},
    {vectorPushPopTest, &vectorPushPopTestInfo},
    {listConstruct, &listConstructInfo},
    {listPushTest, &listPushTestInfo},
    {listPushPopTest, &listPushPopTestInfo},
    {ilistConstruct, &ilistConstructInfo},
    {ilistPushPopTest, &ilistPushPopTestInfo},
    {heapTest, &heapTestInfo},
    {queueEstimatorTest, &queueEstimatorTestInfo},
    {rdtscTest, &rdtscTestInfo},
    {rdhrcTest, &rdhrcTestInfo},
    {rdcscTest, &rdcscTestInfo},
};

/**
 * Runs a particular test and prints a one-line result message.
 *
 * @param test
 *      Describes the test to run.
 */
void
runTest(TestCase& test)
{
    double secs = test.func();
    std::cout << std::left << std::setw(23) << test.info->name;
    std::cout << std::right << std::setw(8) << std::setprecision(2)
              << std::fixed;
    int width = 0;
    if (secs < 1.0e-06) {
        std::cout << 1e09 * secs << "ns";
    } else if (secs < 1.0e-03) {
        std::cout << 1e06 * secs << "us";
    } else if (secs < 1.0) {
        std::cout << 1e03 * secs << "ms";
    } else {
        std::cout << secs << "s ";
    }
    std::cout << std::setw(16) << "" << test.info->description;
    std::cout << std::endl;
}

/**
 * Print short listing of a particular test.
 *
 * @param test
 *      Describes the test to list.
 */
void
listTest(TestCase& test)
{
    std::cout << std::left << std::setw(26) << test.info->name
              << test.info->description << std::endl;
}

/**
 * Print the documentation of a particular test.
 *
 * @param test
 *      Describes the test whose documentation should be printed.
 */
void
infoTest(TestCase& test)
{
    std::cout << "Test Name: " << test.info->name << std::endl << std::endl;
    std::cout << "    " << test.info->description << std::endl << std::endl;
    std::istringstream docs(test.info->docs);
    std::string docLine;
    while (std::getline(docs, docLine)) {
        std::cout << "    " << docLine << std::endl;
    }
    std::cout << std::endl;
}

int
main(int argc, char* argv[])
{
    std::map<std::string, docopt::value> args =
        docopt::docopt(USAGE, {argv + 1, argv + argc},
                       true,                      // show help if requested
                       "Perf (Nano-Benchmark)");  // version string

    if (args["run"].asBool()) {
        if (args["TEST"].asStringList().empty()) {
            // Run all tests if no TEST is specified.
            for (TestCase& test : tests) {
                runTest(test);
            }
        } else {
            // Look for and run only the specified TESTs.
            bool foundTest = false;
            for (TestCase& test : tests) {
                for (auto const& testName : args["TEST"].asStringList()) {
                    if (std::strstr(test.info->name, testName.c_str()) !=
                        NULL) {
                        foundTest = true;
                        runTest(test);
                        break;
                    }
                }
            }
            if (!foundTest) {
                std::cout << "No test found matching the given arguments"
                          << std::endl;
            }
        }
    } else if (args["list"].asBool()) {
        for (TestCase& test : tests) {
            listTest(test);
        }
    } else if (args["info"].asBool()) {
        bool foundTest = false;
        for (TestCase& test : tests) {
            for (auto const& testName : args["TEST"].asStringList()) {
                if (std::strstr(test.info->name, testName.c_str()) != NULL) {
                    foundTest = true;
                    infoTest(test);
                    break;
                }
            }
        }
        if (!foundTest) {
            std::cout << "No test found matching the given arguments"
                      << std::endl;
        }
    }

    return 0;
}
