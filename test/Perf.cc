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

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "Cycles.h"
#include "docopt.h"

#include "Homa/Drivers/Util/QueueEstimator.h"
#include "Intrusive.h"

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

TestInfo mapLookupTestInfo = {
    "mapLookup", "Lookup an element in a std::unordered_map",
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
    {listSearchTest, &listSearchTestInfo},
    {mapLookupTest, &mapLookupTestInfo},
    {queueEstimatorTest, &queueEstimatorTestInfo},
    {rdtscTest, &rdtscTestInfo},
    {rdhrcTest, &rdhrcTestInfo},
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
