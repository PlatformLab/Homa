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

#include <gtest/gtest.h>

#include <Homa/Drivers/Util/QueueEstimator.h>

namespace Homa {
namespace Drivers {
namespace Util {
namespace {

/**
 * A Clock that can be set to an arbitrary time used for unit testing.
 *
 * Conforms to the C++ named requirements for Clock.
 */
struct MockClock {
    typedef std::chrono::nanoseconds duration;
    typedef duration::rep rep;
    typedef duration::period period;
    typedef std::chrono::time_point<MockClock> time_point;
    static const bool is_steady = false;

    static uint64_t mockTimeNS;

    static time_point now() noexcept
    {
        return time_point(std::chrono::nanoseconds(MockClock::mockTimeNS));
    }
};

uint64_t MockClock::mockTimeNS = 0;

class QueueEstimatorTest : public ::testing::Test {
  public:
    QueueEstimatorTest()
        : queueEstimator(8)
    {}

    ~QueueEstimatorTest() {}

    QueueEstimator<MockClock> queueEstimator;
};

TEST_F(QueueEstimatorTest, getQueuedBytes)
{
    EXPECT_EQ(1000000.0, queueEstimator.bandwidth);

    // 1000B queued at 1000us.
    MockClock::mockTimeNS = 1000000;
    queueEstimator.signalBytesSent(1000);
    EXPECT_EQ(1000, queueEstimator.queuedBytes);

    // Size after +50 us.
    MockClock::mockTimeNS = 1050000;
    EXPECT_EQ(950, queueEstimator.getQueuedBytes());
    EXPECT_EQ(950, queueEstimator.queuedBytes);

    // Queue 1000 more at +500 us.
    MockClock::mockTimeNS = 1500000;
    queueEstimator.signalBytesSent(1000);
    EXPECT_EQ(1500, queueEstimator.queuedBytes);

    // Queue should be drained after +2500 us.
    MockClock::mockTimeNS = 30000000;
    EXPECT_EQ(0, queueEstimator.getQueuedBytes());
    EXPECT_EQ(0, queueEstimator.queuedBytes);
}

TEST_F(QueueEstimatorTest, signalBytesSent)
{
    // Nothing to test; tested by QueueEstimatorTest_getQueuedBytes.
}

TEST_F(QueueEstimatorTest, refreshQueuedBytesEstimate)
{
    // Nothing to test; tested by QueueEstimatorTest_getQueuedBytes.
}

}  // namespace
}  // namespace Util
}  // namespace Drivers
}  // namespace Homa
