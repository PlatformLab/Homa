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

#ifndef HOMA_INCLUDE_HOMA_DRIVERS_UTIL_QUEUEESTIMATOR_H
#define HOMA_INCLUDE_HOMA_DRIVERS_UTIL_QUEUEESTIMATOR_H

#include <cassert>
#include <chrono>

namespace Homa {
namespace Drivers {
namespace Util {

/**
 * This class is used to estimate the current number of bytes still awaiting
 * transmission in a NIC's output queue. It does this by tracking when packets
 * are passed to the NIC, and then using the network bandwidth to estimate how
 * many bytes have actually been transmitted. It assumes that this class has
 * complete knowledge of all packets given to the NIC, so it may underestimate
 * queue length in situations where packets can be queued (e.g. by other
 * processes) without the knowledge of this class.
 *
 * This class is NOT thread-safe.
 *
 * @tparam Clock
 *      Class that meets the C++ named requirements for Clock.
 */
template <class Clock>
class QueueEstimator {
  public:
    /**
     * Construct a QueueEstimator; the NIC is assumed to be idle when this
     * method is invoked.
     *
     * @param bandwidth
     *      Bandwidth of the network, in Megabits per second.
     */
    explicit QueueEstimator(uint32_t bandwidth)
        : bandwidth(static_cast<double>(bandwidth) * 1e06 / 8.0)
        , queuedBytes(0)
        , lastUpdateTime(Clock::now())
    {}

    /**
     * Return an estimate of the number of bytes unsent bytes pending in the
     * NIC's output queue.
     */
    uint32_t getQueuedBytes()
    {
        refreshQueuedBytesEstimate();
        return queuedBytes;
    }

    /**
     * Called when more bytes have been added to the NIC queue so that this
     * QueueEstimator can update it's estimate.
     *
     * @param sentBytes
     *      The number of bytes sent to the NIC output queue.
     */
    void signalBytesSent(uint32_t sentBytes)
    {
        refreshQueuedBytesEstimate();
        queuedBytes += sentBytes;
    }

  private:
    /**
     * Helper method to recalculate the current estimated NIC output queue
     * length.
     */
    void refreshQueuedBytesEstimate()
    {
        std::chrono::time_point<Clock> currentTime = Clock::now();
        assert(currentTime >= lastUpdateTime);
        std::chrono::duration<double, std::ratio<1>> updateInterval =
            currentTime - lastUpdateTime;
        // Get the current queue size estimate.
        double queuedBytesEstimate =
            queuedBytes - bandwidth * updateInterval.count();
        queuedBytes = (queuedBytesEstimate < 0)
                          ? 0
                          : static_cast<uint32_t>(queuedBytesEstimate);
        lastUpdateTime = currentTime;
    }

    /// Bandwidth in bytes per second.
    const double bandwidth;

    /// The estimated number of bytes that have been queued at the NIC but not
    /// yet sent out on the wire.
    uint32_t queuedBytes;

    /// The timestamp when the queuedBytes was last updated.
    std::chrono::time_point<Clock> lastUpdateTime;

    // DISALLOW_COPY_AND_ASSIGN
    QueueEstimator(const QueueEstimator&) = delete;
    QueueEstimator& operator=(const QueueEstimator&) = delete;
};

}  // namespace Util
}  // namespace Drivers
}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_DRIVERS_UTIL_QUEUEESTIMATOR_H
