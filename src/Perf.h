/* Copyright (c) 2020, Stanford University
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

#ifndef HOMA_PERF_H
#define HOMA_PERF_H

#include <Homa/Perf.h>
#include <Cycles.h>

#include <atomic>

namespace Homa {
namespace Perf {

/**
 * Collection of collected performance counters.
 */
struct Counters {
    /**
     * Wrapper class for individual counter entries.
     */
    template <typename T>
    struct Stat : private std::atomic<T> {
        /**
         * Passthrough constructor.
         */
        template <typename... Args>
        Stat(Args&&... args)
            : std::atomic<T>(static_cast<Args&&>(args)...)
        {}

        /**
         * Add the value of another Stat to this Stat.
         *
         * This method is thread-safe.
         */
        inline void add(const Stat<T>& other)
        {
            this->fetch_add(other.load(std::memory_order_relaxed),
                            std::memory_order_relaxed);
        }

        /**
         * Add the given value to this Stat.
         *
         * This method is not thread-safe.
         */
        inline void add(T val)
        {
            this->store(this->load(std::memory_order_relaxed) + val,
                        std::memory_order_relaxed);
        }

        /**
         * Return the stat value.
         *
         * This method is thread-safe.
         */
        inline T get() const
        {
            return this->load(std::memory_order_relaxed);
        }
    };

    /**
     * Default constructor.
     */
    Counters()
        : total_cycles(0)
        , active_cycles(0)
        , allocated_rx_messages(0)
        , received_rx_messages(0)
        , delivered_rx_messages(0)
        , destroyed_rx_messages(0)
        , allocated_tx_messages(0)
        , released_tx_messages(0)
        , destroyed_tx_messages(0)
        , tx_bytes(0)
        , rx_bytes(0)
        , tx_data_pkts(0)
        , rx_data_pkts(0)
        , tx_grant_pkts(0)
        , rx_grant_pkts(0)
        , tx_done_pkts(0)
        , rx_done_pkts(0)
        , tx_resend_pkts(0)
        , rx_resend_pkts(0)
        , tx_busy_pkts(0)
        , rx_busy_pkts(0)
        , tx_ping_pkts(0)
        , rx_ping_pkts(0)
        , tx_unknown_pkts(0)
        , rx_unknown_pkts(0)
        , tx_error_pkts(0)
        , rx_error_pkts(0)
    {}

    /**
     * Default destructor.
     */
    ~Counters() = default;

    /**
     * Add the values in other to the corresponding counters in this object.
     */
    void add(const Counters* other)
    {
        total_cycles.add(other->total_cycles);
        active_cycles.add(other->active_cycles);
        allocated_rx_messages.add(other->allocated_rx_messages);
        received_rx_messages.add(other->received_rx_messages);
        delivered_rx_messages.add(other->delivered_rx_messages);
        destroyed_rx_messages.add(other->destroyed_rx_messages);
        allocated_tx_messages.add(other->allocated_tx_messages);
        released_tx_messages.add(other->released_tx_messages);
        destroyed_tx_messages.add(other->destroyed_tx_messages);
        tx_bytes.add(other->tx_bytes);
        rx_bytes.add(other->rx_bytes);
        tx_data_pkts.add(other->tx_data_pkts);
        rx_data_pkts.add(other->rx_data_pkts);
        tx_grant_pkts.add(other->tx_grant_pkts);
        rx_grant_pkts.add(other->rx_grant_pkts);
        tx_done_pkts.add(other->tx_done_pkts);
        rx_done_pkts.add(other->rx_done_pkts);
        tx_resend_pkts.add(other->tx_resend_pkts);
        rx_resend_pkts.add(other->rx_resend_pkts);
        tx_busy_pkts.add(other->tx_busy_pkts);
        rx_busy_pkts.add(other->rx_busy_pkts);
        tx_ping_pkts.add(other->tx_ping_pkts);
        rx_ping_pkts.add(other->rx_ping_pkts);
        tx_unknown_pkts.add(other->tx_unknown_pkts);
        rx_unknown_pkts.add(other->rx_unknown_pkts);
        tx_error_pkts.add(other->tx_error_pkts);
        rx_error_pkts.add(other->rx_error_pkts);
    }

    /**
     * Export this object's counter values to a Stats structure.
     */
    void dumpStats(Stats* stats)
    {
        stats->active_cycles = active_cycles.get();
        stats->idle_cycles = total_cycles.get() - active_cycles.get();
        stats->allocated_rx_messages = allocated_rx_messages.get();
        stats->received_rx_messages = received_rx_messages.get();
        stats->delivered_rx_messages = delivered_rx_messages.get();
        stats->destroyed_rx_messages = destroyed_rx_messages.get();
        stats->allocated_tx_messages = allocated_tx_messages.get();
        stats->released_tx_messages = released_tx_messages.get();
        stats->destroyed_tx_messages = destroyed_tx_messages.get();
        stats->tx_bytes = tx_bytes.get();
        stats->rx_bytes = rx_bytes.get();
        stats->tx_data_pkts = tx_data_pkts.get();
        stats->rx_data_pkts = rx_data_pkts.get();
        stats->tx_grant_pkts = tx_grant_pkts.get();
        stats->rx_grant_pkts = rx_grant_pkts.get();
        stats->tx_done_pkts = tx_done_pkts.get();
        stats->rx_done_pkts = rx_done_pkts.get();
        stats->tx_resend_pkts = tx_resend_pkts.get();
        stats->rx_resend_pkts = rx_resend_pkts.get();
        stats->tx_busy_pkts = tx_busy_pkts.get();
        stats->rx_busy_pkts = rx_busy_pkts.get();
        stats->tx_ping_pkts = tx_ping_pkts.get();
        stats->rx_ping_pkts = rx_ping_pkts.get();
        stats->tx_unknown_pkts = tx_unknown_pkts.get();
        stats->rx_unknown_pkts = rx_unknown_pkts.get();
        stats->tx_error_pkts = tx_error_pkts.get();
        stats->rx_error_pkts = rx_error_pkts.get();
    }

    /// CPU time spent running the Homa poll loop in cycles.
    Stat<uint64_t> total_cycles;

    /// CPU time spent actively processing Homa messages in cycles.
    Stat<uint64_t> active_cycles;

    /// Number of InMessages that have been allocated by the Transport.
    Stat<uint64_t> allocated_rx_messages;

    /// Number of InMessages that have been received by the Transport.
    Stat<uint64_t> received_rx_messages;

    /// Number of InMessages delivered to the application.
    Stat<uint64_t> delivered_rx_messages;

    /// Number of InMessages released back to the Transport for destruction.
    Stat<uint64_t> destroyed_rx_messages;

    /// Number of OutMessages allocated for the application.
    Stat<uint64_t> allocated_tx_messages;

    /// Number of OutMessages released back to the transport.
    Stat<uint64_t> released_tx_messages;

    /// Number of OutMessages destroyed.
    Stat<uint64_t> destroyed_tx_messages;

    /// Number of bytes sent by the transport.
    Stat<uint64_t> tx_bytes;

    /// Number of bytes received by the transport.
    Stat<uint64_t> rx_bytes;

    /// Number of data packets sent.
    Stat<uint64_t> tx_data_pkts;

    /// Number of data packets received.
    Stat<uint64_t> rx_data_pkts;

    /// Number of grant packets sent.
    Stat<uint64_t> tx_grant_pkts;

    /// Number of grant packets received.
    Stat<uint64_t> rx_grant_pkts;

    /// Number of done packets sent.
    Stat<uint64_t> tx_done_pkts;

    /// Number of done packets received.
    Stat<uint64_t> rx_done_pkts;

    /// Number of resend packets sent.
    Stat<uint64_t> tx_resend_pkts;

    /// Number of resend packets received.
    Stat<uint64_t> rx_resend_pkts;

    /// Number of busy packets sent.
    Stat<uint64_t> tx_busy_pkts;

    /// Number of busy packets received.
    Stat<uint64_t> rx_busy_pkts;

    /// Number of ping packets sent.
    Stat<uint64_t> tx_ping_pkts;

    /// Number of ping packets received.
    Stat<uint64_t> rx_ping_pkts;

    /// Number of unknown packets sent.
    Stat<uint64_t> tx_unknown_pkts;

    /// Number of unknown packets received.
    Stat<uint64_t> rx_unknown_pkts;

    /// Number of error packets sent.
    Stat<uint64_t> tx_error_pkts;

    /// Number of error packets received.
    Stat<uint64_t> rx_error_pkts;
};

/**
 * Thread-local collection of performance counters.
 */
struct ThreadCounters : public Counters {
    ThreadCounters();
    ~ThreadCounters();
};

/**
 * Per thread counters.
 */
extern thread_local ThreadCounters counters;

/**
 * Provides a convenient way to measure multiple consecutive cycle time
 * intervals.
 */
class Timer {
  public:
    /**
     * Construct a new Timer.
     */
    Timer()
        : split_tsc(PerfUtils::Cycles::rdtsc())
    {}

    /**
     * Return the number of cycles since the last time split was called.
     */
    inline uint64_t split()
    {
        uint64_t prev_tsc = split_tsc;
        split_tsc = PerfUtils::Cycles::rdtsc();
        return split_tsc - prev_tsc;
    }

  private:
    /// Cycle time that split was last called.
    uint64_t split_tsc;
};

}  // namespace Perf
}  // namespace Homa

#endif  // HOMA_PERF_H
