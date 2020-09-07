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

#ifndef HOMA_INCLUDE_HOMA_PERF_H
#define HOMA_INCLUDE_HOMA_PERF_H

#include <atomic>
#include <cstdint>

namespace Homa {
namespace Perf {

/**
 * Performance statistics
 */
struct Stats {
    /// Relative time when these statistics were gathered in cycles.
    uint64_t timestamp;

    /// Conversion factor from cycles to seconds.
    double cycles_per_second;

    /// CPU time spent actively processing Homa messages in cycles.
    uint64_t active_cycles;

    /// CPU time spent running Homa with no work to do in cycles.
    uint64_t idle_cycles;

    /// Number of InMessages that have been allocated by the Transport.
    uint64_t allocated_rx_messages;

    /// Number of InMessages that have been received by the Transport.
    uint64_t received_rx_messages;

    /// Number of InMessages delivered to the application.
    uint64_t delivered_rx_messages;

    /// Number of InMessages released back to the Transport for destruction.
    uint64_t destroyed_rx_messages;

    /// Number of OutMessages allocated for the application.
    uint64_t allocated_tx_messages;

    /// Number of OutMessages released back to the transport.
    uint64_t released_tx_messages;

    /// Number of OutMessages destroyed.
    uint64_t destroyed_tx_messages;

    /// Number of bytes sent by the transport.
    uint64_t tx_bytes;

    /// Number of bytes received by the transport.
    uint64_t rx_bytes;

    /// Number of data packets sent.
    uint64_t tx_data_pkts;

    /// Number of data packets received.
    uint64_t rx_data_pkts;

    /// Number of grant packets sent.
    uint64_t tx_grant_pkts;

    /// Number of grant packets received.
    uint64_t rx_grant_pkts;

    /// Number of done packets sent.
    uint64_t tx_done_pkts;

    /// Number of done packets received.
    uint64_t rx_done_pkts;

    /// Number of resend packets sent.
    uint64_t tx_resend_pkts;

    /// Number of resend packets received.
    uint64_t rx_resend_pkts;

    /// Number of busy packets sent.
    uint64_t tx_busy_pkts;

    /// Number of busy packets received.
    uint64_t rx_busy_pkts;

    /// Number of ping packets sent.
    uint64_t tx_ping_pkts;

    /// Number of ping packets received.
    uint64_t rx_ping_pkts;

    /// Number of unknown packets sent.
    uint64_t tx_unknown_pkts;

    /// Number of unknown packets received.
    uint64_t rx_unknown_pkts;

    /// Number of error packets sent.
    uint64_t tx_error_pkts;

    /// Number of error packets received.
    uint64_t rx_error_pkts;
};

/**
 * Fill the provided stats structure with the current performance statistics.
 */
void getStats(Stats* stats);

}  // namespace Perf
}  // namespace Homa

#endif  // HOMA_INCLUDE_HOMA_PERF_H
