/* Copyright (c) 2018-2019, Stanford University
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

#ifndef HOMA_CORE_SCHEDULER_H
#define HOMA_CORE_SCHEDULER_H

#include "Homa/Driver.h"

#include "Protocol.h"

namespace Homa {
namespace Core {

/**
 * Implements Homa's receiver-side scheduling policy. Responsible for issuing
 * grants to senders.
 *
 * This class is thread-safe.
 */
class Scheduler {
  public:
    explicit Scheduler(Driver* driver);
    virtual void packetReceived(Protocol::MessageId msgId,
                                Driver::Address* sourceAddr,
                                uint32_t totalMessageLength,
                                uint32_t totalBytesReceived);

  private:
    /// Driver that can be used to send packets.
    Driver* driver;

    /// Number of bytes that can be sent in 1 round-trip-time.
    const uint32_t RTT_BYTES;
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_SCHEDULER_H
