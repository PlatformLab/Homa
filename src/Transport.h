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

#ifndef HOMA_CORE_TRANSPORT_H
#define HOMA_CORE_TRANSPORT_H

#include "OpContext.h"
#include "Protocol.h"
#include "Receiver.h"
#include "Scheduler.h"
#include "Sender.h"
#include "SpinLock.h"

#include <atomic>
#include <bitset>
#include <vector>

/**
 * Homa
 */
namespace Homa {
namespace Core {

/**
 * Provides the implementation of Homa::Transport.
 *
 * This class is thread-safe.
 */
class Transport {
  public:
    explicit Transport(Driver* driver, uint64_t transportId);

    ~Transport();
    OpContext* allocOp();
    OpContext* receiveOp();
    void releaseOp(OpContext* op);
    void sendRequest(OpContext* op, Driver::Address* destination);
    void sendReply(OpContext* op);
    void poll();

    /// Driver from which this transport will send and receive packets.
    Driver* const driver;

  private:
    /// Unique identifier for this transport.
    const uint64_t transportId;

    /// Unique identifier for the next RemoteOp this transport sends.
    std::atomic<uint64_t> nextOpSequenceNumber;

    /// Pool from which this transport will allocate OpContext objects.
    OpContextPool opContextPool;

    /// Collection of ServerOp contexts that are ready but have not yet been
    /// delivered to the application.
    struct {
        /// Protects the serverOpQueue;
        SpinLock mutex;
        /// Holds the undelivered ServerOp contexts.
        std::deque<OpContext*> queue;
    } serverOpQueue;

    /// Module which controls the sending of message.
    std::unique_ptr<Core::Sender> sender;

    /// Module which schedules incoming packets.
    std::unique_ptr<Core::Scheduler> scheduler;

    /// Module which receives packets and forms them into messages.
    std::unique_ptr<Core::Receiver> receiver;

    void processPackets();
    void processMessages();
};

}  // namespace Core
}  // namespace Homa

#endif  // HOMA_CORE_TRANSPORT_H
