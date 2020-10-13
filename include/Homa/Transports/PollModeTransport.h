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

#pragma once

#include <Homa/Homa.h>

namespace Homa {

/**
 * A polling-based Homa transport implementation.
 */
class PollModeTransport : public TransportBase {
  public:
    /**
     * Return a new instance of a polling-based Homa transport.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     * @return
     *      Pointer to the new transport instance.
     */
    static Homa::unique_ptr<PollModeTransport> create(Driver* driver,
                                                      uint64_t transportId);

    /**
     * Make incremental progress performing all Transport functionality.
     *
     * This method MUST be called for the Transport to make progress and should
     * be called frequently to ensure timely progress.
     */
    virtual void poll() = 0;

    /**
     * Check for and return a Message sent to this Socket if available.
     *
     * @param blocking
     *      When set to true, this method should not return until a message
     *      arrives or the socket is shut down.
     * @return
     *      Pointer to the received message, if any; otherwise, nullptr.
     */
    virtual Homa::unique_ptr<Homa::InMessage> receive() = 0;
};

}  // namespace Homa