/* Copyright (c) 2018, Stanford University
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

#ifndef HOMA_TRANSPORT_H
#define HOMA_TRANSPORT_H

#include "Homa/Driver.h"
#include "Homa/Message.h"

#include <atomic>
#include <bitset>
#include <vector>

/**
 * Homa
 */
namespace Homa {

/// Defines a set of flags that set optional behavior in the Transport.
/// @sa #SendFlag, #SEND_NO_FLAGS, #SEND_NO_ACK, #SEND_DETACHED,
/// #SEND_EXPECT_RESPONSE.
typedef std::bitset<3> SendFlag;
/// Default; No flags set.
const SendFlag SEND_NO_FLAGS = 0;
/// Signal to Transport to not require a Transport level acknowledgment.
/// This is ususally because higher-level software has its own way of
/// confirming that the Message is complete.
const SendFlag SEND_NO_ACK = 1 << 0;
/// Request that the Trasport manage the sent Message even after the
/// application destroys the Message. The Transport will attempt resends of
/// the Message until the Message is complete. If the SEND_NO_ACK flag is set,
/// the Message is considered complete after the Message's last byte is sent.
const SendFlag SEND_DETACHED = 1 << 1;
/// Signal to the Transport that the Message is likely to generating an
/// incomming Message. Used by the Transport to anticipate incast.
const SendFlag SEND_EXPECT_RESPONSE = 1 << 2;

/**
 * Provides a means of commicating across the network using the Homa
 * protocol.
 *
 * The transport is used to send and receive messages accross the network.
 * The execution of the transport is driven through repeated calls to the
 * Transport::poll() method; the transport will not make any progress
 * otherwise.
 *
 * When sending a message, the transport will attempt to ensure reliable and
 * at-least-once processing of the message. The transport will continue to
 * retransmit the message periodically until the transport considers the
 * message completed by the receiver, the sender cancels the message, or the
 * message encounters an unrecoverable error. The transport relies on
 * signals from the higher-level software and transport-level
 * acknowledgements to determine when a received message is considered
 * complete (see Transport::sendMessage() and Transport::receiveMessage()).
 * In some cases (e.g. an RPC system), the higher-level software may wish to
 * preclude the use of transport-level acknowledgments for performances
 * reasons. In such classes, the higher-level software should cancel the
 * message onces it is considered complete.
 *
 * This class is thread-safe.
 */
class Transport {
  public:
    /**
     * Construct and return an instances of a Homa-based transport.
     *
     * Caller is responsible for calling delete on the Transport when it is no
     * longer needed.
     *
     * @param driver
     *      Driver with which this transport should send and receive packets.
     * @param transportId
     *      This transport's unique identifier in the group of transports among
     *      which this transport will communicate.
     * @return
     *      Pointer to a new Homa::Transport.
     */
    static Transport* newTransport(Driver* driver, uint64_t transportId);

    /**
     * Create a new Message that can be sent over Homa::Transport.
     */
    virtual Message newMessage() = 0;

    /**
     * Return a Message that has been received by this Homa::Transport. If no
     * Message was received, the returned Message will be uninitilized.
     *
     * The Transport will not consider the returned Message complete until the
     * returned Message is destroyed.
     *
     * @sa Transport::sendMessage()
     */
    virtual Message receiveMessage() = 0;

    /**
     * Send a Message.
     *
     * @param message
     *      Message that should be sent.
     * @param flags
     *      A bit field of flags that sets optional behavior for this method.
     *      See #SendFlag, #SEND_NO_FLAGS, #SEND_NO_ACK, #SEND_DETACHED,
     *      #SEND_EXPECT_RESPONSE.
     * @param completes
     *      Set of messages for which sending this request completes.
     * @param numCompletes
     *      Number of messages in _completes_.
     */
    virtual void sendMessage(Message* message, SendFlag flags = SEND_NO_FLAGS,
                             Message* completes[] = nullptr,
                             uint16_t numCompletes = 0) = 0;

    /**
     * Make incremental progress performing all Transport functionality.
     *
     * This method MUST be called for the Transport to make progress and should
     * be called frequently to ensure timely progress.
     */
    virtual void poll() = 0;
};

}  // namespace Homa

#endif  // HOMA_TRANSPORT_H
