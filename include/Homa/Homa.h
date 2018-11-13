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

#ifndef HOMA_HOMA_H
#define HOMA_HOMA_H

#include <Homa/Driver.h>

#include <bitset>
#include <cstdint>

namespace Homa {

// forward declarations
namespace Core {
class MessageContext;
class TransportImpl;
}  // namespace Core

/// Defines a set of flags that set optional send behavior Homa::Message.
typedef std::bitset<3> SendFlag;
/// Default; No flags set.
static const SendFlag SEND_NO_FLAGS = 0;
/// Signal to Transport to not require a Transport level acknowledgment. This is
/// ususally because higher-level software has its own way of confirming that
/// the Message is complete.
static const SendFlag SEND_NO_ACK = 1 << 0;
/// Request that the Trasport manage the sent Message even after the application
/// destroys the Message. The Transport will attempt resends of the Message
/// until the Message is complete. If the SEND_NO_ACK flag is set, the Message
/// is considered complete after the Message's last byte is sent.
static const SendFlag SEND_DETACHED = 1 << 1;
/// Signal to the Transport that the Message is likely to generating an
/// incomming Message. Used by the Transport to anticipate incast.
static const SendFlag SEND_EXPECT_RESPONSE = 1 << 2;

/**
 * A Message object refers to an array of bytes that can be sent or is
 * received over the network via Homa::Transport.
 *
 * A Message object should be initilized by calling Transport::newMessage()
 * or Transport::receiveMessage(). Uninitialized instances are unusable.
 *
 * This class is NOT thread-safe except for where an instance is accessed
 * by the transport which may be running on a different thread.
 *
 * @sa Transport::newMessage(), Transport::receiveMessage(),
 * Transport::sendMessage()
 */
class Message {
  public:
    /**
     * Basic constructor to create an uninitialized Message object. Use by
     * applications of the Homa library.
     *
     * Message objects can be initialized by moving the result of calling
     * Transport::newMessage() or Transport::receiveMessage().
     */
    Message();

    /**
     * Move constructor.
     */
    Message(Message&& other);

    /**
     * Default destructor for a Message object.
     */
    ~Message();

    /**
     * Move assignment.
     */
    Message& operator=(Message&& other);

    /**
     * Returns true if the Message in initialized; false otherwise.
     */
    operator bool() const;

    /**
     * Append an array of bytes to the end of the Message by copying the
     * bytes into the Message's internal storage.
     *
     * This operation cannot be performed on a received Message or one that
     * has already been sent.
     *
     * @param source
     *      Address of the first byte of data (in a byte array) to be
     *      copied to the end of the Message.
     * @param num
     *      Number of bytes to be appended.
     */
    void append(const void* source, uint32_t num);

    /**
     * Get the contents of a specified range of bytes in the Message by
     * copying them into the provided destination memory region.
     *
     * This operation cannot be performed on a detached Message.
     *
     * @param offset
     *      The number of bytes in the Message preceding the range of bytes
     *      being requested.
     * @param destination
     *      The pointer to the memory region into which the requested byte
     *      range will be copied. The caller must ensure that the buffer is
     *      big enough to hold the requested number of bytes.
     * @param num
     *      The number of bytes being requested.
     *
     * @return
     *      The number of bytes actually copied out. This number may be less
     *      than "num" if the requested byte range exceeds the range of
     *      bytes in the Message.
     */
    uint32_t get(uint32_t offset, void* destination, uint32_t num) const;

    /**
     * Set the contents of a specified range of bytes in the Message using
     * the contents of the provided source memory region.
     *
     * If necessary, this operation will extend the Message to accomidate
     * the provided source content and will leave the contents of the
     * Message before the offset untouched and potentailly uninitilized.
     *
     * This operation cannot be performed on a received Message or one that
     * has already been sent.
     *
     * @param offset
     *      The number of bytes in the Message preceding the range of bytes
     *      to be set.
     * @param source
     *      The pointer to the memory region whose
     * @param num
     *      The number of bytes to set.
     */
    void set(uint32_t offset, const void* source, uint32_t num);

    /**
     * Return the network address associated with this Message. For an
     * incomming Message this is the source address. For an outgoing Message
     * this is the destination address.
     */
    Driver::Address* getAddress() const;

    /**
     * Set the destiation network address for this Message.
     *
     * This operation cannot be performed on a received Message or one that
     * has already been sent.
     */
    void setDestination(Driver::Address* destination);

    /**
     * Send a this Message.
     *
     * @param flags
     *      A bit field of flags that sets optional behavior for this method.
     * @param completes
     *      Set of messages for which sending this request completes.
     * @param numCompletes
     *      Number of messages in _completes_.
     */
    void send(SendFlag flags = SEND_NO_FLAGS, Message* completes[] = nullptr,
              uint16_t numCompletes = 0);

    /**
     * Send a this Message.
     *
     * @param destination
     *      The destiation network address for this Message.
     * @param flags
     *      A bit field of flags that sets optional behavior for this method.
     * @param completes
     *      Set of messages for which sending this request completes.
     * @param numCompletes
     *      Number of messages in _completes_.
     */
    void send(Driver::Address* destination, SendFlag flags = SEND_NO_FLAGS,
              Message* completes[] = nullptr, uint16_t numCompletes = 0);

  private:
    /// Contains the metadata and access to the message contents.
    Core::MessageContext* context;

    /// Transport responsible for this message.
    Core::TransportImpl* transportImpl;

    Message(const Message&) = delete;
    Message& operator=(const Message&) = delete;

    friend class Core::TransportImpl;
};

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
     * Construct an instance of a Homa-based transport.
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
    explicit Transport(Driver* driver, uint64_t transportId);

    /**
     * Transport destructor.
     */
    ~Transport();

    /**
     * Create a new Message that can be sent over Homa::Transport.
     */
    Message newMessage();

    /**
     * Return a Message that has been received by this Homa::Transport. If no
     * Message was received, the returned Message will be uninitilized.
     *
     * The Transport will not consider the returned Message complete until the
     * returned Message is destroyed.
     *
     * @sa Transport::sendMessage()
     */
    Message receiveMessage();

    /**
     * Return a network address handle for the given string representation of
     * the address. Addresses and address strings are Driver specific.
     *
     * @param addressString
     *      See above.
     * @return
     *      Pointer to an Address object.
     * @throw BadAddress
     *      _addressString_ is malformed.
     */
    Driver::Address* getAddress(std::string const* const addressString);

    /**
     * Make incremental progress performing all Transport functionality.
     *
     * This method MUST be called for the Transport to make progress and should
     * be called frequently to ensure timely progress.
     */
    void poll();

  private:
    /// Pointer to the actual transport implementation whose details are hidden
    /// from applications.
    Core::TransportImpl* const transportImpl;

    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
};

}  // namespace Homa

#endif  // HOMA_HOMA_H