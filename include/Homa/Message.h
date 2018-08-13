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

#include "Homa/Driver.h"

namespace Homa {

// Forward declaration
class Transport;
namespace Core {
class MessageContext;
}

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
     * Construct a new Message with the given MessageContext. Called only by
     * internal implementation. NOT FOR USE BY APPLICATIONS.
     *
     * @param context
     *      MessageContext that contains or will contain the metadata and
     *      contents of this new Message.
     */
    explicit Message(Core::MessageContext* context);

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
     * Return a pointer to this Message's context. Used by internal
     * implementation.  NOT FOR USE BY APPLICATIONS.
     */
    Core::MessageContext* getContext() const;

  private:
    /// Contains the metadata and access to the message contents.
    Core::MessageContext* context;

    Message(const Message&) = delete;
    Message& operator=(const Message&) = delete;
};

}  // namespace Homa

#endif  // HOMA_HOMA_H