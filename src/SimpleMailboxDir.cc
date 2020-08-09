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

#include <Homa/Utils/SimpleMailboxDir.h>
#include "SpinLock.h"
#include <list>

namespace Homa {

/**
 * A simple reference implementation of Homa::Mailbox that uses polling to
 * detect incoming messages.
 */
class MailboxImpl : public Mailbox {
  public:
    explicit MailboxImpl();
    ~MailboxImpl() override;
    void close() override;
    void deliver(InMessage* message) override;
    InMessage* retrieve(bool blocking) override;
    void socketShutdown() override;

    /// Protects the queue
    SpinLock mutex;

    /// Keeps track of the number of calls to open() without paired close().
    /// It's initialized to one because, intuitively, a Socket must keep its
    /// mailbox "open" in order to retrieve incoming messages.
    std::atomic<int> openers;

    /// Has the corresponding socket been shut down?
    std::atomic<bool> shutdown;

    /// List of completely received messages.
    std::list<InMessage*> queue;
};

MailboxImpl::MailboxImpl()
    : mutex()
    , openers(1)
    , shutdown()
    , queue()
{}

MailboxImpl::~MailboxImpl()
{
    while (!queue.empty()) {
        InMessage* message = queue.front();
        queue.pop_front();
        Homa::unique_ptr<InMessage> deleter(message);
    }
}

/// See Homa::Mailbox::close()
void
MailboxImpl::close()
{
    if (openers.fetch_sub(1, std::memory_order_release) == 1) {
        std::atomic_thread_fence(std::memory_order_acquire);

        // MailboxImpl was instantiated via "new" in SimpleMailboxDir::alloc.
        delete this;
    }
}

/// See Homa::Mailbox::deliver()
void
MailboxImpl::deliver(InMessage* message)
{
    SpinLock::Lock _(mutex);
    queue.push_back(message);
}

/// See Homa::Mailbox::retrieve()
InMessage*
MailboxImpl::retrieve(bool blocking)
{
    InMessage* message = nullptr;
    do {
        SpinLock::Lock _(mutex);
        if (!queue.empty()) {
            message = queue.front();
            queue.pop_front();
        }
    } while (blocking && !shutdown.load(std::memory_order_relaxed));
    return message;
}

/// See Homa::Mailbox::socketShutdown()
void
MailboxImpl::socketShutdown()
{
    shutdown.store(true);
}

SimpleMailboxDir::SimpleMailboxDir()
    : mutex(new SpinLock())
    , map()
{}

SimpleMailboxDir::~SimpleMailboxDir()
{
    for (auto entry : map) {
        MailboxImpl* mailbox = entry.second;
        mailbox->close();
    }
}

Mailbox*
SimpleMailboxDir::alloc(uint16_t port)
{
    MailboxImpl* mailbox = nullptr;
    SpinLock::Lock _(*mutex);
    auto it = map.find(port);
    if (it == map.end()) {
        mailbox = new MailboxImpl();
        map[port] = mailbox;
    }
    return mailbox;
}

Mailbox*
SimpleMailboxDir::open(uint16_t port)
{
    MailboxImpl* mailbox = nullptr;
    {
        // Look up the mailbox
        SpinLock::Lock _(*mutex);
        auto it = map.find(port);
        if (it != map.end()) {
            mailbox = it->second;
        }
    }

    // Increment the reference count of the mailbox.
    if (mailbox) {
        mailbox->openers.fetch_add(1, std::memory_order_relaxed);
    }
    return mailbox;
}

bool
SimpleMailboxDir::remove(uint16_t port)
{
    MailboxImpl* mailbox;
    {
        SpinLock::Lock _(*mutex);
        auto it = map.find(port);
        if (it == map.end()) {
            return false;
        }
        mailbox = it->second;
        map.erase(it);
    }
    mailbox->close();
    return true;
}

}  // namespace Homa
