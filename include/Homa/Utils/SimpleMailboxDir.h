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

/**
 * @file Homa/Utils/SimpleMailboxDir.h
 *
 * Contains a simple reference implementation for the pluggable mailbox
 * directory in the Homa transport library. A mailbox directory is essential
 * to get a working transport but it's not central to the Homa protocol.
 *
 * Users may choose to use this reference implementation for starter, or define
 * their own implementation for best performance.
 */

#pragma once

#include <Homa/Homa.h>
#include <unordered_map>

namespace Homa {

/// Forward declaration
class SpinLock;
class MailboxImpl;

/**
 * A simple reference implementation of Homa::MailboxDir.
 *
 * This class relies on a monitor-style lock to protect the hash table that
 * maps port numbers to mailboxes and uses reference-counting for safe
 * reclamation of removed mailboxes.
 */
class SimpleMailboxDir final : public MailboxDir {
  public:
    explicit SimpleMailboxDir();
    ~SimpleMailboxDir() override;
    Mailbox* alloc(uint16_t port) override;
    Mailbox* open(uint16_t port) override;
    bool remove(uint16_t port) override;

  private:
    /// Monitor-style lock.
    std::unique_ptr<SpinLock> mutex;

    /// Hash table that maps port numbers to mailboxes.
    std::unordered_map<uint16_t, MailboxImpl*> map;
};

}  // namespace Homa
