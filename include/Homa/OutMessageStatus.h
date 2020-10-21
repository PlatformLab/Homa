/* Copyright (c) 2020 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HOMA_INCLUDE_HOMA_OUTMESSAGESTATUS_H
#define HOMA_INCLUDE_HOMA_OUTMESSAGESTATUS_H

/**
 * Defines the possible states of an OutMessage.
 */
#ifdef __cplusplus
enum class OutMessageStatus : int {
#else
enum homa_outmsg_status {
#endif
    NOT_STARTED,  //< The sending of this message has not started.
    IN_PROGRESS,  //< The message is in the process of being sent.
    CANCELED,     //< The message was canceled while still IN_PROGRESS.
    SENT,         //< The message has been completely sent.
    COMPLETED,    //< The message has been received and processed.
    FAILED,       //< The message failed to be delivered and processed.
};

#endif  // HOMA_INCLUDE_HOMA_OUTMESSAGESTATUS_H