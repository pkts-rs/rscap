// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bitflags::bitflags;

bitflags! {
    /// Flags to modify a call to `send_to()`.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct SendFlags: libc::c_int {
        /// Notifies the link layer that forward progress has happened.
        const CONFIRM = libc::MSG_CONFIRM;
        /// Requires that the datagram only be sent to hosts on directly connected networks (no gateways).
        const DONT_ROUTE = libc::MSG_DONTROUTE;
        /// Causes `recv()` to return immediately if no datagrams are ready to be read (nonblocking).
        const DONT_WAIT = libc::MSG_DONTWAIT;
        /// Blocks the SIGPIPE signal from being sent if a peer has closed the connection (EPIPE still returned).
        const NO_SIGNAL = libc::MSG_NOSIGNAL;
        /// Sends out-of-band data (protocol-specific).
        const OOB = libc::MSG_OOB;
    }
}

bitflags! {
    /// Flags to modify a call to `recv_from()`.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RecvFlags: libc::c_int {
        /// Causes `recv()` to return immediately if no datagrams are ready to be read (nonblocking).
        const DONT_WAIT = libc::MSG_DONTWAIT;
        /// Causes queued errors to be received from the socket error queue.
        const ERRQUEUE = libc::MSG_ERRQUEUE;
        /// Requests receipt of out-of-band data that would not be received normally (protocol-specific).
        const OOB = libc::MSG_OOB;
        /// Causes `recv()` to return a datagram without removing that datagram from the recv queue.
        const PEEK = libc::MSG_PEEK;
        /// Causes `recv()` to return the real length of the packet when truncated.
        const TRUNC = libc::MSG_TRUNC;
    }
}
