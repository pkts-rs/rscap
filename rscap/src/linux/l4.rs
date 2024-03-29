// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Transport-layer (IPv4-only) packet capture/transmission utilities.
//!
//! 
//! 

use std::{io, mem, ptr};
use std::net::SocketAddrV4;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Protocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Internet Control Message Protocol
    Icmp,
    /// Stream Control Transmission Protocol
    Sctp,
    /// Datagram Congestion Control Protocol (RFC4340)
    Dccp,
}

/// A socket that exchanges packets at the transport layer.
///
/// In Linux, this corresponds to `socket(AF_INET, SOCK_RAW, proto)`.
pub struct L4Socket {
    fd: i32,
}

impl L4Socket {
    /// Create a new transport-layer socket.
    ///
    /// By default, transport-layer sockets do not listen or receive packets on any protocol or
    /// interface; to begin receiving packets, call [`bind()`](L3Socket::bind()).
    ///
    /// # Permissions
    ///
    /// A program must have the `CAP_NET_RAW` capability in order for this call to succeed;
    /// otherwise, `EPERM` will be returned.
    #[inline]
    pub fn new(protocol: L4Protocol) -> io::Result<L4Socket> {
        let protocol = match protocol {
            L4Protocol::Dccp => libc::IPPROTO_DCCP,
            L4Protocol::Icmp => libc::IPPROTO_ICMP,
            L4Protocol::Sctp => libc::IPPROTO_SCTP,
            L4Protocol::Tcp => libc::IPPROTO_TCP,
            L4Protocol::Udp => libc::IPPROTO_UDP,
        };

        // Set the socket to receive no packets by default (protocol: 0)
        match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol) } {
            ..=-1 => Err(std::io::Error::last_os_error()),
            fd => Ok(L4Socket { fd }),
        }
    }

    /// Bind the transport-layer socket to a particular address.
    pub fn bind(&self, addr: &SocketAddrV4) -> io::Result<()> {
        let ip_addr = addr.ip();
        let port = addr.port();

        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes(ip_addr.octets()) // TODO: check endianness of this
            },
            sin_port: port,
            sin_zero: [0u8; 8],
        };

        // SAFETY: `ptr::addr_of!(sockaddr_ll)` will always yield a pointer to
        // `mem::size_of::<libc::sockaddr_ll>()` valid bytes.
        match unsafe {
            libc::bind(
                self.fd,
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

