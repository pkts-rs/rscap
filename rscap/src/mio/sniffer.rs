// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io;
use std::mem::ManuallyDrop;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use crate::filter::PacketFilter;
use crate::{Interface, Sniffer};

use mio::event::Source;
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};

/// A cross-platform asynchronous Sniffer interface, suitable for sending/receiving raw packets
/// over network interfaces in a manner compatible with `mio`.
pub struct AsyncSniffer {
    sniffer: Sniffer,
    io: ManuallyDrop<UdpSocket>,
}

impl AsyncSniffer {
    /// Creates a new Sniffer for the given interface.
    #[inline]
    pub fn new(iface: Interface) -> io::Result<Self> {
        let sniffer = Sniffer::new(iface)?;
        sniffer.set_nonblocking(true)?;

        // SAFETY: `AsyncTun` ensures that the RawFd is extracted from `io` in its drop()
        // implementation so that the descriptor isn't closed twice.
        let io = unsafe { UdpSocket::from_raw_fd(sniffer.as_raw_fd()) };

        Ok(Self {
            sniffer,
            io: ManuallyDrop::new(io),
        })
    }

    /// Activates the `Sniffer` to begin capturing packets.
    ///
    /// If `filter` is set to `None`, the `Sniffer` will capture all packets being both transmitted
    /// and received on the interface. Otherwise, the specified filter will be used to determine
    /// what kinds of packets should be captured or dropped. This filtering is performed in the OS
    /// and is generally much more efficient than userspace filtering, so using it is recommended.
    ///
    /// Calling this method is only necessary to receive packets over the `Sniffer`. If only sending
    /// packets is desired, this method may be omitted.
    ///
    /// # Re-activating a `Sniffer`
    ///
    /// If a `Sniffer` is activated, deactivated (via [`deactivate()`](Self::deactivate)) and then
    /// activated once again, any outstanding packets from the previous activation will be flushed.
    /// Likewise, if `activate()` is called on a `Sniffer` that has already been activated, all
    /// outstanding packets in its buffers will be flushed at the time the second `activate()` is
    /// called, even if the exact same `filter` is applied. If these outstanding packets are needed,
    /// a developer may first `deactivate()` the sniffer, sequentially read all outstanding packets
    /// (see [`recv()`](Self::recv)), and then `activate()` the sniffer with whatever new `filter`
    /// they wish to apply, provided the operating system supports saving outstanding packets
    /// (see the **WARNING** portion of [`activate()`](Self::activate)).
    ///
    /// The reason outstanding packets are always flushed on activation is to ensure that all
    /// packets received following activation adhere to the `filter` rule. If this were not the
    /// behavior of `activate()`, the `filter` rule could never be trusted--the developer would have
    /// no way of knowing where the outstanding queue of (unfiltered) packets end and where the new
    /// filtered packets begin. For the same reason, packets are never captured by a `Sniffer` until
    /// `activate()` is first called.
    #[inline]
    pub fn activate(&mut self, filter: Option<PacketFilter>) -> io::Result<()> {
        self.sniffer.activate(filter)
    }

    /// Stops the sniffer from capturing packets.
    ///
    /// A `Sniffer` may have outstanding packets in its buffers at the time this method is called.
    /// These packets can be retrieved via consecutive calls to [`recv()`](Self::recv); once all
    /// outstanding packets have been received, `recv()` will return an error of kind
    /// [`io::ErrorKind::NotConnected`]. This behavior is consistent for both nonblocking and
    /// blocking modes of operation.
    ///
    /// **WARNING:** the above behavior is not yet guaranteed across operating systems--Linux, MacOS
    /// and FreeBSD correctly retain outstanding packets when `deactivate()` is called, whereas all
    /// other operating systems (Windows, other *BSD variants, Solaris/IllumOS) flush outstanding
    /// packets from their buffers on deactivation. This is due to fundamental limitations in the
    /// packet capture APIs available on these platforms. If/when this functionality is made
    /// available, the behavior and documentation of this method will be updated appropriately.
    ///
    pub fn deactivate(&mut self) -> io::Result<()> {
        self.sniffer.deactivate()
    }

    /// Indicates whether nonblocking I/O is enabled or disabled for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.sniffer.nonblocking()
    }

    /// Enables or disables nonblocking I/O for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.sniffer.set_nonblocking(nonblocking)
    }

    // TODO: `sendmsg`, `recvmsg` implementations that return additional data

    /// Send a packet out on the [`Interface`] the `Sniffer` is associated with.
    ///
    /// The structure of the packet depends on the link-type of the interface the `Sniffer` is
    /// sending packets out over.
    ///
    /// A `Sniffer` does not need to be activated (see [`activate()`](Self::activate)) to send
    /// packets.
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.sniffer.send(buf)
    }

    /// Receive a packet from the [`Interface`] the `Sniffer` is listening on.
    ///
    /// The `Sniffer` must be activated prior to receiving packets. Any attempt to receive a packet
    /// prior to first activating the `Sniffer` via a call to [`activate()`](Self::activate) will
    /// fail with an error of kind [`io::ErrorKind::NotConnected`].
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sniffer.recv(buf)
    }
}

impl Source for AsyncSniffer {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.io.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.io.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.io.deregister(registry)
    }
}

impl Drop for AsyncSniffer {
    fn drop(&mut self) {
        // This ensures that `UdpSocket` is dropped properly while not double-closing the RawFd.
        // SAFETY: `self.io` won't be accessed after this thanks to ManuallyDrop
        let io = unsafe { ManuallyDrop::take(&mut self.io) };
        let _ = io.into_raw_fd();
    }
}
