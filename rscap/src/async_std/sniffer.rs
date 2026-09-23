// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(target_os = "windows")]
use std::borrow::ToOwned;
use std::io;
#[cfg(target_os = "windows")]
use std::sync::Arc;

#[cfg(not(target_os = "windows"))]
use async_io::Async;

use crate::filter::PacketFilter;
use crate::{Interface, Sniffer};

#[cfg(target_os = "windows")]
#[derive(Clone)]
struct SnifferWrapper(Arc<Sniffer>);

#[cfg(target_os = "windows")]
impl SnifferWrapper {
    /// Returns a reference to the underlying `Sniffer` function.
    fn get_ref(&self) -> &Sniffer {
        self.0.as_ref()
    }

    /// Returns a reference to the underlying `Sniffer` function.
    unsafe fn get_mut(&mut self) -> &mut Sniffer {
        // SAFETY: we never use this within spawn_blocking or similar async contexts
        Arc::<Sniffer>::get_mut(&mut self.0).unwrap()
    }
}

/// A cross-platform asynchronous Sniffer interface, suitable for sending/receiving raw packets
/// over network interfaces in a manner compatible with `async-std`.
pub struct AsyncSniffer {
    #[cfg(not(target_os = "windows"))]
    sniffer: Async<Sniffer>,
    #[cfg(target_os = "windows")]
    sniffer: SnifferWrapper,
}

impl AsyncSniffer {
    /// Creates a new Sniffer for the given interface.
    #[inline]
    pub fn new(iface: Interface) -> io::Result<Self> {
        Self::new_impl(iface)
    }

    #[cfg(not(target_os = "windows"))]
    fn new_impl(iface: Interface) -> io::Result<Self> {
        let sniffer = Sniffer::new(iface)?;
        sniffer.set_nonblocking(true)?;

        Ok(Self {
            sniffer: Async::new(sniffer)?,
        })
    }

    #[cfg(target_os = "windows")]
    fn new_impl(iface: Interface) -> io::Result<Self> {
        let sniffer = Sniffer::new(iface)?;
        // Note: nonblocking mode should NOT be set here, as in Windows we spawn a new thread for each send()/recv()

        Ok(Self {
            sniffer: SnifferWrapper(Arc::new(sniffer)),
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
        unsafe { self.sniffer.get_mut().activate(filter) }
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
        unsafe { self.sniffer.get_mut().deactivate() }
    }

    /// Indicates whether nonblocking I/O is enabled or disabled for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.sniffer.get_ref().nonblocking()
    }

    /// Enables or disables nonblocking I/O for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.sniffer.get_ref().set_nonblocking(nonblocking)
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
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        self.sniffer.write_with(|inner| inner.send(buf)).await
    }

    #[cfg(target_os = "windows")]
    #[inline]
    async fn send_impl(&self, buf: &[u8]) -> io::Result<usize> {
        let arc = self.sniffer.clone();
        let buf = buf.to_owned();
        async_std::task::spawn_blocking(move || arc.get_ref().send(buf.as_slice())).await
    }

    /// Receive a packet from the [`Interface`] the `Sniffer` is listening on.
    ///
    /// The `Sniffer` must be activated prior to receiving packets. Any attempt to receive a packet
    /// prior to first activating the `Sniffer` via a call to [`activate()`](Self::activate) will
    /// fail with an error of kind [`io::ErrorKind::NotConnected`].
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_impl(buf).await
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sniffer.read_with(|inner| inner.recv(buf)).await
    }

    #[cfg(target_os = "windows")]
    pub async fn recv_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Prepare to share ownership of `Sniffer` with a blocking thread
        let arc = self.sniffer.clone();
        let buflen = buf.len();

        // Run `recv()` in a blocking thread
        let (res, data) = async_std::task::spawn_blocking(move || {
            let mut buf = vec![0; buflen];
            let res = arc.get_ref().recv(buf.as_mut_slice());
            (res, buf)
        })
        .await;

        // Copy data output from the blocking thread to `buf`
        match res {
            Ok(len) => {
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            err => err,
        }
    }
}
