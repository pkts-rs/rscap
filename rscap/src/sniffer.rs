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
#[cfg(doc)]
use std::marker::PhantomData;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, RawFd};

#[cfg(target_os = "openbsd")]
use crate::bpf::RxFrameImpl;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
use crate::bpf::SnifferImpl;
/*
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
use crate::dlpi::SnifferImpl;
*/
#[cfg(target_os = "linux")]
use crate::linux::{RxFrameImpl, SnifferImpl};
#[cfg(all(target_os = "windows", feature = "npcap"))]
use crate::npcap::SnifferImpl;
use crate::{filter::PacketFilter, Interface};
// TODO: add pktmon here

// Linux doesn't start capturing packets by default until bind() is called.
// Both npcap and BPF do.
// We need to handle this edge case.

// BIOCFLUSH - flushes BPF
// BIOCSETFNR - sets filter without flushing BPF
// NPF_ResetBufferContents
//
// SO_ATTACH_FILTER doesn't flush BPF

/// A device capable of transmitting and receiving arbitrary link-layer (i.e., L2) packets.
///
/// This device is specifically capable of transmitting a link-layer packet composed of arbitrary
/// (including potentially invalid) bytes, as well as receiving all packets passing _in either
/// direction_ through a given network interface (including those being transmitted by the device
/// itself).
pub struct Sniffer {
    #[cfg(not(doc))]
    inner: SnifferImpl,
}

impl Sniffer {
    /// Creates a new Sniffer instance.
    ///
    /// The sniffer will not capture new packets by default until [`activate()`](Self::activate)
    /// is called.
    #[inline]
    pub fn new(iface: Interface) -> io::Result<Self> {
        Ok(Self {
            inner: SnifferImpl::new(iface)?,
        })
    }

    /// Creates a new sniffer instance using `ring_size` for the size of any zero-copy RX or TX
    /// rings.
    ///
    /// `ring_size` must be a multiple of 524288 (0x80000, or 512 KiB) to work across relevant
    /// platforms (currently Linux and FreeBSD).
    #[cfg(any(doc, target_os = "freebsd", target_os = "linux"))]
    #[inline]
    pub fn new_with_size(iface: Interface, ring_size: usize) -> io::Result<Self> {
        Ok(Self {
            inner: SnifferImpl::new_with_size(iface, ring_size)?,
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
        // This method needs to:
        // 1. flush the buffer of any pending packets from a previous call to `deactivate()`
        // 2. Set the BPF to the one provided, or else `ret 1`
        self.inner.activate(filter)
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
        self.inner.deactivate()
    }

    // TODO: ^ since Solaris/IllumOS support PF_PACKET, it's actually the case that they *will*

    /// Indicates whether nonblocking I/O is enabled or disabled for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    #[inline]
    pub fn nonblocking(&mut self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    /// Enables or disables nonblocking I/O for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Send a packet out on the [`Interface`] the `Sniffer` is associated with.
    ///
    /// The structure of the packet depends on the link-type of the interface the `Sniffer` is
    /// sending packets out over.
    ///
    /// A `Sniffer` does not need to be activated (see [`activate()`](Self::activate)) to send
    /// packets.
    #[inline]
    pub fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.inner.send(packet)
    }

    // TODO: `sendmsg`, `recvmsg` implementations that return additional data

    /// Receive a packet from the [`Interface`] the `Sniffer` is listening on.
    ///
    /// The `Sniffer` must be activated prior to receiving packets. Any attempt to receive a packet
    /// prior to first activating the `Sniffer` via a call to [`activate()`](Self::activate) will
    /// fail with an error of kind [`io::ErrorKind::NotConnected`].
    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf)
    }

    /// Receive a zero-copy packet from the [`Interface`] the `Sniffer` is listening on.
    ///
    /// The `Sniffer` must be activated prior to receiving packets. Any attempt to receive a packet
    /// prior to first activating the `Sniffer` via a call to [`activate()`](Self::activate) will
    /// fail with an error of kind [`io::ErrorKind::NotConnected`].
    #[cfg(any(doc, target_os = "linux", target_os = "freebsd"))]
    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrame<'_>> {
        Some(RxFrame {
            inner: self.inner.mapped_recv()?,
        })
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for Sniffer {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

/// A packet frame holding a single received zero-copy packet.
#[cfg(any(doc, target_os = "linux", target_os = "freebsd"))]
pub struct RxFrame<'a> {
    #[cfg(not(doc))]
    inner: RxFrameImpl<'a>,
    #[cfg(doc)]
    _phantom: PhantomData<&'a ()>,
}

#[cfg(any(doc, target_os = "linux", target_os = "freebsd"))]
impl RxFrame<'_> {
    /// A slice to the underlying zero-copy packet.
    ///
    /// Once a packet is finished with, simply dropping the `RxFrame` will lead to the packet frame
    /// being correctly marked for the kernel to use for future packets.
    pub fn data(&self) -> &[u8] {
        self.inner.data()
    }

    /// A mutable slice to the underlying zero-copy packet.
    ///
    /// Any desired modifications may be performed on the packet safely; once a packet is finished
    /// with, simply dropping the `RxFrame` will lead to the packet frame being correctly marked
    /// for the kernel to use for future packets.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.inner.data_mut()
    }

    // TODO: any way to unify `bpf_ts` and the PACKET_RX_RING timestamps??
}
