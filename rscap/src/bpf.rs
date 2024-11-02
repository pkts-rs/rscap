// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (BSD/MacOS) Berkeley Packet Filter (BPF) packet capture and transmission interface.
//!
//! Note that this module is not for filtering packets, but rather for the `/dev/bpf` interface
//! used for packet capture. See the `filter` module for cross-platform filtering utilities,
//! including BPF programs.
//!

mod l2;

pub use l2::{Bpf, BpfAccess, BpfVersion};
#[cfg(any(doc, target_os = "freebsd"))]
pub use l2::{RxBlock, RxFrame, RxFrameIter, RxMappedBpf, RxRing};

use std::io;

use crate::{filter::PacketFilter, Interface};

#[cfg(target_os = "freebsd")]
pub const DEFAULT_DRIVER_BUFFER: usize = 2 * 1024 * 1024 * 1024; // Default each buffer of 1MB

pub(crate) struct SnifferImpl {
    #[cfg(not(target_os = "freebsd"))]
    bpf: Bpf,
    #[cfg(target_os = "freebsd")]
    bpf: RxMappedBpf,
}

impl SnifferImpl {
    #[inline]
    pub fn new(iface: Interface) -> io::Result<Self> {
        Self::new_impl(iface)
    }

    #[cfg(not(target_os = "freebsd"))]
    #[inline]
    fn new_impl(iface: Interface) -> io::Result<Self> {
        let bpf = Bpf::new(BpfAccess::ReadWrite)?;
        bpf.flush()?;
        bpf.bind(iface)?;

        Ok(Self { bpf })
    }

    #[cfg(target_os = "freebsd")]
    #[inline]
    fn new_impl(iface: Interface) -> io::Result<Self> {
        Self::new_with_size(iface, DEFAULT_DRIVER_BUFFER)
    }

    #[cfg(target_os = "freebsd")]
    #[inline]
    pub fn new_with_size(iface: Interface, ring_size: usize) -> io::Result<Self> {
        let bpf = Bpf::new(BpfAccess::ReadWrite)?;
        bpf.flush()?;
        bpf.bind(iface)?;

        Ok(Self {
            bpf: bpf.packet_rx_ring(ring_size / 2)?,
        })
    }

    #[inline]
    pub fn activate(&mut self, filter: Option<PacketFilter>) -> io::Result<()> {
        self.bpf.flush()?;

        let mut filter = filter.unwrap_or(PacketFilter::accept_all());
        self.bpf.set_filter(&mut filter)
    }

    #[inline]
    pub fn deactivate(&mut self) -> io::Result<()> {
        self.bpf.set_filter(&mut PacketFilter::reject_all())
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.bpf.nonblocking()
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.bpf.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.bpf.send(packet)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.bpf.recv(buf)
    }

    #[cfg(target_os = "freebsd")]
    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrameImpl<'_>> {
        Some(RxFrameImpl {
            frame: self.bpf.mapped_recv()?,
        })
    }
}

#[cfg(target_os = "freebsd")]
pub struct RxFrameImpl<'a> {
    frame: RxFrame<'a>,
}
