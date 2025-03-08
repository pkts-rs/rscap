// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (Windows) npcap packet capture and transmission interface.
//!

// RSCAP_NPCAP_PATH:
// C:\Windows\System32\Npcap\Packet.dll
// Associated with Packet32.h

mod adapter;
mod dll;

use std::io;

use crate::filter::PacketFilter;
use crate::Interface;

pub use adapter::NpcapAdapter;

/// The mode of operation for the `npcap` adapter.
#[derive(Clone, Copy, Debug)]
pub enum NpcapMode {
    Capture,
    Statistic,
}

/// A timeout specifier for read operations on the `npcap` adapter.
#[derive(Clone, Copy, Debug)]
pub enum NpcapTimeout {
    /// A call to `read()` will return immediately if no packets are ready.
    Immediate,
    /// A call to `read()` will wait for up to the specified number of milliseconds for a packet
    /// to arrive before returning.
    Milliseconds(u32),
    /// Calls to `read()` will never time out
    None,
}

pub(crate) struct SnifferImpl {
    adapter: NpcapAdapter,
}

impl SnifferImpl {
    #[inline]
    pub fn new(iface: Interface) -> io::Result<Self> {
        let adapter = NpcapAdapter::new(iface)?;
        adapter.set_filter(&mut PacketFilter::reject_all())?;

        Ok(Self { adapter })
    }

    #[inline]
    pub fn activate(&mut self, filter: Option<PacketFilter>) -> io::Result<()> {
        self.adapter.flush()?;

        let mut filter = filter.unwrap_or(PacketFilter::reject_all());
        self.adapter.set_filter(&mut filter)
    }

    #[inline]
    pub fn deactivate(&mut self) -> io::Result<()> {
        self.adapter.set_filter(&mut PacketFilter::reject_all())
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.adapter.set_nonblocking(nonblocking);
        Ok(())
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        Ok(self.adapter.nonblocking())
    }

    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.adapter.send(buf)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.adapter.recv(buf)
    }
}

unsafe impl Send for SnifferImpl {}

unsafe impl Sync for SnifferImpl {}
