// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Rust packet capture and manipulation utilities.
//!
//!

// TODO:
// Packet sockets (`PF_PACKET`) are available in Solaris/IllumOS as well as Linux:
// https://docs.oracle.com/cd/E88353_01/html/E37851/pf-packet-4p.html
// https://www.illumos.org/opensolaris/ARChive/PSARC/2009/232/pfp-psarc.txt
//
// While neither support memory-mapped ring buffers (`PACKET_TX_RING`/`PACKET_RX_RING`),
// IllumOS *does* support attaching BPF programs to a packet socket:
// https://github.com/illumos/illumos-gate/blob/47ec9542e2cec788e0d0ff35e54ad5cef6f520d5/usr/src/uts/common/sys/socket.h#L155
//
// NOTE: Solaris and IllumOS both support /dev/bpf. Should probably just use that by default.

// NOTE: Fuschia OS likewise supports `/dev/bpf`.

// Show required OS/features on docs.rs.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(
    doc,
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
pub mod bpf;
// #[cfg(any(target_os = "illumos", target_os = "solaris"))]
// pub mod dlpi;
pub mod filter;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(any(doc, all(target_os = "windows", feature = "npcap")))]
pub mod npcap;
#[cfg(any(doc, target_os = "windows"))]
pub mod pktmon;

#[cfg(any(doc, not(target_os = "windows"), feature = "npcap"))]
mod sniffer;
mod utils;

#[cfg(any(doc, not(target_os = "windows"), feature = "npcap"))]
pub use sniffer::Sniffer;

use std::ffi::CStr;
use std::io;

#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::MAX_ADAPTER_NAME;

#[cfg(not(target_os = "windows"))]
const INTERNAL_MAX_INTERFACE_NAME_LEN: usize = libc::IF_NAMESIZE - 1;
#[cfg(target_os = "windows")]
const INTERNAL_MAX_INTERFACE_NAME_LEN: usize = MAX_ADAPTER_NAME as usize - 1;

// pub use pkts::*;

// Idea: 3 types--Sniffer, Spoofer and Socket
// Sniffer is read-only, Spoofer is write-only, Socket is RW

/// An identifier associated with a particular network device.
///
/// Network interfaces are not guaranteed to be static; network devices can be added and removed,
/// and in certain circumstances an interface that once pointed to one device may end up pointing
/// to another during the course of a program's lifetime.  Likewise, [`name()`](Interface::name())
/// and [`name_raw()`](Interface::name_raw()) aren't guaranteed to always return the same interface
/// name for a given interface, as the network device associated to that interface could change
/// between consecutive calls to `name()`/`name_raw()`.
///
/// In general, best practice is to use an `Interface` soon after constructing it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    /// The stored name of the interface.
    name: [u8; Self::MAX_INTERFACE_NAME_LEN + 1],
    is_catchall: bool,
}

impl Interface {
    const ANY: &'static [u8] = b"any\0";

    /// The maximum length (in bytes) that an interface name can be.
    ///
    /// Note that this value is platform-dependent. It determines the size of the buffer used for
    /// storing the interface name in an `Interface` instance, so the size of an `Interface` is
    /// likewise platform-dependent.
    pub const MAX_INTERFACE_NAME_LEN: usize = INTERNAL_MAX_INTERFACE_NAME_LEN;

    /// A special catch-all interface identifier that specifies all operational interfaces.
    pub fn any() -> io::Result<Self> {
        let mut name = [0u8; Self::MAX_INTERFACE_NAME_LEN + 1];
        name[..Self::ANY.len()].copy_from_slice(Self::ANY);

        Ok(Self {
            name,
            is_catchall: true,
        })
    }

    /// Returns an `Interface` corresponding to the given `if_name`, if such an interface exists.
    ///
    /// `if_name` must not consist of more than 15 bytes of UTF-8, and must not have any null
    /// characters.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if `if_name` is longer than 15 characters
    /// or contains a null byte.
    ///
    /// Otherwise, any returned error indicates that `if_name` does not correspond with a valid
    /// interface.
    #[inline]
    pub fn new(if_name: &CStr) -> io::Result<Self> {
        Self::new_raw(if_name.to_bytes())
    }

    /// Find all available interfaces on the given machine.
    pub fn find_all() -> io::Result<Vec<Self>> {
        todo!()
    }

    /// returns an `Interface` corresponding to the given `if_name`, if such an interface exists.
    ///
    /// `if_name` should consist of a sequence of up to 15 non-null byte characters. Any terminating
    /// null character must be removed prior to calling this method or it will fail.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if `if_name` is longer than 15 characters
    /// or contains a null byte.
    ///
    /// Otherwise, any returned error indicates that `if_name` does not correspond with a valid
    /// interface.
    pub fn new_raw(if_name: &[u8]) -> io::Result<Self> {
        if if_name.len() > Self::MAX_INTERFACE_NAME_LEN || if_name.contains(&0x00) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed interface name",
            ));
        }

        let mut name = [0u8; Self::MAX_INTERFACE_NAME_LEN + 1];
        name[..if_name.len()].copy_from_slice(if_name);

        let interface = Interface {
            name,
            is_catchall: false,
        };

        // If we can, check to see if the interface is valid
        #[cfg(not(target_os = "windows"))]
        interface.index()?;

        Ok(interface)
    }

    /// Returns an `Interface` corresponding to the given interface index.
    ///
    /// # Errors
    ///
    /// Any returned error indicates that `if_index` does not correspond to a valid interface.
    #[inline]
    #[cfg(not(target_os = "windows"))]
    pub fn from_index(if_index: u32) -> io::Result<Self> {
        // TODO: do systems other than Linux actually consider '0' to be a catchall?
        if if_index == 0 {
            return Self::any();
        }

        let mut name = [0u8; Self::MAX_INTERFACE_NAME_LEN + 1];
        match unsafe { libc::if_indextoname(if_index, name.as_mut_ptr() as *mut i8) } {
            ptr if ptr.is_null() => Err(io::Error::last_os_error()),
            _ => Ok(Self {
                name,
                is_catchall: false,
            }),
        }
    }

    /// The raw index of the network interface.
    #[inline]
    #[cfg(not(target_os = "windows"))]
    pub fn index(&self) -> io::Result<u32> {
        if self.is_catchall {
            return Ok(0);
        }

        match unsafe { libc::if_nametoindex(self.name.as_ptr() as *const i8) } {
            0 => Err(io::Error::last_os_error()),
            i => Ok(i),
        }
    }

    /// Returns the name associated with the given interface.
    ///
    /// # Errors
    ///
    /// Returns [InvalidData](io::ErrorKind::InvalidData) if the name assigned to the interface is
    /// not valid UTF-8.
    ///
    /// Otherwise, a returned error indicates that [`Interface`] does not correspond to a valid
    /// interface.
    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.name.as_ptr() as *const i8) }
    }

    /// Returns the raw byte name associated with the given interface.
    ///
    /// The returned byte slice contains a single null-terminating character at the end of the slice.
    pub fn name_raw(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .enumerate()
            .find(|(_, c)| **c == b'\0')
            .unwrap()
            .0;
        &self.name[..end + 1]
    }

    #[cfg(any(doc, target_os = "linux"))]
    pub fn arp_type(&self) -> io::Result<u16> {
        use std::ptr;

        let mut ifr = libc::ifreq {
            ifr_name: std::array::from_fn(|i| self.name[i] as i8),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_hwaddr: libc::sockaddr {
                    sa_family: 0,
                    sa_data: [0; 14],
                },
            },
        };

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, ptr::addr_of_mut!(ifr)) } < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        unsafe {
            libc::close(fd);
            Ok(ifr.ifr_ifru.ifru_hwaddr.sa_family)
        }
    }

    // See https://github.com/the-tcpdump-group/libpcap/blob/afa58de01aba5b7f971b1f8d72a1fc5b5fd514e4/pcap-linux.c#L1868
    #[cfg(target_os = "linux")]
    #[inline]
    pub fn datalink_type(&self) -> io::Result<u16> {
        match self.arp_type()? {
            // TODO: Android incorrectly assigns ARPHRD_ETHER to some interfaces
            libc::ARPHRD_ETHER => todo!(), // DLT_EN10MB
            _ => todo!(),
        }
    }
}
