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

use std::ffi::CStr;
use std::io;

#[cfg(target_os = "linux")]
pub mod linux;

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
    /// The index of the interface.
    if_index: u32,
}

impl Interface {
    /// A special catch-all interface identifier that specifies all operational interfaces.
    pub const ALL: Self = Self { if_index: 0 };

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
    pub fn new(if_name: &str) -> io::Result<Self> {
        if if_name == "all" {
            return Ok(Self::ALL);
        }

        Self::new_raw(if_name.as_bytes())
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
        if if_name.len() >= 16 || if_name.contains(&0x00) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed interface name",
            ));
        }

        let mut if_cstr = [0u8; libc::IF_NAMESIZE];
        if_cstr.as_mut_slice()[..if_name.len()].copy_from_slice(if_name);

        match unsafe { libc::if_nametoindex(if_cstr.as_ptr() as *const i8) } {
            0 => Err(io::Error::last_os_error()),
            i => Ok(Interface { if_index: i }),
        }
    }

    /// Returns an `Interface` corresponding to the given interface index.
    ///
    /// # Errors
    ///
    /// Any returned error indicates that `if_index` does not correspond to a valid interface.
    #[inline]
    pub fn from_index(if_index: u32) -> io::Result<Self> {
        if if_index == 0 {
            return Ok(Self::ALL);
        }

        let iface = Interface { if_index };
        iface.name_raw()?; // Check to see if the device exists
        Ok(iface)
    }

    /// The raw index of the network interface.
    #[inline]
    pub fn index(&self) -> u32 {
        self.if_index
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
    pub fn name(&self) -> io::Result<String> {
        let mut name_bytes = [0u8; libc::IF_NAMESIZE];
        match unsafe { libc::if_indextoname(self.if_index, name_bytes.as_mut_ptr() as *mut i8) } {
            ptr if ptr.is_null() => Err(io::Error::last_os_error()),
            _ => Ok(CStr::from_bytes_until_nul(&name_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .to_str()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .to_string()),
        }
    }

    /// Returns the raw byte name associated with the given interface.
    ///
    /// # Errors
    ///
    /// Any returned error indicates that [`Interface`] does not correspond to a valid
    /// interface.
    pub fn name_raw(&self) -> io::Result<Vec<u8>> {
        let mut name_arr = [0u8; libc::IF_NAMESIZE];
        match unsafe { libc::if_indextoname(self.if_index, name_arr.as_mut_ptr() as *mut i8) } {
            ptr if ptr.is_null() => Err(io::Error::last_os_error()),
            _ => Ok(Vec::from_iter(name_arr.into_iter().take_while(|b| *b != 0))),
        }
    }
}

// Various platform-specific ways to get IPv4 + IPv6 interfaces:
// https://stackoverflow.com/questions/20743709/get-ipv6-addresses-in-linux-using-ioctl

// Linux:
// use glibc if_nametoindex, it uses netlink properly:
// https://github.com/bminor/glibc/blob/ae612c45efb5e34713859a5facf92368307efb6e/sysdeps/unix/sysv/linux/if_index.c
// or use getifaddrs; it likewise does netlink right:
// https://github.com/bminor/glibc/blob/ae612c45efb5e34713859a5facf92368307efb6e/sysdeps/unix/sysv/linux/ifaddrs.c

// OpenBSD:
// Supports IPv6 directly in calls to SIOCGIFCONF by mangling sockaddr ABI:
// https://man.openbsd.org/netintro.4

// Apple:
// Use getifaddrs:
// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
// (evidence it returns IPv6 addrs)
// https://developer.apple.com/forums/thread/660434

// FreeBSD:
// Likewise does some interesting ABI mangling behavior that should be watched out for:
// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=159099

// Note that libpcap only uses either getifaddrs (if available) or SIOCGIFCONF (if getifaddrs isn't available):
// https://github.com/the-tcpdump-group/libpcap/blob/fbcc461fbc2bd3b98de401cc04e6a4a10614e99f/fad-glifc.c
// https://github.com/the-tcpdump-group/libpcap/blob/fbcc461fbc2bd3b98de401cc04e6a4a10614e99f/fad-getad.c

// Some interfaces may only support certain packet families (that don't include AF_PACKET):
// https://stackoverflow.com/questions/19227781/linux-getting-all-network-interface-names
