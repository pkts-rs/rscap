// Copyright 2022 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Rust packet capture and manipulation utilities.

#[cfg(target_os = "linux")]
pub mod linux;

pub use pkts::*;

// 3 types: Sniffer, Spoofer and Socket
// Sniffer is read-only, Spoofer is write-only, Socket is RW

#[derive(Debug)]
pub struct RscapError {
    reason: &'static str,
}

pub struct Interface {
    if_name: [u8; libc::IF_NAMESIZE],
    /// The index of the interface. Meant to specify "all" when set to None
    if_index: u32,
}

impl Interface {
    #[inline]
    pub fn new(if_name: &str) -> Result<Self, RscapError> {
        Self::new_raw(if_name.as_bytes())
    }

    pub fn new_raw(if_name: &[u8]) -> Result<Self, RscapError> {
        if if_name.len() >= 16 && !(if_name.len() == 16 && if_name.contains(&0x00)) {
            return Err(RscapError {
                reason: "malformed interface name",
            }); // Interface name too long
        }

        let mut if_cstr = [0u8; libc::IF_NAMESIZE];
        if_cstr.as_mut_slice()[..if_name.len()].copy_from_slice(if_name);

        match unsafe { libc::if_nametoindex(if_cstr.as_ptr() as *const i8) } {
            0 => Err(RscapError {
                reason: "interface not found",
            }),
            i => Ok(Interface {
                if_name: if_cstr,
                if_index: i,
            }),
        }
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.if_index
    }

    #[inline]
    pub fn name(&self) -> &[u8] {
        for (idx, b) in self.if_name.iter().enumerate().rev() {
            if *b != 0 {
                return &self.if_name[..idx + 1];
            }
        }

        &[]
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
