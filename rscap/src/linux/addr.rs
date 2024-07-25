// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Link-layer address structures.
//!
//! Link-layer addresses may take different byte formats depending on the link-layer protocol in use.
//! To account for this, link-layer addresses are strongly coupled to protocol by defining distinct
//! address types for each link-layer protocol available. A generalized type of all of these possible
//! protocols is additionally made available as [`L2AddrAny`].

use std::array;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use crate::Interface;

use pkts_common::Buffer;

/// A link-layer protocol identifier.
///
/// This value corresponds directly to `libc::ETH_P_*` protocol specifier values.
pub type L2Protocol = i32;

/// Defines a generic link-layer address.
pub trait L2Addr: TryFrom<libc::sockaddr_ll> {
    /// The link-layer protocol associated with the address type.
    fn protocol(&self) -> L2Protocol;

    /// The interface packets are sent to or received from.
    fn interface(&self) -> Interface;

    /// Set the interface the packet is sent to or received from.
    ///
    /// This will only change the interface for the `L2Addr`, not for any socket the address was
    /// retrieved from. To change the interface of a socket, use `bind()`.
    fn set_interface(&mut self, iface: Interface);

    /// Constructs a [`sockaddr_ll`](libc::sockaddr_ll) struct from the given address.
    fn to_sockaddr(&self) -> libc::sockaddr_ll;
}

/// An error in converting the format of an address.
///
/// This type encompasses errors in parsing either a `sockaddr_*` type or a string into an address.
#[derive(Debug)]
pub struct AddrConversionError {
    reason: &'static str,
}

impl AddrConversionError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns a string describing the nature of the conversion error.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.reason
    }
}

/// A MAC (Media Access Control) address.
pub struct MacAddr {
    addr: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    #[inline]
    fn from(value: [u8; 6]) -> Self {
        Self { addr: value }
    }
}

impl From<MacAddr> for [u8; 6] {
    #[inline]
    fn from(value: MacAddr) -> Self {
        value.addr
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacAddress")
            .field(
                "addr",
                &format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    self.addr[0],
                    self.addr[1],
                    self.addr[2],
                    self.addr[3],
                    self.addr[4],
                    self.addr[5]
                ),
            )
            .finish()
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = AddrConversionError; // TODO: change to MacAddrParseError?

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        let mut addr_idx = 0;

        if let Some(delim @ (b':' | b'-')) = s.as_bytes().get(2) {
            // Hexadecimal separated by colons (XX:XX:XX:XX:XX:XX) or dashes (XX-XX-XX-XX-XX-XX)

            if s.bytes().len() != 17 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                let mod3_idx = idx % 3;
                if (mod3_idx) == 2 {
                    if b != *delim {
                        return Err(AddrConversionError::new(
                            "invalid character in MAC address: expected colon/dash",
                        ));
                    }
                    addr_idx += 1;
                } else {
                    b = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => 10 + (b - b'a'),
                        b'A'..=b'F' => 10 + (b - b'A'),
                        _ => {
                            return Err(AddrConversionError::new(
                                "invalid character in MAC address: expected hexadecimal value",
                            ))
                        }
                    };

                    if mod3_idx == 0 {
                        b <<= 4;
                    }

                    addr[addr_idx] |= b;
                }
            }
        } else if let Some(b'.') = s.as_bytes().get(4) {
            // Hexadecimal separated by dots (XXXX.XXXX.XXXX)

            if s.bytes().len() != 14 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                let mod5_idx = idx % 5;
                if (mod5_idx) == 4 {
                    if b != b'.' {
                        return Err(AddrConversionError::new("invalid character in MAC address: expected '.' after four hexadecimal values"));
                    }
                } else {
                    b = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => 10 + (b - b'a'),
                        b'A'..=b'F' => 10 + (b - b'A'),
                        _ => {
                            return Err(AddrConversionError::new(
                                "invalid character in MAC address: expected hexadecimal value",
                            ))
                        }
                    };

                    if mod5_idx & 0b1 == 0 {
                        // Evens, i.e. every first hex value in a byte
                        addr[addr_idx] = b << 4;
                    } else {
                        // Odds, i.e. every 2nd hex value
                        addr[addr_idx] |= b;
                        addr_idx += 1;
                    }
                }
            }
        } else {
            // Unseparated hexadecimal (XXXXXXXXXXXX)

            if s.bytes().len() != 12 {
                return Err(AddrConversionError::new("invalid length MAC address"));
            }

            for (idx, mut b) in s.bytes().enumerate() {
                b = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => 10 + (b - b'a'),
                    b'A'..=b'F' => 10 + (b - b'A'),
                    _ => {
                        return Err(AddrConversionError::new(
                            "invalid character in MAC address: expected hexadecimal value",
                        ))
                    }
                };

                let even_bit = (idx & 0b1) == 0;

                if even_bit {
                    // Evens, i.e. every first hex value in a byte
                    addr[addr_idx] = b << 4;
                } else {
                    // Odds, i.e. every 2nd hex value
                    addr[addr_idx] |= b;
                    addr_idx += 1;
                }
            }
        }

        Ok(Self { addr })
    }
}

/// A link-layer address corresponding to the `ETH_P_IP` protocol.
pub struct L2AddrIp {
    addr: MacAddr,
    iface: Interface,
}

impl TryFrom<libc::sockaddr_ll> for L2AddrIp {
    type Error = AddrConversionError;

    #[inline]
    fn try_from(value: libc::sockaddr_ll) -> Result<Self, Self::Error> {
        if value.sll_family != libc::AF_PACKET as u16 {
            return Err(AddrConversionError::new("invalid address family"));
        }

        if value.sll_protocol != libc::ETH_P_IP as u16 {
            return Err(AddrConversionError::new("unexpected address protocol"));
        }

        if value.sll_halen != 6 {
            return Err(AddrConversionError::new("invalid address length"));
        }

        let addr: [u8; 6] = array::from_fn(|i| value.sll_addr[i]);

        Ok(L2AddrIp {
            addr: MacAddr { addr },
            iface: Interface {
                if_index: value.sll_ifindex as u32,
            },
        })
    }
}

impl L2Addr for L2AddrIp {
    #[inline]
    fn protocol(&self) -> L2Protocol {
        libc::ETH_P_IP
    }

    #[inline]
    fn interface(&self) -> Interface {
        self.iface
    }

    #[inline]
    fn set_interface(&mut self, iface: Interface) {
        self.iface = iface;
    }

    fn to_sockaddr(&self) -> libc::sockaddr_ll {
        let sll_addr = array::from_fn(|i| *self.addr.addr.get(i).unwrap_or(&0));

        libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::ETH_P_IP as u16,
            sll_ifindex: self.iface.if_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr,
        }
    }
}

/// A type encompassing any Link-Layer address.
pub enum L2AddrAny {
    /// A link-layer address containing an Internet Protocol packet.
    Ip(L2AddrIp),
    /// Some other link-layer address type that does not have an explicit type defined.
    Other(L2AddrUnspec),
}

impl TryFrom<libc::sockaddr_ll> for L2AddrAny {
    type Error = AddrConversionError;

    #[inline]
    fn try_from(value: libc::sockaddr_ll) -> Result<Self, Self::Error> {
        Ok(match value.sll_protocol as i32 {
            libc::ETH_P_IP => Self::Ip(L2AddrIp::try_from(value)?),
            _ => Self::Other(L2AddrUnspec::try_from(value)?),
        })
    }
}

impl L2Addr for L2AddrAny {
    #[inline]
    fn protocol(&self) -> L2Protocol {
        match self {
            L2AddrAny::Ip(addr_ip) => addr_ip.protocol(),
            L2AddrAny::Other(addr_other) => addr_other.protocol(),
        }
    }

    #[inline]
    fn interface(&self) -> Interface {
        match self {
            L2AddrAny::Ip(addr_ip) => addr_ip.interface(),
            L2AddrAny::Other(addr_other) => addr_other.interface(),
        }
    }

    #[inline]
    fn set_interface(&mut self, iface: Interface) {
        match self {
            L2AddrAny::Ip(addr_ip) => addr_ip.set_interface(iface),
            L2AddrAny::Other(addr_other) => addr_other.set_interface(iface),
        }
    }

    #[inline]
    fn to_sockaddr(&self) -> libc::sockaddr_ll {
        match self {
            L2AddrAny::Ip(addr_ip) => addr_ip.to_sockaddr(),
            L2AddrAny::Other(addr_other) => addr_other.to_sockaddr(),
        }
    }
}

/// An unspecified link-layer address.
pub struct L2AddrUnspec {
    addr: Buffer<8>,
    iface: Interface,
    protocol: L2Protocol,
}

impl TryFrom<libc::sockaddr_ll> for L2AddrUnspec {
    type Error = AddrConversionError;

    fn try_from(value: libc::sockaddr_ll) -> Result<Self, Self::Error> {
        if value.sll_family != libc::AF_PACKET as u16 {
            return Err(AddrConversionError::new("invalid address family "));
        }

        let mut addr = Buffer::new();
        match value.sll_addr.get(..value.sll_halen as usize) {
            None => return Err(AddrConversionError::new("invalid address length")),
            Some(s) => addr.append(s),
        }

        Ok(L2AddrUnspec {
            addr,
            iface: Interface {
                if_index: value.sll_ifindex as u32,
            },
            protocol: value.sll_protocol as i32,
        })
    }
}

impl L2Addr for L2AddrUnspec {
    #[inline]
    fn protocol(&self) -> L2Protocol {
        self.protocol
    }

    #[inline]
    fn interface(&self) -> Interface {
        self.iface
    }

    #[inline]
    fn set_interface(&mut self, iface: Interface) {
        self.iface = iface;
    }

    fn to_sockaddr(&self) -> libc::sockaddr_ll {
        let sll_addr = array::from_fn(|i| *self.addr.as_slice().get(i).unwrap_or(&0));

        libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::ETH_P_IP as u16,
            sll_ifindex: self.iface.if_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr,
        }
    }
}
