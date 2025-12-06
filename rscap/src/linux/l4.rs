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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem, ptr};

use crate::Interface;

use super::addr::L2Protocol;
use super::l3::L3Socket;

pub struct L4Route {
    pub protocol: L4Protocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Debug)]
pub enum L4Protocol {
    Icmp,
    Igmp,
    Ipip,
    Tcp,
    Udp,
    Dccp,
    Esp,
    Ah,
    Sctp,
    UdpLite,
    /// A custom protocol number.
    Custom(u8),
}

impl L4Protocol {
    fn value(&self) -> u8 {
        match self {
            L4Protocol::Icmp => 1,
            L4Protocol::Igmp => 2,
            L4Protocol::Ipip => 4,
            L4Protocol::Tcp => 6,
            L4Protocol::Udp => 17,
            L4Protocol::Dccp => 33,
            L4Protocol::Esp => 50,
            L4Protocol::Ah => 51,
            L4Protocol::Sctp => 132,
            L4Protocol::UdpLite => 136,
            L4Protocol::Custom(val) => *val,
        }
    }
}

/// A filter on the protocol, addresses and ports (where applicable) of packets to be sniffed.
#[derive(Clone, Debug)]
pub enum L4ProtocolFilter {
    /// Internet Control Message Protocol
    Icmp(NetworkPath),
    /// Internet Group Management Protocol
    Igmp(NetworkPathV4),
    /// IPIP tunnels
    Ipip(NetworkPathV4),
    /// Transmission Control Protocol
    Tcp(TransportPath),
    /// User Datagram Protocol
    Udp(TransportPath),
    /// Datagram Congestion Control Protocol (RFC 4340)
    Dccp(TransportPath),
    /// Encapsulation Security Payload protocol
    Esp(NetworkPath),
    /// Authentication Header protocol
    Ah(NetworkPath),
    /// Stream Control Transmission Protocol
    Sctp(TransportPath),
    /// UDP-Lite (RFC 3828)
    UdpLite(TransportPath),
    /// A custom arbitrary protocol number.
    Custom(u8, NetworkPath),
    /// Any protocol number.
    /// 
    /// Note: if either of `local_port` or `remote_port` are not `None`, this option will only
    /// include traffic from protocols that specify port numbers (i.e., TCP, UDP, DCCP, SCTP,
    /// and UDP-Lite).
    Any(TransportPath),
}

impl L4ProtocolFilter {
    fn protocol(&self) -> Option<L4Protocol> {
        match self {
            L4ProtocolFilter::Icmp(_) => Some(L4Protocol::Icmp),
            L4ProtocolFilter::Igmp(_) => Some(L4Protocol::Igmp),
            L4ProtocolFilter::Ipip(_) => Some(L4Protocol::Ipip),
            L4ProtocolFilter::Tcp(_) => Some(L4Protocol::Tcp),
            L4ProtocolFilter::Udp(_) => Some(L4Protocol::Udp),
            L4ProtocolFilter::Dccp(_) => Some(L4Protocol::Dccp),
            L4ProtocolFilter::Esp(_) => Some(L4Protocol::Esp),
            L4ProtocolFilter::Ah(_) => Some(L4Protocol::Ah),
            L4ProtocolFilter::Sctp(_) => Some(L4Protocol::Sctp),
            L4ProtocolFilter::UdpLite(_) => Some(L4Protocol::UdpLite),
            L4ProtocolFilter::Custom(value, _) => Some(L4Protocol::Custom(*value)),
            L4ProtocolFilter::Any(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum NetworkPath {
    V4(NetworkPathV4),
    V6(NetworkPathV6),
    /// Captures traffic across all source and destination addresses for both protocols.
    Any,
}

impl NetworkPath {
    pub const ANY: NetworkPath = NetworkPath::Any;
}

#[derive(Clone, Debug)]
pub enum PathDirection {
    /// Only captures traffic for which `remote` is the source and `local` is the destination.
    Incoming,
    /// Only captures traffic for which `local` is the source and `remote` is the destination.
    Outgoing,
    /// Only captures traffic in both directions between `local` and `remote`.
    Bidirectional,
}

#[derive(Clone, Debug)]
pub struct NetworkPathV4 {
    pub local: Option<Ipv4Addr>,
    pub remote: Option<Ipv4Addr>,
    pub direction: PathDirection,
}

impl NetworkPathV4 {
    pub const ANY: NetworkPathV4 = NetworkPathV4 {
        local: None,
        remote: None,
        direction: PathDirection::Bidirectional,
    };
}

#[derive(Clone, Debug)]
pub struct NetworkPathV6 {
    pub local: Option<Ipv6Addr>,
    pub remote: Option<Ipv6Addr>,
    pub direction: PathDirection,
}

impl NetworkPathV6 {
    pub const ANY: NetworkPathV6 = NetworkPathV6 {
        local: None,
        remote: None,
        direction: PathDirection::Bidirectional,
    };
}

#[derive(Clone, Debug)]
pub enum TransportPath {
    V4(TransportPathV4),
    V6(TransportPathV6),
    Any(TransportPathAny),
}

impl TransportPath {
    pub const ANY: TransportPath = TransportPath::Any(TransportPathAny {
        local_port: None,
        remote_port: None,
        direction: PathDirection::Bidirectional,
    });
}

impl From<NetworkPath> for TransportPath {
    fn from(value: NetworkPath) -> Self {
        match value {
            NetworkPath::V4(v4) => Self::V4(v4.into()),
            NetworkPath::V6(v6) => Self::V6(v6.into()),
            NetworkPath::Any => Self::ANY,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportPathV4 {
    pub local_addr: Option<Ipv4Addr>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<Ipv4Addr>,
    pub remote_port: Option<u16>,
    pub direction: PathDirection,
}

impl From<NetworkPathV4> for TransportPathV4 {
    fn from(value: NetworkPathV4) -> Self {
        Self {
            local_addr: value.local,
            local_port: None,
            remote_addr: value.remote,
            remote_port: None,
            direction: value.direction,
        }
    }
}

impl TransportPathV4 {
    pub const ANY: TransportPathV4 = TransportPathV4 {
        local_addr: None,
        local_port: None,
        remote_addr: None,
        remote_port: None,
        direction: PathDirection::Bidirectional,
    };
}

#[derive(Clone, Debug)]
pub struct TransportPathV6 {
    pub local_addr: Option<Ipv6Addr>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<Ipv6Addr>,
    pub remote_port: Option<u16>,
    pub direction: PathDirection,
}

impl TransportPathV6 {
    pub const ANY: TransportPathV6 = TransportPathV6 {
        local_addr: None,
        local_port: None,
        remote_addr: None,
        remote_port: None,
        direction: PathDirection::Bidirectional,
    };
}

impl From<NetworkPathV6> for TransportPathV6 {
    fn from(value: NetworkPathV6) -> Self {
        Self {
            local_addr: value.local,
            local_port: None,
            remote_addr: value.remote,
            remote_port: None,
            direction: value.direction,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportPathAny {
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub direction: PathDirection,
}

/*
From https://sock-raw.org/papers/sock_raw

FreeBSD takes another approach. It *never* passes TCP or UDP packets to raw
sockets. Such packets need to be read directly at the datalink layer by using
libraries like libpcap or the bpf API. It also *never* passes any fragmented 
datagram. Each datagram has to be completeley reassembled before it is passed
to a raw socket.
FreeBSD passes to a raw socket:
	a) every IP datagram with a protocol field that is not registered in
	the kernel
	b) all IGMP packets after kernel finishes processing them
	c) all ICMP packets (except echo request, timestamp request and address
	mask request) after kernel finishes processes them
*/

/// A socket that exchanges packets at the transport layer.
///
/// In Linux, this loosely corresponds to `socket(AF_INET, SOCK_RAW, proto)`, though in practice
/// it is actually implemented with an L3 socket and specific BPF rules.
pub struct L4Socket {
    socket: L3Socket,
    local: Option<IpAddr>,
    remote: Option<IpAddr>,
    protocol: Option<L4Protocol>,
}

impl L4Socket {
    /// Create a new transport-layer socket.
    ///
    /// By default, transport-layer sockets do not listen or receive packets on any protocol or
    /// interface; to begin receiving packets, call [`bind()`](L4Socket::bind()).
    ///
    /// # Permissions
    ///
    /// A program must have the `CAP_NET_RAW` capability in order for this call to succeed;
    /// otherwise, `EPERM` will be returned.
    #[inline]
    pub fn new() -> io::Result<L4Socket> {
        Ok(Self {
            socket: L3Socket::new()?,
            local: None,
            remote: None,
            protocol: None,
        })
    }

    /// Sets the transport-layer socket to capture packets
    pub fn bind(&self, iface: Interface, filter: L4ProtocolFilter) -> io::Result<()> {
        
        


        self.socket.bind(iface, L2Protocol::Ipv4)
    }

    /// Sets the transport-layer socket to capture packets from all interfaces.
    pub fn bind_all(&self, filter: L4ProtocolFilter) -> io::Result<()> {
        let ip_addr = addr.ip();
        let port = addr.port();

        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_addr: libc::in_addr {
                s_addr: u32::from_le_bytes(ip_addr.octets()), // TODO: check endianness of this
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

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    ///
    /// This method will fail if the socket has not been bound to an address (i.e., via
    /// [`bind()`](L4Socket::bind())).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            sent => Ok(sent as usize),
        }
    }

    /// Receive a datagram from the socket.
    ///
    /// This method will fail if the socket has not been bound  to an address (i.e., via
    /// [`bind()`](L4Socket::bind())).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// Send a datagram via the specified route.
    pub fn send_to(
        &self,
        buf: &[u8],
        route: L4Route,
    ) -> io::Result<usize> {
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: rem_addr.port(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes(rem_addr.ip().octets()), // TODO: endianness?
            },
            sin_zero: [0u8; 8],
        };

        let addrlen = mem::size_of_val(&sockaddr) as u32;

        match unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *mut libc::c_void,
                buf.len(),
                flags.bits(),
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                addrlen,
            )
        } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// Receive a datagram from the socket.
    pub fn recv_from(&self, buf: &[u8]) -> io::Result<(usize, L4Route)> {
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0u8; 8],
        };

        let addrlen = mem::size_of_val(&sockaddr) as u32;

        match unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *mut libc::c_void,
                buf.len(),
                flags.bits(),
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                addrlen,
            )
        } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => {
                let rem_addr = SocketAddrV4::new(
                    Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_be_bytes()), // TODO: endianness?
                    sockaddr.sin_port,
                );
                Ok((recvd as usize, rem_addr))
            }
        }
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.socket.nonblocking()
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }
}

impl AsRawFd for L4Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_localhost() {
        let sock = L4Socket::new(L4Protocol::Udp).unwrap();
        sock.bind(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 777))
            .unwrap();
    }
}
