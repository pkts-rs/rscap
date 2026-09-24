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

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem, ptr};

use super::sndrcv::{RecvFlags, SendFlags};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Protocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Internet Control Message Protocol
    Icmp,
    /// Stream Control Transmission Protocol
    Sctp,
    /// Datagram Congestion Control Protocol (RFC 4340)
    Dccp,
    /// A custom-chosen protocol number. Must not be IPPROTO_RAW (0xff).
    Custom(u8),
}

/// A socket that exchanges packets at the transport layer.
///
/// In Linux, this corresponds to `socket(AF_INET, SOCK_RAW, proto)`.
pub struct L4Socket {
    fd: i32,
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
    pub fn new(protocol: L4Protocol) -> io::Result<L4Socket> {
        let protocol = match protocol {
            L4Protocol::Dccp => libc::IPPROTO_DCCP,
            L4Protocol::Icmp => libc::IPPROTO_ICMP,
            L4Protocol::Sctp => libc::IPPROTO_SCTP,
            L4Protocol::Tcp => libc::IPPROTO_TCP,
            L4Protocol::Udp => libc::IPPROTO_UDP,
            L4Protocol::Custom(protocol) => {
                if protocol == libc::IPPROTO_RAW as u8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "IPPROTO_RAW not supported for L4Socket",
                    ));
                }
                protocol as i32
            }
        };

        // Set the socket to receive no packets by default (protocol: 0)
        match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol) } {
            ..=-1 => Err(std::io::Error::last_os_error()),
            fd => Ok(L4Socket { fd }),
        }
    }

    /// Bind the transport-layer socket to only capture packets being received by the specified
    /// address.
    pub fn bind(&self, addr: &SocketAddrV4) -> io::Result<()> {
        let ip_addr = addr.ip().to_bits();
        let port = addr.port();

        let ip_filter = unsafe {
            [
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 12),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    ip_addr,
                    0,
                    1,
                ),
                libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, 0xFFFF),
                libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, 0),
            ]
        };
        let ip_port_filter = unsafe {
            [
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 12),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    ip_addr,
                    0,
                    4,
                ),
                libc::BPF_STMT((libc::BPF_LDX | libc::BPF_MSH | libc::BPF_B) as u16, 0),
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_H | libc::BPF_IND) as u16, 0),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    port as u32,
                    0,
                    1,
                ),
                libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, 0xFFFF),
                libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, 0),
            ]
        };

        let filter = if port == 0 {
            ip_filter.as_slice()
        } else {
            ip_port_filter.as_slice()
        };

        let bpf_program = libc::sock_fprog {
            len: filter.len() as libc::c_ushort,
            filter: filter.as_ptr().cast_mut(),
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&raw const bpf_program).cast(),
                mem::size_of_val(&bpf_program) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Restrict transport-layer socket to only capture packets being sent by the specified remote
    /// address.
    pub fn connect(&self, addr: SocketAddrV4) -> io::Result<()> {
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

        match unsafe {
            libc::connect(
                self.fd,
                (&raw const sockaddr).cast(),
                mem::size_of_val(&sockaddr) as libc::socklen_t,
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
        match unsafe { libc::send(self.fd, buf.as_ptr().cast(), buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            sent => Ok(sent as usize),
        }
    }

    /// Receive a datagram from the socket.
    ///
    /// This method will fail if the socket has not been bound  to an address (i.e., via
    /// [`bind()`](L4Socket::bind())).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// Send a datagram to the specified IPv4 address.
    pub fn send_to(
        &self,
        buf: &[u8],
        rem_addr: SocketAddrV4,
        flags: SendFlags,
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
    pub fn recv_from(&self, buf: &[u8], flags: RecvFlags) -> io::Result<(usize, SocketAddrV4)> {
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
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(flags & libc::O_NONBLOCK > 0)
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut fcntl_flags = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            ..=-1 => return Err(io::Error::last_os_error()),
            f => f,
        };

        if nonblocking {
            fcntl_flags |= libc::O_NONBLOCK;
        } else {
            fcntl_flags &= !libc::O_NONBLOCK;
        }

        match unsafe { libc::fcntl(self.fd, libc::F_SETFL, fcntl_flags) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl AsRawFd for L4Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    // use std::net::UdpSocket;
    // use std::process::Command;

    use super::*;

    #[test]
    fn bind_localhost() {
        let sock = L4Socket::new(L4Protocol::Udp).unwrap();
        sock.bind(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 777))
            .unwrap();
    }

    /*
    #[test]
    fn bind_localhost_recv() {
        let _ = Command::new("modprobe").arg("dummy").output();
        let _ = Command::new("ip").args(["link", "delete", "dummy0"]).output();
        Command::new("ip").args(["link", "add", "dummy0", "type", "dummy"]).output().unwrap();
        Command::new("ip").args(["addr", "add", "10.0.0.1/24", "dev", "dummy0"]).output().unwrap();
        Command::new("ip").args(["link", "set", "dummy0", "up"]).output().unwrap();

        let sock = L4Socket::new(L4Protocol::Udp).unwrap();
        sock.bind(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5543))
            .unwrap();

        let udp2 = UdpSocket::bind("127.0.0.1:5567").unwrap();

        let pkt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        udp2.send_to(pkt.as_slice(), "10.0.0.1:5543").unwrap();

        let mut buf = [0u8; 1024];
        let len = sock.recv(&mut buf).unwrap();

        assert!(len > 8);
        assert_eq!(&buf[len - 8..len], pkt.as_slice());

        drop(udp2);

        Command::new("ip").args(["link", "delete", "dummy0"]).output().unwrap();
    }
    */
}
