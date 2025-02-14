// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Network-layer packet capture/transmission utilities.
//!

use std::{io, mem, os::fd::AsRawFd, ptr};

use super::addr::{L2Addr, L2Protocol};
use super::mapped::{
    BlockConfig, FrameIndex, OsiLayer, PacketRxRing, PacketTxRing, RxFrame, TxFrame, TxFrameVariant,
};
use super::{FanoutAlgorithm, RxTimestamping, TxTimestamping};

use crate::filter::PacketStatistics;
use crate::Interface;

/// A socket that exchanges packets at the network layer.
///
/// In Linux, this corresponds to `socket(AF_PACKET, SOCK_RAW, 0)`.
pub struct L3Socket {
    fd: i32,
}

impl L3Socket {
    /// Create a new network-layer socket.
    ///
    /// By default, network-layer sockets do not listen or receive packets on any protocol or
    /// interface; to begin receiving packets, call [`bind()`](L3Socket::bind()).
    ///
    /// # Permissions
    ///
    /// A program must have the `CAP_NET_RAW` capability in order for this call to succeed;
    /// otherwise, `EPERM` will be returned.
    #[inline]
    pub fn new() -> io::Result<L3Socket> {
        // Set the socket to receive no packets by default (protocol: 0)
        match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, 0) } {
            ..=-1 => Err(std::io::Error::last_os_error()),
            fd => Ok(L3Socket { fd }),
        }
    }

    /// Bind the network-layer socket to a particular protocol/address and interface and begin
    /// receiving packets.
    ///
    /// The address type can be any implementor of the [`L2Addr`] trait. For concrete examples,
    /// refer to its documentation.
    pub fn bind(&self, iface: Interface, proto: L2Protocol) -> io::Result<()> {
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: u16::from(proto),
            sll_ifindex: iface.index()? as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0u8; 8],
        };

        // SAFETY: `ptr::addr_of!(sockaddr_ll)` will always yield a pointer to
        // `mem::size_of::<libc::sockaddr_ll>()` valid bytes.
        match unsafe {
            libc::bind(
                self.fd,
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Binds the device to all interfaces, enabling it to begin receiving packets matching the
    /// link-layer protocol `proto`.
    pub fn bind_all(&self, proto: L2Protocol) -> io::Result<()> {
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: u16::from(proto),
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0u8; 8],
        };

        // SAFETY: `ptr::addr_of!(sockaddr_ll)` will always yield a pointer to
        // `mem::size_of::<libc::sockaddr_ll>()` valid bytes.
        match unsafe {
            libc::bind(
                self.fd,
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Moves the network-layer socket's behavior in or out of blocking mode.
    ///
    /// An [`L3Socket`] that is nonblocking will return with an error of kind
    /// [WouldBlock](io::ErrorKind::WouldBlock) whenever a packet cannot be immediately sent or
    /// received. This is only applicable to the [`send()`](L3Socket::send()) or
    /// [`recv()`](L3Socket::recv()) methods; any memory-mapped methods are always guaranteed to be
    /// nonblocking.
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

    /// Configures transmitted packets to bypass kernel's traffic control (qdisc) layer.
    ///
    /// This allows packet buffering at the qdisc layer to be avoided, which is useful for
    /// applications that intend to intentionally flood a network with traffic. Enabling this option
    /// will lead to increased packet drops in transmission when network devices are busy (as the
    /// kernel will not be buffering packets originating from the socket).
    ///
    /// This option is disabled (`false`) by default.
    pub fn set_qdisc_bypass(&self, bypass: bool) -> io::Result<()> {
        let bypass_req = if bypass { 1u32 } else { 0u32 };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_QDISC_BYPASS,
                ptr::addr_of!(bypass_req) as *const libc::c_void,
                mem::size_of::<u32>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Returns packet statistics about the current socket.
    ///
    /// Packet statistics include [`received`](PacketStatistics::received) and
    /// [`dropped`](PacketStatistics::dropped) packet counts; both of these counters are reset
    /// each time this method is called.
    pub fn packet_stats(&self) -> io::Result<PacketStatistics> {
        let mut stats = crate::linux::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };

        let mut stats_len = mem::size_of::<crate::linux::tpacket_stats>() as u32;

        if unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_STATISTICS,
                ptr::addr_of_mut!(stats) as *mut libc::c_void,
                ptr::addr_of_mut!(stats_len),
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }
        debug_assert!(stats_len == mem::size_of::<crate::linux::tpacket_stats>() as u32);

        Ok(PacketStatistics {
            received: stats.tp_packets,
            dropped: stats.tp_drops,
        })
    }

    /// Returns the interface that the socket is currently sniffing on.
    pub fn interface(&self) -> io::Result<Interface> {
        let mut sockaddr = libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };
        let mut sockaddr_len = mem::size_of::<libc::sockaddr_ll>() as u32;

        let res = unsafe {
            libc::getsockname(
                self.fd,
                ptr::addr_of_mut!(sockaddr) as *mut libc::sockaddr,
                ptr::addr_of_mut!(sockaddr_len),
            )
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        if sockaddr_len != mem::size_of::<libc::sockaddr_ll>() as u32
            || sockaddr.sll_family != libc::AF_PACKET as u16
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "bound address was not of type sockaddr_ll",
            ));
        }

        Interface::from_index(sockaddr.sll_ifindex as u32)
    }

    /// Determines the source of timestamp information for TX_RING/RX_RING packets.
    /// If `true`, this option requests that the operating system use hardware timestamps
    /// provided by the NIC.
    ///
    /// For hardware timestamping to be employed, the socket must be bound to a specific interface.
    ///
    /// # Errors
    ///
    /// `ERANGE` - the requested packets cannot be timestamped by hardware.
    ///
    /// `EINVAL` - hardware timestamping is not supported by the network card.
    fn set_timestamp_method(&self, tx: TxTimestamping, rx: RxTimestamping) -> io::Result<()> {
        if tx == TxTimestamping::Hardware || rx == RxTimestamping::Hardware {
            let mut hwtstamp_config = libc::hwtstamp_config {
                flags: 0,
                tx_type: if tx == TxTimestamping::Hardware {
                    libc::HWTSTAMP_TX_ON
                } else {
                    libc::HWTSTAMP_TX_OFF
                } as i32,
                rx_filter: if rx == RxTimestamping::Hardware {
                    libc::HWTSTAMP_FILTER_ALL
                } else {
                    libc::HWTSTAMP_FILTER_NONE
                } as i32,
            };

            let iface = self.interface()?;

            let mut if_name = [0i8; libc::IF_NAMESIZE];
            let if_name_ptr = if_name.as_mut_ptr();

            let res = unsafe { libc::if_indextoname(iface.index()?, if_name_ptr) };
            if res.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut ifreq = libc::ifreq {
                ifr_name: if_name,
                ifr_ifru: libc::__c_anonymous_ifr_ifru {
                    ifru_data: ptr::addr_of_mut!(hwtstamp_config) as *mut i8,
                },
            };

            let res =
                unsafe { libc::ioctl(self.fd, libc::SIOCSHWTSTAMP, ptr::addr_of_mut!(ifreq)) };
            if res != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let timestamp_req = match tx {
            TxTimestamping::Hardware => libc::SOF_TIMESTAMPING_TX_HARDWARE,
            TxTimestamping::Software => libc::SOF_TIMESTAMPING_TX_SOFTWARE,
            TxTimestamping::Sched => libc::SOF_TIMESTAMPING_TX_SCHED,
        } | match rx {
            RxTimestamping::Hardware => libc::SOF_TIMESTAMPING_RX_HARDWARE,
            RxTimestamping::Software => libc::SOF_TIMESTAMPING_RX_SOFTWARE,
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_TIMESTAMP,
                ptr::addr_of!(timestamp_req) as *const libc::c_void,
                mem::size_of::<crate::linux::tpacket_versions>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Configures the network device the socket is currently bound to to act in promiscuous mode.
    ///
    /// A network device in promiscuous mode will capture all packets observed on a physical medium,
    /// not just those destined for it.
    pub fn set_promiscuous(&self, promisc: bool) -> io::Result<()> {
        let iface = self.interface()?;

        let req = libc::packet_mreq {
            mr_ifindex: iface.index()? as i32,
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0u8; 8],
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                if promisc {
                    libc::PACKET_ADD_MEMBERSHIP
                } else {
                    libc::PACKET_DROP_MEMBERSHIP
                },
                ptr::addr_of!(req) as *const libc::c_void,
                mem::size_of::<libc::packet_mreq>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Adds the given socket to a fanout group.
    ///
    /// A fanout group is a set of sockets that act together to process packets. Each received
    /// packet is sent to only one of the sockets in the fanout group, based on the algorithm
    /// chosen in `fan_alg`. The group is specified using a 16-bit group identifier, `group_id`.
    /// Some additional options can be set:
    ///
    /// - `defrag` causes the kernel to defragment IP packets prior to sending them to the
    /// fanout group (e.g. to ensure [`FanoutAlgorithm::Hash`] works despite fragmentation)
    /// - `rollover` causes packets to be sent to a different socket than originally decided
    /// by `fan_alg` if the original socket is backlogged with packets.
    pub fn set_fanout(
        &self,
        group_id: u16,
        fan_alg: FanoutAlgorithm,
        defrag: bool,
        rollover: bool,
    ) -> io::Result<()> {
        let mut opt = match fan_alg {
            FanoutAlgorithm::Cpu => crate::linux::PACKET_FANOUT_CPU,
            FanoutAlgorithm::Hash => crate::linux::PACKET_FANOUT_HASH,
            FanoutAlgorithm::QueueMapping => crate::linux::PACKET_FANOUT_QM,
            FanoutAlgorithm::Random => crate::linux::PACKET_FANOUT_RND,
            FanoutAlgorithm::Rollover => crate::linux::PACKET_FANOUT_ROLLOVER,
            FanoutAlgorithm::RoundRobin => crate::linux::PACKET_FANOUT_LB,
        };

        opt |= (group_id as u32) << 16;

        if defrag {
            opt |= crate::linux::PACKET_FANOUT_FLAG_DEFRAG;
        }

        if rollover {
            opt |= crate::linux::PACKET_FANOUT_FLAG_ROLLOVER;
        }

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_FANOUT,
                ptr::addr_of!(opt) as *const libc::c_void,
                mem::size_of::<u32>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    ///
    /// This method will fail if the socket has not been bound to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3Socket::bind())).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            sent => Ok(sent as usize),
        }
    }

    /// Receive a datagram from the socket.
    ///
    /// This method will fail if the socket has not been bound  to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3Socket::bind())).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// TODO: add addr
    pub fn send_to<A: L2Addr>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        let sockaddr = addr.to_sockaddr();
        let addrlen = mem::size_of::<libc::sockaddr_ll>() as u32;

        match unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                addrlen,
            )
        } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// # Errors
    ///
    /// In the event that a packet is received that does not match either the address family
    /// (`AF_PACKET`) or the specified protocol type of `A`, this function will return.
    /// [`InvalidData`](io::ErrorKind::InvalidData). Note that `buf` will still be
    pub fn recv_from<A: L2Addr>(&self, buf: &mut [u8]) -> io::Result<(usize, A)> {
        let mut sockaddr = libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };
        let mut sockaddr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_ll>() as u32;

        let recvd = match unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                ptr::addr_of_mut!(sockaddr) as *mut libc::sockaddr,
                ptr::addr_of_mut!(sockaddr_len),
            )
        } {
            ..=-1 => return Err(io::Error::last_os_error()),
            recvd => recvd as usize,
        };

        if sockaddr.sll_family != libc::AF_PACKET as u16 {
            // Cannot guarantee received sockaddr is size_of::<libc::sockaddr_ll>()
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address received (address family not AF_PACKET)",
            ));
        }

        let Ok(addr) = A::try_from(sockaddr) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected address received (address protocol mismatch)",
            ));
        };

        Ok((recvd, addr))
    }

    /// Sets the PACKET_VERSION socket option to TPACKET_V3.
    fn set_tpacket_v3_opt(&self) -> io::Result<()> {
        let pkt_version_3 = crate::linux::tpacket_versions::TPACKET_V3;
        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_VERSION,
                ptr::addr_of!(pkt_version_3) as *const libc::c_void,
                mem::size_of::<crate::linux::tpacket_versions>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sets the PACKET_TX_RING socket option.
    fn set_tx_ring_opt(&self, config: BlockConfig) -> io::Result<()> {
        let req_tx = crate::linux::tpacket_req3 {
            tp_block_size: config.block_size(),
            tp_block_nr: config.block_cnt(),
            tp_frame_size: config.frame_size(),
            tp_frame_nr: config.frame_cnt(),
            tp_retire_blk_tov: 0,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_TX_RING,
                ptr::addr_of!(req_tx) as *const libc::c_void,
                mem::size_of::<crate::linux::tpacket_req>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sets the PACKET_RX_RING socket option.
    fn set_rx_ring_opt(
        &self,
        config: BlockConfig,
        mut timeout: Option<u32>,
        private_size: Option<u32>,
    ) -> io::Result<()> {
        if timeout == Some(0) {
            timeout = Some(1); // Prevent user from accidentally selecting kernel default
        }

        let req_rx = crate::linux::tpacket_req3 {
            tp_block_size: config.block_size(),
            tp_block_nr: config.block_cnt(),
            tp_frame_size: config.frame_size(),
            tp_frame_nr: config.frame_cnt(),
            tp_retire_blk_tov: timeout.unwrap_or(0),
            tp_sizeof_priv: private_size.unwrap_or(0),
            tp_feature_req_word: 0,
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_RX_RING,
                ptr::addr_of!(req_rx) as *const libc::c_void,
                mem::size_of::<crate::linux::tpacket_req>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Memory-map the packet's TX/RX ring buffers to enable zero-copy packet exchange.
    ///
    /// On error, the consumed [`L3Socket`] will be closed.
    fn mmap_socket(
        &self,
        config: BlockConfig,
        combined_tx_rx: bool,
    ) -> io::Result<*mut libc::c_void> {
        let map_length = if combined_tx_rx {
            config.map_length() * 2
        } else {
            config.map_length()
        };

        let mapped = unsafe {
            libc::mmap(
                ptr::null::<*mut libc::c_void>() as *mut libc::c_void,
                map_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED,
                self.fd,
                0,
            )
        };

        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(mapped)
    }

    /// Enables zero-copy packet transmission and reception for the socket.
    ///
    /// On error, the consumed `L3Socket` will be closed.
    ///
    /// NOTE: some performance issues have been noted when TX_RING sockets are used in blocking mode (see
    /// [here](https://stackoverflow.com/questions/43193889/sending-data-with-packet-mmap-and-packet-tx-ring-is-slower-than-normal-withou)).
    /// It is recommended that the socket be set as nonblocking before calling `packet_ring`.
    pub fn packet_ring(
        self,
        config: BlockConfig,
        timeout: Option<u32>,
        reserved: Option<u32>,
    ) -> io::Result<L3MappedSocket> {
        self.set_tpacket_v3_opt()?;
        self.set_rx_ring_opt(config, timeout, reserved)?;
        let mapping = self.mmap_socket(config, true)?;

        let rx_ring = unsafe {
            PacketRxRing::new(
                mapping as *mut u8,
                config,
                reserved.unwrap_or(0) as usize,
                OsiLayer::L3,
            )
        };

        let tx_ring =
            unsafe { PacketTxRing::new((mapping as *mut u8).add(config.map_length()), config) };

        // This will immediately wrap around to the first packet due to `frame_offset: None`
        let start_frame = FrameIndex {
            blocks_index: tx_ring.blocks_cnt() - 1,
            frame_offset: None,
        };

        Ok(L3MappedSocket {
            socket: self,
            rx_ring,
            next_rx: start_frame,
            tx_ring,
            last_checked_tx: start_frame,
            next_tx: start_frame,
            manual_tx_status: false,
            tx_full: false,
        })
    }

    /// Enables zero-copy packet transmission for the socket.
    ///
    /// On error, the consumed `L3Socket` will be closed.
    ///
    /// In past kernel versions, some performance issues have been noted when TX_RING sockets are
    /// used in blocking mode (see [here](https://stackoverflow.com/questions/43193889/sending-data-with-packet-mmap-and-packet-tx-ring-is-slower-than-normal-withou)).
    /// It is recommended that the socket be set as nonblocking before calling `packet_tx_ring`.
    pub fn packet_tx_ring(self, config: BlockConfig) -> io::Result<L3TxMappedSocket> {
        self.set_tpacket_v3_opt()?;
        self.set_tx_ring_opt(config)?;
        let mapping = self.mmap_socket(config, false)?;

        let tx_ring = unsafe { PacketTxRing::new(mapping as *mut u8, config) };

        // This will immediately wrap around to the first packet due to `frame_offset: None`
        let start_frame = FrameIndex {
            blocks_index: tx_ring.blocks_cnt() - 1,
            frame_offset: None,
        };

        Ok(L3TxMappedSocket {
            socket: self,
            tx_ring,
            last_checked_tx: start_frame,
            next_tx: start_frame,
            manual_tx_status: false,
            tx_full: false,
        })
    }

    /// Enables zero-copy packet reception for the socket.
    ///
    /// On error, the consumed `L3Socket` will be closed.
    pub fn packet_rx_ring(
        self,
        config: BlockConfig,
        timeout: Option<u32>,
        reserved: Option<u32>,
    ) -> io::Result<L3RxMappedSocket> {
        self.set_tpacket_v3_opt()?;
        self.set_rx_ring_opt(config, timeout, reserved)?;
        let mapping = self.mmap_socket(config, false)?;

        let rx_ring = unsafe {
            PacketRxRing::new(
                mapping as *mut u8,
                config,
                reserved.unwrap_or(0) as usize,
                OsiLayer::L3,
            )
        };

        // This will immediately wrap around to the first packet due to `frame_offset: None`
        let start_frame = FrameIndex {
            blocks_index: rx_ring.blocks_cnt() - 1,
            frame_offset: None,
        };

        Ok(L3RxMappedSocket {
            socket: self,
            rx_ring,
            next_rx: start_frame,
        })
    }
}

impl Drop for L3Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for L3Socket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.fd
    }
}

/// A network-layer socket with zero-copy packet transmission and reception.
pub struct L3MappedSocket {
    socket: L3Socket,
    rx_ring: PacketRxRing,
    next_rx: FrameIndex,
    tx_ring: PacketTxRing,
    last_checked_tx: FrameIndex,
    next_tx: FrameIndex,
    manual_tx_status: bool,
    tx_full: bool,
}

impl L3MappedSocket {
    /// Bind the network-layer socket to a particular interface and begin receiving packets matching
    /// the link-layer protocol `proto`.
    pub fn bind(&self, iface: Interface, proto: L2Protocol) -> io::Result<()> {
        self.socket.bind(iface, proto)
    }

    /// Binds the device to all interfaces, enabling it to begin receiving packets matching the
    /// link-layer protocol `proto`.
    #[inline]
    pub fn bind_all(&self, proto: L2Protocol) -> io::Result<()> {
        self.socket.bind_all(proto)
    }

    /// When set, configures transmitted packets to bypass kernel's traffic control (qdisc) layer.
    ///
    /// This allows packet buffering at the qdisc layer to be avoided, which is useful for
    /// applications that intend to intentionally flood a network with traffic. Enabling this option
    /// will lead to increased packet drops in transmission when network devices are busy (as the
    /// kernel will not be buffering packets originating from the socket).
    ///
    /// This option is disabled (`false`) by default.
    pub fn set_qdisc_bypass(&self, bypass: bool) -> io::Result<()> {
        self.socket.set_qdisc_bypass(bypass)
    }

    /// Reserves `amount` padding bytes before the packet in an [`RxFrame`].
    ///
    /// Note that the actual padding bytes available in an [`RxFrame`] may be slightly more than
    /// `amount` due to alignment requirements.
    pub fn set_reserve(&self, amount: u32) -> io::Result<()> {
        if unsafe {
            libc::setsockopt(
                self.socket.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_RESERVE,
                ptr::addr_of!(amount) as *const libc::c_void,
                mem::size_of::<u32>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Returns packet statistics about the current socket.
    ///
    /// Packet statistics include [`received`](PacketStatistics::received) and
    /// [`dropped`](PacketStatistics::dropped) packet counts; both of these counters are reset
    /// each time this method is called.
    pub fn packet_stats(&self) -> io::Result<PacketStatistics> {
        self.socket.packet_stats()
    }

    /// Returns the interface that the socket is currently sniffing on.
    #[inline]
    pub fn interface(&self) -> io::Result<Interface> {
        self.socket.interface()
    }

    /// Determines the source of timestamp information for TX_RING/RX_RING packets.
    /// If `true`, this option requests that the operating system use hardware timestamps
    /// provided by the NIC.
    ///
    /// For hardware timestamping to be employed, the socket must be bound to a specific interface.
    ///
    /// # Errors
    ///
    /// `ERANGE` - the requested packets cannot be timestamped by hardware.
    ///
    /// `EINVAL` - hardware timestamping is not supported by the network card.
    pub fn set_timestamp_method(&self, tx: TxTimestamping, rx: RxTimestamping) -> io::Result<()> {
        self.socket.set_timestamp_method(tx, rx)
    }

    /// Configures the network device the socket is currently bound to to act in promiscuous mode.
    ///
    /// A network device in promiscuous mode will capture all packets observed on a physical medium,
    /// not just those destined for it.
    pub fn set_promiscuous(&self, promisc: bool) -> io::Result<()> {
        self.socket.set_promiscuous(promisc)
    }

    /// Adds the given socket to a fanout group.
    ///
    /// A fanout group is a set of sockets that act together to process packets. Each received
    /// packet is sent to only one of the sockets in the fanout group, based on the algorithm
    /// chosen in `fan_alg`. The group is specified using a 16-bit group identifier, `group_id`.
    /// Some additional options can be set:
    ///
    /// - `defrag` causes the kernel to defragment IP packets prior to sending them to the
    /// fanout group (e.g. to ensure [`FanoutAlgorithm::Hash`] works despite fragmentation)
    /// - `rollover` causes packets to be sent to a different socket than originally decided
    /// by `fan_alg` if the original socket is backlogged with packets.
    pub fn set_packet_fanout(
        &self,
        group_id: u16,
        fan_alg: FanoutAlgorithm,
        defrag: bool,
        rollover: bool,
    ) -> io::Result<()> {
        self.socket.set_fanout(group_id, fan_alg, defrag, rollover)
    }

    /// Sets [`mapped_send()`](Self::mapped_send) results to be manually handled through repeated
    /// calls to [`tx_status()`](Self::tx_status).
    ///
    /// By default (i.e., when `manual` = `false`), the results of packet transmission are
    /// transparently handled. As a result, packets flagged as malformed by the kernel are
    /// aggregated into statistics rather than being reported back to the user on a case-by-case
    /// basis.
    ///
    /// If individual packet results are desired, setting this option to `true` modifies socket
    /// behavior such that each sent packet must have its status checked using
    /// [`tx_status()`](Self::tx_status) prior to that packet being discarded from the ring.
    #[inline]
    pub fn manual_tx_status(&mut self, manual: bool) {
        self.manual_tx_status = manual;
    }

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    ///
    /// NOTE: this method DOES NOT employ memory-mapped I/O and is functionally equivalent
    /// to [`L3Socket::send()`]. If you are looking to send a memory-mapped packet, use
    /// [`mapped_send()`](L3MappedSocket::mapped_send()) instead.
    ///
    /// This method will fail if the socket has not been bound to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3MappedSocket::bind())).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    /// Receive a datagram from the socket.
    ///
    /// NOTE: this method DOES NOT employ memory-mapped I/O and is functionally equivalent
    /// to [`L3Socket::recv()`]. If you are looking to receive a memory-mapped packet, use
    /// [`L3MappedSocket::mapped_recv()`] instead.
    ///
    /// This method will fail if the socket has not been bound  to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3MappedSocket::bind())).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    /// Retrieves the next frame in the memory-mapped ring buffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    pub fn mapped_send(&mut self) -> Option<TxFrame<'_>> {
        if self.tx_full {
            return None;
        }

        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.next_tx);
        let TxFrameVariant::Available(frame) = frame_variant else {
            return None;
        };

        if !self.manual_tx_status {
            self.last_checked_tx = self.next_tx;
        } else if self.last_checked_tx == next_tx {
            // TX has looped around fully with manual_tx_status enabled--indicate TX ring is now full
            self.tx_full = true;
        }

        self.next_tx = next_tx;

        Some(frame)
    }

    //
    // # Examples
    //
    // ```
    // use std::{thread, time::Duration};
    // use rscap::linux::prelude::*;
    //
    // let mut sock = L3Socket::new()?.packet_tx_ring(BlockConfig::new(65536, 16, 8192)?);
    // sock.manual_tx_status(true);
    // let mut sending = 0;
    // let mut malformed = 0;
    // for _ in 0..5 {
    //     let mut tx_frame = sock.mapped_send().unwrap();
    //     tx_frame.data()[0..11].copy_from_slice(b"hello world"); // This will obviously be malformed
    //     tx_frame.send(11);
    //     sending += 1;
    // }
    //
    // while sending > 0 {
    //     match sock.tx_status() {
    //         TxFrameVariant::Available(_) => sending -= 1,
    //         TxFrameVariant::WrongFormat(pkt) => {
    //             println!("Malformed packet: {:?}", pkt.data());
    //             malformed += 1;
    //             sending -= 1;
    //         }
    //         TxFrameVariant::SendRequest | TxFrameVariant::Sending => thread::sleep(Duration::from_millis(50)),
    //     }
    // }
    //
    // assert!(malformed == 5);
    // # Ok::<(), io::Error>(())
    // ```

    /// Checks the status of previously-sent packets in the order they were sent.
    ///
    /// By default, or when `manual_tx_status` is set to `false`, this method will only return the
    /// status the last packet sent using `mapped_send()`. When `manual_tx_status()` is set to
    /// `true`, this method will return the status of each packet sent with `mapped_send()` in the
    /// order they were sent.
    ///
    /// To correctly handle TX statuses manually, one should count pending packets sent with
    /// `mapped_send()`. The status of each pending packet should then be retrieved via consecutive
    /// calls to `tx_status()`. If `tx_status()` returns [`TxFrameVariant::Available`], the packet
    /// was successfully sent and the count of packets can be decremented. If `tx_status()`
    /// returns [`TxFrameVariant::SendRequest`] or [`TxFrameVariant::Sending`], the packet is still
    /// being handled by the kernel. In this case, the count should not be decremented, as the next
    /// call to `tx_status()` will return the status of that same packet. If `tx_status()` returns
    /// [`TxFrameVariant::WrongFormat`], the kernel has rejected the packet, and the count of pending
    /// packets should be decremented. The contents of the packet can be retrieved from the
    /// [`InvalidTxFrame`](super::mapped::InvalidTxFrame) if desired.
    pub fn tx_status(&mut self) -> TxFrameVariant<'_> {
        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.last_checked_tx);

        if self.manual_tx_status && (self.tx_full || self.last_checked_tx != self.next_tx) {
            // The TX ring is meant to be manually incremented _and_ is not empty
            if let TxFrameVariant::Available(_) | TxFrameVariant::WrongFormat(_) = frame_variant {
                // Increment the TX ring
                self.tx_full = false;
                self.last_checked_tx = next_tx;
            }
        }

        frame_variant
    }

    /// Retrieves the next frame in the memory-mapped ring buffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrame<'_>> {
        let (rx_frame, next_rx) = self.rx_ring.next_frame(self.next_rx)?;
        self.next_rx = next_rx;

        Some(rx_frame)
    }
}

impl Drop for L3MappedSocket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.rx_ring.mapped_start() as *mut libc::c_void,
                self.rx_ring.mapped_size() * 2,
            );
        }
        // The L3Socket will close itself when dropped
    }
}

impl AsRawFd for L3MappedSocket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}

/// A network-layer socket with zero-copy packet transmission.
pub struct L3TxMappedSocket {
    socket: L3Socket,
    tx_ring: PacketTxRing,
    last_checked_tx: FrameIndex,
    next_tx: FrameIndex,
    manual_tx_status: bool,
    tx_full: bool,
}

impl L3TxMappedSocket {
    /// Bind the network-layer socket to a particular interface and begin receiving packets matching
    /// the link-layer protocol `proto`.
    #[inline]
    pub fn bind(&self, iface: Interface, proto: L2Protocol) -> io::Result<()> {
        self.socket.bind(iface, proto)
    }

    /// Binds the device to all interfaces, enabling it to begin receiving packets matching the
    /// link-layer protocol `proto`.
    #[inline]
    pub fn bind_all(&self, proto: L2Protocol) -> io::Result<()> {
        self.socket.bind_all(proto)
    }

    /// When set, configures transmitted packets to bypass kernel's traffic control (qdisc) layer.
    ///
    /// This allows packet buffering at the qdisc layer to be avoided, which is useful for
    /// applications that intend to intentionally flood a network with traffic. Enabling this option
    /// will lead to increased packet drops in transmission when network devices are busy (as the
    /// kernel will not be buffering packets originating from the socket).
    ///
    /// This option is disabled (`false`) by default.
    #[inline]
    pub fn set_qdisc_bypass(&self, bypass: bool) -> io::Result<()> {
        self.socket.set_qdisc_bypass(bypass)
    }

    /// Returns packet statistics about the current socket.
    ///
    /// Packet statistics include [`received`](PacketStatistics::received) and
    /// [`dropped`](PacketStatistics::dropped) packet counts; both of these counters are reset
    /// each time this method is called.
    pub fn packet_stats(&self) -> io::Result<PacketStatistics> {
        self.socket.packet_stats()
    }

    /// Returns the interface that the socket is currently sniffing on.
    #[inline]
    pub fn interface(&self) -> io::Result<Interface> {
        self.socket.interface()
    }

    /// Determines the source of timestamp information for TX_RING/RX_RING packets.
    /// If `true`, this option requests that the operating system use hardware timestamps
    /// provided by the NIC.
    ///
    /// For hardware timestamping to be employed, the socket must be bound to a specific interface.
    ///
    /// # Errors
    ///
    /// `ERANGE` - the requested packets cannot be timestamped by hardware.
    ///
    /// `EINVAL` - hardware timestamping is not supported by the network card.
    pub fn set_timestamp_method(&self, tx: TxTimestamping, rx: RxTimestamping) -> io::Result<()> {
        self.socket.set_timestamp_method(tx, rx)
    }

    /// Receive a datagram from the socket.
    ///
    /// NOTE: this method DOES NOT employ memory-mapped I/O and is functionally equivalent
    /// to [`L3Socket::recv()`]. If you are looking to receive a memory-mapped packet, use
    /// [`mapped_recv()`](L3MappedSocket::mapped_recv()) instead.
    ///
    /// This method will fail if the socket has not been bound  to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3RxMappedSocket::bind())).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    ///
    /// NOTE: this method DOES NOT employ memory-mapped I/O and is functionally equivalent
    /// to [`L3Socket::send()`]. If you are looking to send a memory-mapped packet, use
    /// [`mapped_send()`](L3MappedSocket::mapped_send()) instead.
    ///
    /// This method will fail if the socket has not been bound to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3TxMappedSocket::bind())).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    /// Retrieves the next frame in the memory-mapped ring buffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    pub fn mapped_send(&mut self) -> Option<TxFrame<'_>> {
        if self.tx_full {
            return None;
        }

        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.next_tx);
        let TxFrameVariant::Available(frame) = frame_variant else {
            return None;
        };

        if !self.manual_tx_status {
            self.last_checked_tx = self.next_tx;
        } else if self.last_checked_tx == next_tx {
            // TX has looped around fully with manual_tx_status enabled--indicate TX ring is now full
            self.tx_full = true;
        }

        self.next_tx = next_tx;

        Some(frame)
    }

    /// Sets [`mapped_send()`](Self::mapped_send()) results to be manually handled via repeated
    /// calls to [`tx_status()`](Self::tx_status()).
    ///
    /// By default (i.e., when `manual` = `false`), the results of packet transmission are
    /// transparently handled. As a result, packets flagged as malformed by the kernel are
    /// aggregated into statistics rather than being reported back to the user on a case-by-case
    /// basis.
    ///
    /// If individual packet results are desired, setting this option to `true` modifies socket
    /// behavior such that each sent packet must have its status checked using `tx_status` prior
    /// to that packet being discarded from the ring.
    pub fn set_tx_status(&mut self, manual: bool) {
        self.manual_tx_status = manual;
    }

    //
    // # Examples
    //
    // ```
    // use std::{thread, time::Duration};
    // use rscap::linux::prelude::*;
    //
    // let mut sock = L3Socket::new()?.packet_tx_ring(BlockConfig::new(65536, 16, 8192)?);
    // sock.manual_tx_status(true);
    // let mut sending = 0;
    // let mut malformed = 0;
    // for _ in 0..5 {
    //     let mut tx_frame = sock.mapped_send().unwrap();
    //     tx_frame.data()[0..11].copy_from_slice(b"hello world"); // This will obviously be malformed
    //     tx_frame.send(11);
    //     sending += 1;
    // }
    //
    // while sending > 0 {
    //     match sock.tx_status() {
    //         TxFrameVariant::Available(_) => sending -= 1,
    //         TxFrameVariant::WrongFormat(pkt) => {
    //             println!("Malformed packet: {:?}", pkt.data());
    //             malformed += 1;
    //             sending -= 1;
    //         }
    //         TxFrameVariant::SendRequest | TxFrameVariant::Sending => thread::sleep(Duration::from_millis(50)),
    //     }
    // }
    //
    // assert!(malformed == 5);
    // # Ok::<(), io::Error>(())
    // ```

    /// Checks the status of previously-sent packets in the order they were sent.
    ///
    /// By default, or when [`set_tx_status()`](Self::set_tx_status()) is set to `false`, this
    /// method will only return the status the last packet sent using `mapped_send()`. When
    /// `set_tx_status()` is set to `true`, this method will return the status of each packet sent
    /// with [`mapped_send()`](Self::mapped_send()) in the order they were sent.
    ///
    /// To correctly handle TX statuses manually, one should count pending packets sent with
    /// `mapped_send()`. The status of each pending packet should then be retrieved via consecutive
    /// calls to `tx_status()`. If `tx_status()` returns [`TxFrameVariant::Available`], the packet
    /// was successfully sent and the count of packets can be decremented. If `tx_status()`
    /// returns [`TxFrameVariant::SendRequest`] or [`TxFrameVariant::Sending`], the packet is still
    /// being handled by the kernel. In this case, the count should not be decremented, as the next
    /// call to `tx_status()` will return the status of that same packet. If `tx_status()` returns
    /// [`TxFrameVariant::WrongFormat`], the kernel has rejected the packet, and the count of
    /// pending packets should be decremented. The contents of the packet can be retrieved from the
    /// encapsulated [`InvalidTxFrame`](super::mapped::InvalidTxFrame) if desired.
    pub fn tx_status(&mut self) -> TxFrameVariant<'_> {
        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.last_checked_tx);

        if self.manual_tx_status && (self.tx_full || self.last_checked_tx != self.next_tx) {
            // The TX ring is meant to be manually incremented _and_ is not empty
            if let TxFrameVariant::Available(_) | TxFrameVariant::WrongFormat(_) = frame_variant {
                // Increment the TX ring
                self.tx_full = false;
                self.last_checked_tx = next_tx;
            }
        }

        frame_variant
    }
}

impl Drop for L3TxMappedSocket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.tx_ring.mapped_start() as *mut libc::c_void,
                self.tx_ring.mapped_size(),
            );
        }
        // The L3Socket will close itself when dropped
    }
}

impl AsRawFd for L3TxMappedSocket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}

/// A network-layer socket with zero-copy packet reception.
pub struct L3RxMappedSocket {
    socket: L3Socket,
    rx_ring: PacketRxRing,
    next_rx: FrameIndex,
}

impl L3RxMappedSocket {
    /// Bind the network-layer socket to a particular interface and begin receiving packets matching
    /// the link-layer protocol `proto`.
    #[inline]
    pub fn bind(&self, iface: Interface, proto: L2Protocol) -> io::Result<()> {
        self.socket.bind(iface, proto)
    }

    /// Binds the network-layer socket to all interfaces, enabling it to begin receiving packets
    /// matching the link-layer protocol `proto`.
    #[inline]
    pub fn bind_all(&self, proto: L2Protocol) -> io::Result<()> {
        self.socket.bind_all(proto)
    }

    /// When set, configures transmitted packets to bypass kernel's traffic control (qdisc) layer.
    ///
    /// This allows packet buffering at the qdisc layer to be avoided, which is useful for
    /// applications that intend to intentionally flood a network with traffic. Enabling this option
    /// will lead to increased packet drops in transmission when network devices are busy (as the
    /// kernel will not be buffering packets originating from the socket).
    ///
    /// This option is disabled (`false`) by default.
    pub fn set_qdisc_bypass(&self, bypass: bool) -> io::Result<()> {
        self.socket.set_qdisc_bypass(bypass)
    }

    /// Returns packet statistics about the current socket.
    ///
    /// Packet statistics include [`received`](PacketStatistics::received) and
    /// [`dropped`](PacketStatistics::dropped) packet counts; both of these counters are reset
    /// each time this method is called.
    pub fn packet_stats(&self) -> io::Result<PacketStatistics> {
        self.socket.packet_stats()
    }

    /// Reserves `amount` padding bytes before the packet in an [`RxFrame`].
    ///
    /// Note that the actual padding bytes available in an [`RxFrame`] may be slightly more than
    /// `amount` due to alignment requirements.
    pub fn set_reserve(&self, amount: u32) -> io::Result<()> {
        if unsafe {
            libc::setsockopt(
                self.socket.fd,
                libc::SOL_PACKET,
                crate::linux::PACKET_RESERVE,
                ptr::addr_of!(amount) as *const libc::c_void,
                mem::size_of::<u32>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Returns the interface that the socket is currently sniffing on.
    #[inline]
    pub fn interface(&self) -> io::Result<Interface> {
        self.socket.interface()
    }

    /// Determines the source of timestamp information for TX_RING/RX_RING packets.
    /// If `true`, this option requests that the operating system use hardware timestamps
    /// provided by the NIC.
    ///
    /// For hardware timestamping to be employed, the socket must be bound to a specific interface.
    ///
    /// # Errors
    ///
    /// `ERANGE` - the requested packets cannot be timestamped by hardware.
    ///
    /// `EINVAL` - hardware timestamping is not supported by the network card.
    pub fn set_timestamp_method(&self, tx: TxTimestamping, rx: RxTimestamping) -> io::Result<()> {
        self.socket.set_timestamp_method(tx, rx)
    }

    /// Adds the given socket to a fanout group.
    ///
    /// A fanout group is a set of sockets that act together to process packets. Each received
    /// packet is sent to only one of the sockets in the fanout group, based on the algorithm
    /// chosen in `fan_alg`. The group is specified using a 16-bit group identifier, `group_id`.
    /// Some additional options can be set:
    ///
    /// - `defrag` causes the kernel to defragment IP packets prior to sending them to the
    /// fanout group (e.g. to ensure [`FanoutAlgorithm::Hash`] works despite fragmentation)
    /// - `rollover` causes packets to be sent to a different socket than originally decided
    /// by `fan_alg` if the original socket is backlogged with packets.
    pub fn set_packet_fanout(
        &self,
        group_id: u16,
        fan_alg: FanoutAlgorithm,
        defrag: bool,
        rollover: bool,
    ) -> io::Result<()> {
        self.socket.set_fanout(group_id, fan_alg, defrag, rollover)
    }

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    ///
    /// NOTE: this method DOES NOT employ memory-mapped I/O and is functionally equivalent
    /// to [`L3Socket::send()`]. If you are looking to send a memory-mapped packet, use
    /// [`L3MappedSocket::mapped_send()`] instead.
    ///
    /// This method will fail if the socket has not been bound to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3TxMappedSocket::bind())).
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    /// Receive a datagram from the socket.
    ///
    /// NOTE: this method DOES NOT employ memory-mapped I/O and is functionally equivalent
    /// to [`L3Socket::recv()`]. If you are looking to receive a memory-mapped packet, use
    /// [`mapped_recv()`](L3MappedSocket::mapped_recv()) instead.
    ///
    /// This method will fail if the socket has not been bound  to an [`L2Addr`] (i.e., via
    /// [`bind()`](L3RxMappedSocket::bind())).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    /// Retrieves the next frame in the memory-mapped ring buffer to receive a packet from.
    ///
    /// The returned [`RxFrame`] contains packet data that may be modified in-place if desired.
    pub fn mapped_recv(&mut self) -> Option<RxFrame<'_>> {
        let (rx_frame, next_rx) = self.rx_ring.next_frame(self.next_rx)?;
        self.next_rx = next_rx;

        Some(rx_frame)
    }
}

impl Drop for L3RxMappedSocket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.rx_ring.mapped_start() as *mut libc::c_void,
                self.rx_ring.mapped_size(),
            );
        }
        // The L3Socket will close itself when dropped
    }
}

impl AsRawFd for L3RxMappedSocket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}
