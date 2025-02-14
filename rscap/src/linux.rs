// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (Linux) `AF_PACKET`/`SOCK_RAW` packet capture and transmission interface.
//!
//! Sockets that transmit/receive link-layer packets can be found in the [`l2`] submodule, while
//! sockets that handle network-layer packets can be found in [`l3`]. Memory-mapped socket utilites
//! are available in the [`mapped`] submodule.
//!
//! To include all common linux-specific structures, simply add `use rscap::linux::prelude::*` to
//! your source.

use addr::L2Protocol;
use l2::{L2MappedSocket, L2Socket};

use mapped::{BlockConfig, RxFrame};

use std::io;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, RawFd};

use crate::{filter::PacketFilter, Interface};

pub mod addr;
pub mod l2;
pub mod l3;
pub mod l4;
pub mod mapped;
#[doc(hidden)]
pub mod prelude;
mod sndrcv;

// Temporarily used until they are merged into libc:

// pub(crate) const PACKET_HOST: libc::c_uchar = 0;
// pub(crate) const PACKET_BROADCAST: libc::c_uchar = 1;
// pub(crate) const PACKET_MULTICAST: libc::c_uchar = 2;
// pub(crate) const PACKET_OTHERHOST: libc::c_uchar = 3;
// pub(crate) const PACKET_OUTGOING: libc::c_uchar = 4;
// pub(crate) const PACKET_LOOPBACK: libc::c_uchar = 5;
// pub(crate) const PACKET_USER: libc::c_uchar = 6;
// pub(crate) const PACKET_KERNEL: libc::c_uchar = 7;

pub(crate) const PACKET_RX_RING: libc::c_int = 5;
pub(crate) const PACKET_STATISTICS: libc::c_int = 6;
// pub(crate) const PACKET_AUXDATA: libc::c_int = 8;
pub(crate) const PACKET_VERSION: libc::c_int = 10;
pub(crate) const PACKET_RESERVE: libc::c_int = 12;
pub(crate) const PACKET_TX_RING: libc::c_int = 13;
// pub(crate) const PACKET_LOSS: libc::c_int = 14;
pub(crate) const PACKET_TIMESTAMP: libc::c_int = 17;
pub(crate) const PACKET_FANOUT: libc::c_int = 18;
pub(crate) const PACKET_QDISC_BYPASS: libc::c_int = 20;

pub(crate) const PACKET_FANOUT_HASH: libc::c_uint = 0;
pub(crate) const PACKET_FANOUT_LB: libc::c_uint = 1;
pub(crate) const PACKET_FANOUT_CPU: libc::c_uint = 2;
pub(crate) const PACKET_FANOUT_ROLLOVER: libc::c_uint = 3;
pub(crate) const PACKET_FANOUT_RND: libc::c_uint = 4;
pub(crate) const PACKET_FANOUT_QM: libc::c_uint = 5;
// pub(crate) const PACKET_FANOUT_CBPF: libc::c_uint = 6;
// pub(crate) const PACKET_FANOUT_EBPF: libc::c_uint = 7;
pub(crate) const PACKET_FANOUT_FLAG_ROLLOVER: libc::c_uint = 0x1000;
// pub(crate) const PACKET_FANOUT_FLAG_UNIQUEID: libc::c_uint = 0x2000;
pub(crate) const PACKET_FANOUT_FLAG_DEFRAG: libc::c_uint = 0x8000;

// pub(crate) const TP_STATUS_KERNEL: u32 = 0;
pub(crate) const TP_STATUS_USER: u32 = 1 << 0;
pub(crate) const TP_STATUS_COPY: u32 = 1 << 1;
pub(crate) const TP_STATUS_LOSING: u32 = 1 << 2;
pub(crate) const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;
pub(crate) const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
// pub(crate) const TP_STATUS_BLK_TMO: u32 = 1 << 5;
pub(crate) const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;
pub(crate) const TP_STATUS_CSUM_VALID: u32 = 1 << 7;

pub(crate) const TP_STATUS_AVAILABLE: u32 = 0;
pub(crate) const TP_STATUS_SEND_REQUEST: u32 = 1 << 0;
pub(crate) const TP_STATUS_SENDING: u32 = 1 << 1;
pub(crate) const TP_STATUS_WRONG_FORMAT: u32 = 1 << 2;

// pub(crate) const TP_STATUS_TS_SOFTWARE: u32 = 1 << 29;
// pub(crate) const TP_STATUS_TS_SYS_HARDWARE: u32 = 1 << 30;
// pub(crate) const TP_STATUS_TS_RAW_HARDWARE: u32 = 1 << 31;

// pub(crate) const TP_FT_REQ_FILL_RXHASH: u32 = 1;

pub(crate) const TPACKET_ALIGNMENT: usize = 16;

/*
#[repr(align(8))]
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_rollover_stats {
    pub tp_all: u64,
    pub tp_huge: u64,
    pub tp_failed: u64,
}
*/

#[repr(align(8))]
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub(crate) struct tpacket_hdr_v1 {
    pub block_status: u32,
    pub num_pkts: u32,
    pub offset_to_first_pkt: u32,
    pub blk_len: u32,
    pub seq_num: u64,
    pub ts_first_pkt: tpacket_bd_ts,
    pub ts_last_pkt: tpacket_bd_ts,
}

#[repr(u32)]
#[allow(non_camel_case_types)]
pub(crate) enum tpacket_versions {
    #[allow(unused)]
    TPACKET_V1,
    #[allow(unused)]
    TPACKET_V2,
    TPACKET_V3,
}

/*
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct fanout_args {
    #[cfg(target_endian = "little")]
    pub id: u16,
    pub type_flags: u16,
    #[cfg(target_endian = "big")]
    pub id: u16,
    pub max_num_members: u32,
}


#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct sockaddr_pkt {
    pub spkt_family: libc::c_ushort,
    pub spkt_device: [libc::c_uchar; 14],
    pub spkt_protocol: libc::c_ushort,
}


#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_auxdata {
    pub tp_status: u32,
    pub tp_len: u32,
    pub tp_snaplen: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub tp_vlan_tci: u16,
    pub tp_vlan_tpid: u16,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_hdr {
    pub tp_status: libc::c_ulong,
    pub tp_len: libc::c_uint,
    pub tp_snaplen: libc::c_uint,
    pub tp_mac: libc::c_ushort,
    pub tp_net: libc::c_ushort,
    pub tp_sec: libc::c_uint,
    pub tp_usec: libc::c_uint,
}
*/

#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_hdr_variant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    pub tp_padding: u16,
}

/*
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket2_hdr {
    pub tp_status: u32,
    pub tp_len: u32,
    pub tp_snaplen: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_vlan_tci: u16,
    pub tp_vlan_tpid: u16,
    pub tp_padding: [u8; 4],
}
*/

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub(crate) struct tpacket_req {
    pub tp_block_size: libc::c_uint,
    pub tp_block_nr: libc::c_uint,
    pub tp_frame_size: libc::c_uint,
    pub tp_frame_nr: libc::c_uint,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub(crate) struct tpacket_req3 {
    pub tp_block_size: libc::c_uint,
    pub tp_block_nr: libc::c_uint,
    pub tp_frame_size: libc::c_uint,
    pub tp_frame_nr: libc::c_uint,
    pub tp_retire_blk_tov: libc::c_uint,
    pub tp_sizeof_priv: libc::c_uint,
    pub tp_feature_req_word: libc::c_uint,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_stats {
    pub tp_packets: libc::c_uint,
    pub tp_drops: libc::c_uint,
}

/*
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_stats_v3 {
    pub tp_packets: libc::c_uint,
    pub tp_drops: libc::c_uint,
    pub tp_freeze_q_cnt: libc::c_uint,
}
*/

#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket3_hdr {
    pub tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: tpacket_hdr_variant1,
    pub tp_padding: [u8; 8],
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub(crate) struct tpacket_bd_ts {
    pub ts_sec: libc::c_uint,
    pub ts_usec: libc::c_uint,
}

/*
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) union tpacket_req_u {
    pub req: tpacket_req,
    pub req3: tpacket_req3,
}
*/

#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) union tpacket_bd_header_u {
    pub bh1: tpacket_hdr_v1,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct tpacket_block_desc {
    pub version: u32,
    pub offset_to_priv: u32,
    pub hdr: tpacket_bd_header_u,
}

// What kind of sockets does Linux support?
//
//
// AF_PACKET, SOCK_RAW -> user must include L2 header
// AF_PACKET, SOCK_DGRAM -> L3 and beyond (L2 is cooked into packet) based on sockaddr_ll supplied by destination
//
// protocol == htons(ETH_P_ALL) -> receive all protocols over the packet
// protocol == 0 -> no packets are received
// protocol == SOME_PROTOCOL -> packets of that particular protocol are received
// bind() with nonzero sll_protocol -> start receiving packets of that protocol
//
// bind() with a specific sockaddr_ll -> receive packets from a particular interface (by default, packets can come from all interfaces)
//
// when MSG_TRUNC is passed to recvmsg, recv, etc. then real length of packet is returned even if it's longer than buffer
//
// sockaddr_ll {
//   sll_ifindex -> 0 indicates any index
// }
//
// AF_INET, SOCK_RAW, protocol -> enables sending & receiving packets from a specified source/destination IPv4 address pair (i.e. an L4 socket)
//
// Can be made to be L3 with IP_HDRINCL
//
// A protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able
// to send any IP protocol that is specified in the passed header.
// Receiving of all IP protocols via IPPROTO_RAW is not possible
// using raw sockets.
//
//
// # Other notes
//
// CAP_NET_RAW is required for AF_PACKET

/// Specifies a source of packet transmission timestamps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TxTimestamping {
    /// Collect TX timestamps from the network adapter.
    Hardware,
    /// Measure TX timestamps as packets leave the kernel.
    Software,
    /// Measure TX timestamps as packets enter the kernel packet scheduler.
    Sched,
}

/// Specifies a source of packet reception timestamps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RxTimestamping {
    /// Collect RX timestamps from the network adapter.
    Hardware,
    /// Measure receive timestamps as packets leave the kernel.
    Software,
}

/// The distribution algorithm to be used in a fanout group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutAlgorithm {
    /// Takes a hash of the network address (and optionally transport-layer ports) in the packet
    /// and selects the socket based on that hash. This method maintains per-flow ordering; packets
    /// from a given address/port 4-tuple are always sent to the same socket.
    Hash,
    /// Selects the socket in a round-robin manner.
    RoundRobin,
    /// Selects the socket based on the CPU the packet arrived on.
    Cpu,
    /// Always passes data to the first subscribed socket, moving to the next in the event of
    /// backlog (and so on).
    Rollover,
    /// Selects the socket randomly.
    Random,
    /// Selects the socket using the kernel's recorded queue_mapping for the received packet skb.
    QueueMapping,
}

pub(crate) const DEFAULT_DRIVER_BUFFER: usize = 2 * 1024 * 1024 * 1024; // Default each buffer of 1MB

pub(crate) struct SnifferImpl {
    socket: L2MappedSocket,
}

impl SnifferImpl {
    #[inline]
    pub fn new(if_name: Interface) -> io::Result<Self> {
        Self::new_with_size(if_name, DEFAULT_DRIVER_BUFFER)
    }

    /// Note that `ring_size` must be greater than or equal to 524288 (512 KiB), and will be
    /// rounded down to the nearest 512 KiB when allocating buffers.
    #[inline]
    pub fn new_with_size(if_name: Interface, ring_size: usize) -> io::Result<Self> {
        let individual_ring_size = ring_size / 2;

        let units = individual_ring_size / (131072 * 2);
        if units == 0 {
            // Need at least 2 blocks, each of size 2*2^16.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ring_size must be >= 524288 (512 KiB)",
            ));
        }

        let Ok(units) = u32::try_from(units) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "specified ring size was too big to represent for internal integers",
            ));
        };

        let mut block_size = 131072;
        let mut block_cnt = 2;

        // Double the block size, and allocate the rest toward block count
        // This algorithm may be changed in the future based on perf measurements
        if units > 1 {
            let remainder = units % 2;
            let units = units / 2;

            // Double the block size to 256 KiB
            block_size *= 2;
            // Put the rest towards block count
            block_cnt = (block_cnt * units) + remainder;
            // remainder is 1/2; 1/2 of 2 (block_cnt) is 1
        }

        let socket = L2Socket::new()?;
        let config = BlockConfig::new(block_size, block_cnt, 65648)?;
        let mapped_socket = socket.packet_ring(config, None, None)?;
        mapped_socket.set_filter(&mut PacketFilter::reject_all())?;
        mapped_socket.bind(if_name, L2Protocol::All)?;

        Ok(Self {
            socket: mapped_socket,
        })
    }

    #[inline]
    pub fn activate(&mut self, filter: Option<PacketFilter>) -> io::Result<()> {
        self.socket.flush()?;

        match filter {
            None => self.socket.clear_filter(),
            Some(mut filter) => self.socket.set_filter(&mut filter),
        }
    }

    #[inline]
    pub fn deactivate(&mut self) -> io::Result<()> {
        self.socket.set_filter(&mut PacketFilter::reject_all())
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.socket.nonblocking()
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.socket.send(packet)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }

    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrameImpl<'_>> {
        Some(RxFrameImpl {
            frame: self.socket.mapped_recv()?,
        })
    }
}

impl AsRawFd for SnifferImpl {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

pub(crate) struct RxFrameImpl<'a> {
    frame: RxFrame<'a>,
}

impl RxFrameImpl<'_> {
    pub fn data(&self) -> &[u8] {
        self.frame.data()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.frame.data_mut()
    }
}
