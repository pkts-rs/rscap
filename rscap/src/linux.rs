// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Linux-specific packet capture/transmission utilities.
//!
//! Sockets that transmit/receive link-layer packets can be found in the [`l2`] submodule, while
//! sockets that handle network-layer packets can be found in [`l3`]. Memory-mapped socket utilites
//! are available in the [`mapped`] submodule.
//!
//! To include all common linux-specific structures, simply add `use rscap::linux::prelude::*` to
//! your source.

pub mod addr;
pub mod l2;
pub mod l3;
pub mod l4;
pub mod mapped;
pub mod prelude;

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

/// Statistics on packets sent and dropped by a socket.
#[derive(Clone, Copy)]
pub struct PacketStatistics {
    /// The number of packets received by a socket.
    pub packets_seen: usize,
    /// The number of packets dropped by a socket.
    pub packets_dropped: usize,
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
