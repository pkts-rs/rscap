// Copyright 2022 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod addr;
pub mod l2;
pub mod l3;
pub mod mapped;

/// What kind of sockets does Linux support?
///
///
/// AF_PACKET, SOCK_RAW -> user must include L2 header
/// AF_PACKET, SOCK_DGRAM -> L3 and beyond (L2 is cooked into packet) based on sockaddr_ll supplied by destination
///
/// protocol == htons(ETH_P_ALL) -> receive all protocols over the packet
/// protocol == 0 -> no packets are received
/// protocol == SOME_PROTOCOL -> packets of that particular protocol are received
/// bind() with nonzero sll_protocol -> start receiving packets of that protocol
///
/// bind() with a specific sockaddr_ll -> receive packets from a particular interface (by default, packets can come from all interfaces)
///
/// when MSG_TRUNC is passed to recvmsg, recv, etc. then real length of packet is returned even if it's longer than buffer
///
/// sockaddr_ll {
///   sll_ifindex -> 0 indicates any index
/// }
///
/// AF_INET, SOCK_RAW, protocol -> enables sending & receiving packets from a specified source/destination IPv4 address pair (i.e. an L4 socket)
///
/// Can be made to be L3 with IP_HDRINCL
///
/// A protocol of IPPROTO_RAW implies enabled IP_HDRINCL and is able
/// to send any IP protocol that is specified in the passed header.
/// Receiving of all IP protocols via IPPROTO_RAW is not possible
/// using raw sockets.
///
///
/// # Other notes
///
/// CAP_NET_RAW is required for AF_PACKET

/*
pub struct L3Socket {
    fd: i32,
}

pub struct RawSocket {
    fd: i32,
}
*/

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TxTimestamping {
    /// Request transmission timestamps be collected from the network adapter.
    Hardware,
    /// Request transmission timestamps be measured when the packet leaves the kernel.
    Software,
    /// Request transmission timestamps be measured prior to entering the kernel packet scheduler.
    Sched,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RxTimestamping {
    /// Request transmission timestamps be collected from the network adapter.
    Hardware,
    /// Request transmission timestamps be measured when the packet leaves the kernel.
    Software,
}

#[derive(Clone, Copy)]
pub struct PacketStatistics {
    pub packets_seen: usize,
    pub packets_dropped: usize,
}
