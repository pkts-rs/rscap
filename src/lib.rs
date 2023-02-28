// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <contact@rscap.org>

//! Rust packet capture and manipulation utilities.

pub mod linux;

pub use pkts::*;

pub(crate) use pkts::utils;

use std::{mem, ptr, net::SocketAddr, io::Read};

// 3 types: Sniffer, Spoofer and Socket
// Sniffer is read-only, Spoofer is write-only, Socket is RW

pub struct Interface {
    if_name: [u8; libc::IF_NAMESIZE],
    /// The index of the interface. Meant to specify "all" when set to None
    if_index: u32,
}

impl Interface {
    #[inline]
    pub fn new(if_name: &str) -> Result<Self, SockError> {
        Self::new_raw(if_name.as_bytes())
    }

    pub fn new_raw(if_name: &[u8]) -> Result<Self, SockError> {
        if if_name.len() >= 16 && !(if_name.len() == 16 && if_name.contains(&0x00)) {
            return Err(SockError { reason: format!("invalid interface name in Interface") }) // Interface name too long
        }

        let mut if_cstr = [0u8; libc::IF_NAMESIZE];
        if_cstr.as_mut_slice()[..if_name.len()].copy_from_slice(if_name);

        match unsafe { libc::if_nametoindex(if_cstr.as_ptr() as *const i8) } {
            0 => Err(SockError { reason: format!("if_nametoindex failed in Interface") }),
            i => Ok(Interface {
                if_name: if_cstr,
                if_index: i,
            })
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
                return &self.if_name[..idx + 1]
            }
        }

        return &[]
    }
}

pub struct L2Socket {
    fd: i32,
}

impl L2Socket {
    // TODO: add optional `protocol` arg
    pub fn new(iface: Option<Interface>) -> Result<Self, SockError> {
        let protocol = if iface.is_none() {
            (libc::ETH_P_ALL as u16).to_be() as i32
        } else {
            0
        };

        let fd = match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) } {
            -1 => return Err(SockError { reason: format!("socket creation failed") }),
            fd => fd,
        };

        if let Some(interface) = iface {
            let bind_iface = libc::sockaddr_ll {
                sll_family: libc::PF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: interface.index() as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };

            let res = unsafe { libc::bind(fd, ptr::addr_of!(bind_iface) as *const libc::sockaddr, core::mem::size_of::<libc::sockaddr_ll>() as u32) };
            if res == -1 {
                unsafe { libc::close(fd) };
                return Err(SockError { reason: format!("bind failed") })
            }

            // BUG: the byte representation of `Interface` is converted to its corresponding index, and that index is then used here.
            // This opens up a race condition--the interface could be dropped and a new one take its place in that index with a different name.
            // We would then be binding to the wrong interface.
            // There is no solution to this issue in Linux; at best, we can mitigate the possibility of it happening by checking the name of
            // the interface immediately after the `bind` call:
            let mut buf = [0u8; libc::IF_NAMESIZE];
            if unsafe { libc::if_indextoname(interface.index(), buf.as_mut_ptr() as *mut i8) } == core::ptr::null_mut() {
                unsafe { libc::close(fd) };
                return Err(SockError { reason: format!("if_indextoname failed") })
            } else if buf != interface.if_name {
                unsafe { libc::close(fd) };
                return Err(SockError { reason: format!("interface changed between time of creation and time of bind") })
            }
        }

        Ok(L2Socket {
            fd,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct PacketIndex {
    pub blk_offset: usize,
    pub num_pkts: u32,
}

// 1 << 22 * 64 = 256MB
// 1 << 18 * 128 = 32MB
pub struct L2RingSocket<const BLK_SZ: usize = {1 << 18}, const BLK_CNT: usize = 128> {
    blks: &'static mut[[u8; BLK_SZ]; BLK_CNT],
    blk_idx: usize,
    mtu: usize,
    pkt_idx: PacketIndex,
    sock: L2Socket,
    blk_read: bool,
}

impl<const BLK_SZ: usize, const BLK_CNT: usize> L2RingSocket<BLK_SZ, BLK_CNT> {
    pub fn new(iface: Option<Interface>, mtu: usize) -> Result<Self, SockError> {
        // if mtu % 16 != 0, fail
        // if mtu > BLK_SZ, fail
        // if BLK_SZ == 0 or BLK_CNT == 0, fail

        let sock = L2Socket::new(iface)?;

        let version = libc::tpacket_versions::TPACKET_V3;
        let res = unsafe { libc::setsockopt(sock.fd, libc::SOL_PACKET, libc::PACKET_VERSION, core::ptr::addr_of!(version) as *const libc::c_void, 4) };
        if res == -1 {
            return Err(SockError { reason: format!("failed to setsockopt PACKET_VERSION") })
        }
        
        let t_req = libc::tpacket_req3 {
            tp_block_size: BLK_SZ as libc::c_uint,
            tp_block_nr: BLK_CNT as libc::c_uint,
            tp_frame_size: mtu as libc::c_uint,
            tp_frame_nr:((BLK_SZ / mtu) * BLK_CNT) as libc::c_uint,
            tp_retire_blk_tov: 60,
            tp_feature_req_word: 0,
            tp_sizeof_priv: 0,
        };

        let res = unsafe { setsockopt(sock.fd, libc::SOL_PACKET, libc::PACKET_RX_RING, t_req) };
        if res == -1 {
            return Err(SockError { reason: format!("failed to setsockopt PACKET_RX_RING") })
        }

        let mapped_mem = unsafe { libc::mmap(core::ptr::null_mut(), BLK_SZ * BLK_CNT, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_LOCKED, sock.fd, 0) };
        if mapped_mem == libc::MAP_FAILED {
            return Err(SockError { reason: format!("failed to mmap") })
        }

        // Safety: `ring` must not outlive the PACKET socket in `sock`. Since these two
        // are tightly coupled within this struct, this is safe.
        return Ok(L2RingSocket {
            mtu,
            blks: unsafe { &mut *(mapped_mem as *mut [[u8; BLK_SZ]; BLK_CNT]) },
            blk_idx: 0,
            pkt_idx: PacketIndex { blk_offset: 0, num_pkts: 0 },
            sock,
            blk_read: false,
        })
    }

    pub fn read<'a>(&'a mut self) -> L2RingPacket<'a, BLK_SZ> {
        if self.pkt_idx.num_pkts <= 0 {
            // Special case: self.blk_read == false && self.pkt_idx.num_pkts == 0 means that the L2RingSocket has just been initialized
            if self.blk_read {
                self.blks[self.blk_idx][8..12].copy_from_slice(&libc::TP_STATUS_KERNEL.to_ne_bytes());
                self.blk_idx = (self.blk_idx + 1) % BLK_CNT; // Progress to the next block of the ring
                self.blk_read = false;
            }

            loop {
                let block_status = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 8).unwrap());
                if (block_status & libc::TP_STATUS_USER) == 0 {
                    let mut pfd = libc::pollfd {
                        fd: self.sock.fd,
                        events: libc::POLLIN | libc::POLLERR,
                        revents: 0,
                    };
                    unsafe { libc::poll(core::ptr::addr_of_mut!(pfd), 1, -1) };
                    // BUG: poll result left unused. If there's an error with polling, what do we do?
                } else {
                    let num_pkts = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 12).unwrap());
                    if num_pkts <= 0 {
                        // Short-circuit this block and move onto the next one if there were no packets
                        self.blks[self.blk_idx][8..12].copy_from_slice(&libc::TP_STATUS_KERNEL.to_ne_bytes());
                        self.blk_idx = (self.blk_idx + 1) % BLK_CNT;
                        self.blk_read = false;
                    } else {
                        break
                    }
                }
            }

            let num_pkts = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 12).unwrap());
            let blk_offset = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 16).unwrap()) as usize;

            self.pkt_idx = PacketIndex {
                blk_offset,
                num_pkts,
            };
        }

        L2RingPacket {
            blk: &mut self.blks[self.blk_idx],
            pkt_idx: &mut self.pkt_idx,
            blk_read: &mut self.blk_read,
        }
    }

    pub fn read_nonblocking<'a>(&'a mut self) -> Result<L2RingPacket<'a, BLK_SZ>, SockError> {
        if self.pkt_idx.num_pkts == 0 {
            // Special case: self.blk_read == false && self.pkt_idx.num_pkts == 0 means that the L2RingSocket has just been initialized
            if self.blk_read {
                self.blks[self.blk_idx][8..12].copy_from_slice(&libc::TP_STATUS_KERNEL.to_ne_bytes());
                self.blk_idx = (self.blk_idx + 1) % BLK_CNT; // Progress to the next block of the ring
                self.blk_read = false;
            }

            loop {
                let block_status = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 8).unwrap());
                if (block_status & libc::TP_STATUS_USER) == 0 {
                    return Err(SockError { reason: format!("no packets available to read") })
                } else {
                    let num_pkts = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 12).unwrap());
                    if num_pkts <= 0 {
                        // Short-circuit this block and move onto the next one if there were no packets
                        self.blks[self.blk_idx][8..12].copy_from_slice(&libc::TP_STATUS_KERNEL.to_ne_bytes());
                        self.blk_idx = (self.blk_idx + 1) % BLK_CNT;
                    } else {
                        break
                    }
                }
            }

            let num_pkts = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 12).unwrap());
            let blk_offset = u32::from_ne_bytes(*utils::get_array(self.blks[self.blk_idx].as_slice(), 16).unwrap()) as usize;

            self.pkt_idx = PacketIndex {
                blk_offset,
                num_pkts,
            };
        }

        Ok(L2RingPacket {
            blk: &mut self.blks[self.blk_idx],
            pkt_idx: &mut self.pkt_idx,
            blk_read: &mut self.blk_read,
        })
    }
}

pub struct L2RingPacket<'a, const BLK_SZ: usize> {
    blk: &'a mut [u8; BLK_SZ],
    pkt_idx: &'a mut PacketIndex,
    blk_read: &'a mut bool,
}

impl<'a, const BLK_SZ: usize> L2RingPacket<'a, BLK_SZ> {
    pub fn data(&self) -> &[u8] {
        let eth_offset = PacketHeaderV3::new(&self.blk[self.pkt_idx.blk_offset..]).mac() as usize;
        let eth_len = PacketHeaderV3::new(&self.blk[self.pkt_idx.blk_offset..]).snaplen() as usize;
        let start = self.pkt_idx.blk_offset + eth_offset;
        &self.blk[start..start + eth_len]
    }

    pub fn pkt_hdr(&'a self) -> PacketHeaderV3<'a> {
        PacketHeaderV3 { data: &self.blk[self.pkt_idx.blk_offset..] }
    }

    pub fn is_truncated(&self) -> bool {
        (PacketHeaderV3::new(&self.blk[self.pkt_idx.blk_offset..]).status() & libc::TP_STATUS_COPY) > 0
    }
}

impl<'a, const BLK_SZ: usize> Drop for L2RingPacket<'a, BLK_SZ> {
    fn drop(&mut self) {
        if self.pkt_idx.num_pkts == 0 {
            *self.blk_read = true;
        } else {
            self.pkt_idx.num_pkts -= 1;
            self.pkt_idx.blk_offset += PacketHeaderV3::new(&self.blk[self.pkt_idx.blk_offset..]).next_offset() as usize;
            if self.pkt_idx.num_pkts == 0 {
                *self.blk_read = true;
            }
        }
    }
}

pub struct PacketHeaderV3<'a> {
    data: &'a [u8],
}

impl<'a> PacketHeaderV3<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        PacketHeaderV3 { 
            data: bytes,
        }
    }

    pub fn next_offset(&self) -> u32 {
        u32::from_ne_bytes(*utils::get_array(self.data, 0).unwrap())
    }

    pub fn sec(&self) -> u32 {
        u32::from_ne_bytes(*utils::get_array(self.data, 4).unwrap())
    }

    pub fn nsec(&self) -> u32 {
        u32::from_ne_bytes(*utils::get_array(self.data, 8).unwrap())
    }

    pub fn snaplen(&self) -> u32 {
        u32::from_ne_bytes(*utils::get_array(self.data, 12).unwrap())
    }

    pub fn len(&self) -> u32 {
        u32::from_ne_bytes(*utils::get_array(self.data, 16).unwrap())
    }

    pub fn status(&self) -> u32 {
        u32::from_ne_bytes(*utils::get_array(self.data, 20).unwrap())
    }

    pub fn mac(&self) -> u16 {
        u16::from_ne_bytes(*utils::get_array(self.data, 24).unwrap())
    }

    pub fn net(&self) -> u16 {
        u16::from_ne_bytes(*utils::get_array(self.data, 26).unwrap())
    }
}

#[derive(Debug)]
pub struct SockError {
    reason: String,
}

pub struct PacketMmapSniffer<const PKT_SIZE: usize, const RING_SIZE: usize> {
    fd: i32,
    receive_buf: [*mut [u8; PKT_SIZE]; RING_SIZE], // TODO: change to MaybeUninit
//    transmit_buf: [*mut [u8; PKT_SIZE]; RING_SIZE],
}

impl<const PKT_SIZE: usize, const RING_SIZE: usize> PacketMmapSniffer<PKT_SIZE, RING_SIZE> {
    pub fn create(iface: &[u8]) -> Result<Self, SockError> {

        if iface.len() == 0 || iface.len() > 12 || iface.last().map(|b| if *b == 0 { Some(()) } else { None }).is_none() {
            return Err(SockError { reason: format!("Invalid interface {:?}", iface) })
        }

        // protocol set to 0 initially so that our RX buffer doesn't fill
        let fd = match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be()) } {
            -1 => return Err(SockError { reason: format!("socket creation failed") }),
            fd => fd,
        };

        let res = unsafe { setsockopt(fd, libc::SOL_PACKET, libc::PACKET_VERSION, libc::tpacket_versions::TPACKET_V3) };
        if res == -1 {
            unsafe { libc::close(fd) };
            return Err(SockError { reason: format!("setsockopt PACKET_VERSION failed") })
        }

        debug_assert!(PKT_SIZE <= (libc::c_uint::MAX ^ (libc::c_uint::MAX >> 1)) as usize);
        let tp_block_size = if PKT_SIZE.count_ones() == 1 {
            PKT_SIZE // PKT_SIZE is a power of 2
        } else {
            (PKT_SIZE << 1) ^ PKT_SIZE // Get next power of 2 larger than PKT_SIZE
        } as libc::c_uint;

        debug_assert!(RING_SIZE <= libc::c_int::MAX as usize);

        let t_req = libc::tpacket_req3 {
            tp_block_size,
            tp_block_nr: RING_SIZE as libc::c_uint,
            tp_frame_size: PKT_SIZE as libc::c_uint,
            tp_frame_nr: RING_SIZE as libc::c_uint,
            tp_retire_blk_tov: 60,
            tp_feature_req_word: 0,
            tp_sizeof_priv: 0,
        };

        /*let hdr = libc::ethhdr {
            
        }*/

        let res = unsafe { setsockopt(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, t_req) };
        if res == -1 {
            unsafe { libc::close(fd); }
            return Err(SockError { reason: format!("setsockopt PACKET_RX_RING failed") })
        }

        let size = tp_block_size as usize * RING_SIZE;
        let mapped_mem = unsafe { libc::mmap(core::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_LOCKED, fd, 0) };
        if mapped_mem == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(SockError { reason: format!("mmap failed") })
        }



        let recv = core::array::from_fn(move |i| unsafe { mapped_mem.add(i * tp_block_size as usize) as *mut [u8; PKT_SIZE] });

        

        Ok(PacketMmapSniffer {
            fd,
            receive_buf: recv,
        })
    }

}

pub(crate) unsafe fn setsockopt<T>(
    fd: libc::c_int,
    socket_level: libc::c_int,
    socket_option: libc::c_int,
    payload: T,
) -> i32 {
    libc::setsockopt(
        fd,
        socket_level,
        socket_option,
        ptr::addr_of!(payload).cast(),
        mem::size_of::<T>() as libc::socklen_t,
    )
}


pub fn get_interfaces() {

}



pub fn getifaddrs() {

    // SAFETY: `getifaddrs` expects no fields to be set in its corresponding `ifaddrs` struct.
    let mut ifaddrs_ptr: *mut libc::ifaddrs = unsafe { mem::zeroed() };
    // SAFETY: `getifaddrs` expects a pointer to a pointer which it allocates with memory.
    // We provide that pointer and later free it.
    let res = unsafe { libc::getifaddrs(ptr::addr_of_mut!(ifaddrs_ptr)) };
    if res == -1 {
        todo!("return error here")
    }

    // SAFETY: ifaddrs_ptr is guaranteed to be allocated so long as getifaddrs did not return -1.
    let ifaddrs_ref =  unsafe { &*ifaddrs_ptr };



}



pub fn interfaces() -> Vec<String> {
    let ifaces = Vec::new();

    unsafe {
        let sock = match libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) {
            -1 => panic!("couldn't create socket"),
            s => s,
        };

        // Initialize buffer to all 0 values
        let mut ifreq_buf: [libc::ifreq; 128] = [libc::ifreq {
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0u16,
                    sa_data: [0i8; 14],
                }
            },
            ifr_name: [0i8; 16],
        }; 128];

        /*
        let ifconf = libc::ifconf {
            ifc_len: 128 * mem::size_of::<libc::ifreq>() as i32,
            ifc_ifcu: libc::__c_anonymous_ifc_ifcu {
                ifcu_buf: ifreq_buf.as_mut_ptr() as *mut i8,
            }
        };
        

        match libc::ioctl(sock, libc::SIOCGIFCONF, &ifconf) {
            0 => (),
            _ => panic!("SIOCGIFCONF ioctl() failed"),
        }

        let ifc_num = ifconf.ifc_len / mem::size_of::<libc::ifreq>() as i32;
        for ifreq in ifreq_buf.iter().take(ifc_num as usize) {
            //ifreq.ifr_ifru.ifru_addr
        }
        */



    }

    ifaces
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
