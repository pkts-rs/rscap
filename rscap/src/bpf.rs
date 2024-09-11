// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (BSD/MacOS) Berkeley Packet Filter (BPF) packet capture and transmission interface (see `filter`
//! for cross-platform BPF filtering utilities).
//!
//!

use core::{mem, slice};
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{array, io, ptr};

use crate::filter::PacketStatistics;
use crate::Interface;

const BPF_PATH: &[u8] = b"/dev/bpf\0";
/// `L2Socket::new()` will only iterate through up to this many BPF device names before failing.
const MAX_OPEN_BPF: u32 = 1024;

// TODO: add AIX support by loading BPF driver

// Temporary replacements for libc during development
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_version {
    major: libc::c_ushort,
    minor: libc::c_ushort,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_stat {
    bs_recv: libc::c_uint,
    bs_drop: libc::c_uint,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_zbuf {
    bz_bufa: *mut libc::c_void,
    bz_bufb: *mut libc::c_void,
    bz_buflen: libc::size_t,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_xhdr {
    bh_tstamp: bpf_ts,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: libc::c_ushort,
}

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_ts {
    bt_sec: i64,
    bt_frac: u64,
}

const BIOCFLUSH: libc::c_ulong = 0x20004268;
const BIOCPROMISC: libc::c_ulong = 0x20004269;
const BIOCGDLT: libc::c_ulong = 0x4004426a;
const BIOCGBLEN: libc::c_ulong = 0x40044266;
const BIOCSBLEN: libc::c_ulong = 0xc0044266;
const BIOCVERSION: libc::c_ulong = 0x40044271;
const BIOCGETIF: libc::c_ulong = 0x4020426b;
const BIOCSETIF: libc::c_ulong = 0x8020426c;
const BIOCGSTATS: libc::c_ulong = 0x4008426f;
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
const BIOCSETZBUF: libc::c_ulong = 0x80184281;
const BIOCFEEDBACK: libc::c_ulong = 0x8004427c;
const BIOCLOCK: libc::c_ulong = 0x2000427a;

const BPF_ALIGNMENT: usize = mem::size_of::<libc::c_long>();
#[allow(non_snake_case)]
const fn BPF_WORDALIGN(x: usize) -> usize {
    (x + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
}

#[derive(Clone, Copy, Debug)]
pub enum SocketAccess {
    /// The socket can only be used to read packets being sent/received.
    ReadOnly,
    /// The socket can both read and write packets.
    ReadWrite,
    /// The socket can only be used to send packets.
    WriteOnly,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BpfVersion {
    major: u16,
    minor: u16,
}

impl BpfVersion {
    pub fn major(&self) -> u16 {
        self.major
    }

    pub fn minor(&self) -> u16 {
        self.minor
    }
}

#[repr(u16)]
#[non_exhaustive]
pub enum LinkType {
    Null = 0,
    En10Mb = 1,
    En3Mb = 2,
    Ax25 = 3,
    Pronet = 4,
    Chaos = 5,
    Ieee802 = 6,
    Arcnet = 7,
    Slip = 8,
    Ppp = 9,
    Fddi = 10,
    #[cfg(target_os = "openbsd")]
    Raw = 14,
    #[cfg(not(target_os = "openbsd"))]
    Raw = 12,
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    SlipBsdos = 13,
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    PppBsdos = 14,
    #[cfg(target_os = "netbsd")]
    Hippi = 15,
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "openbsd"
    ))]
    Pfsync = 18,
    AtmClip = 19,
    RedbackSmartedge = 32,
    PppSerial = 50,
    PppEther = 51,
    SymantecFirewall = 99,
    Chdlc = 104,
    Ieee80211 = 105,
    Frelay = 107,
    #[cfg(target_os = "openbsd")]
    Loop = 12,
    #[cfg(not(target_os = "openbsd"))]
    Loop = 108,
    #[cfg(target_os = "openbsd")]
    Enc = 13,
    #[cfg(not(target_os = "openbsd"))]
    Enc = 109,
    #[cfg(target_os = "netbsd")]
    Hdlc = 16,
    #[cfg(not(target_os = "netbsd"))]
    Hdlc = 112,
    LinuxSll = 113,
    Ltalk = 114,
    Econet = 115,
    Ipfilter = 116,
    Pflog = 117,
    CiscoIos = 118,
    PrismHeader = 119,
    AironetHeader = 120,
    #[cfg(target_os = "freebsd")]
    Pfsync = 121,
    #[cfg(not(target_os = "freebsd"))]
    Hhdlc = 121,
    IpOverFc = 122,
    SunAtm = 123,
    Rio = 124,
    PciExp = 125,
    Aurora = 126,
    Ieee80211Radio = 127,
    Tzsp = 128,
    ArcnetLinux = 129,
    /* more defined in <net/dlt.h> */
}

#[repr(C)]
struct BpfHeader {
    bzh_kernel_gen: AtomicU32,
    bzh_kernel_len: AtomicU32,
    bzh_user_gen: AtomicU32,
    _bzh_pad: [libc::c_uint; 5],
}

#[derive(Clone, Copy)]
enum ReceiveIndex {
    FirstBlock(usize),
    SecondBlock(usize),
}

impl ReceiveIndex {
    pub fn increment(&mut self, amount: usize) {
        match self {
            ReceiveIndex::FirstBlock(a) => *a += amount,
            ReceiveIndex::SecondBlock(b) => *b += amount,
        }
    }

    pub fn swap(&mut self) {
        *self = match self {
            ReceiveIndex::FirstBlock(_) => ReceiveIndex::SecondBlock(0),
            ReceiveIndex::SecondBlock(_) => ReceiveIndex::FirstBlock(0),
        }
    }
}

pub struct L2Socket {
    fd: RawFd,
}

impl L2Socket {
    pub fn new(access_mode: SocketAccess) -> io::Result<Self> {
        let mode = match access_mode {
            SocketAccess::ReadOnly => libc::O_RDONLY,
            SocketAccess::ReadWrite => libc::O_RDWR,
            SocketAccess::WriteOnly => libc::O_WRONLY,
        };

        let mut fd = unsafe { libc::open(BPF_PATH.as_ptr() as *const i8, mode) };
        if fd >= 0 {
            return Ok(L2Socket { fd });
        }

        let errno = unsafe { *libc::__error() };
        if errno != libc::ENOENT {
            return Err(io::Error::from_raw_os_error(errno));
        }

        // `/dev/bpf` isn't available--try `/dev/bpfX`
        // Some net utilities hardcode /dev/bpf0 for use, so we politely avoid it
        for dev_idx in 1..MAX_OPEN_BPF {
            let device = CString::new(format!("/dev/bpf{}", dev_idx).into_bytes()).unwrap();
            fd = unsafe { libc::open(device.as_ptr(), mode) };
            if fd >= 0 {
                return Ok(L2Socket { fd });
            }

            let errno = unsafe { *libc::__error() };
            if errno != libc::EBUSY {
                break; // Device wasn't in use, but some other error occurred--return
            }
        }

        Err(io::Error::last_os_error())
    }

    pub fn bpf_version(&self) -> io::Result<BpfVersion> {
        let mut version = bpf_version { major: 0, minor: 0 };

        let res = unsafe {
            libc::ioctl(
                self.fd,
                BIOCVERSION,
                ptr::addr_of_mut!(version) as *mut libc::c_char,
            )
        };
        match res {
            0 => Ok(BpfVersion {
                major: version.major,
                minor: version.minor,
            }),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Returns the maximum byte length of packets received by the socket.
    ///
    /// Any packet exceeding this length will be truncated to fit within the frame.
    pub fn frame_len(&self) -> io::Result<u32> {
        let mut frame_len: libc::c_uint = 0;
        let res = unsafe { libc::ioctl(self.fd, BIOCGBLEN, ptr::addr_of_mut!(frame_len)) };
        match res {
            0.. => Ok(frame_len),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Sets the maximum byte length of packets received by the socket.
    ///
    /// Any packet exceeding this length will be truncated to fit within the frame.
    pub fn set_frame_len(&self, mut frame_len: u32) -> io::Result<()> {
        let res = unsafe { libc::ioctl(self.fd, BIOCSBLEN, ptr::addr_of_mut!(frame_len)) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Returns the type of the link layer associated with the interface the socket is bound to.
    pub fn link_type(&self) -> io::Result<u16> {
        let mut linktype: u16 = 0;
        let res = unsafe { libc::ioctl(self.fd, BIOCGDLT, ptr::addr_of_mut!(linktype)) };
        match res {
            0.. => Ok(linktype),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Configures the network device the socket is currently bound to to act in promiscuous mode.
    ///
    /// A network device in promiscuous mode will capture all packets observed on a physical medium,
    /// not just those destined for it. When this option is used, _any sockets bound to the device_
    /// will receive packets promiscuously, not just the socket that `set_promiscuous()` was called on.
    pub fn set_promiscuous(&self) -> io::Result<()> {
        let res = unsafe { libc::ioctl(self.fd, BIOCPROMISC) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Flushes the buffer of incoming packets and resets packet statistics for the current socket.
    pub fn flush(&self) -> io::Result<()> {
        let res = unsafe { libc::ioctl(self.fd, BIOCFLUSH) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Binds the device to the given interface, enabling it to receive packets from that interface.
    pub fn bind(&self, iface: Interface) -> io::Result<()> {
        let name = iface.name_raw();
        let mut ifreq = libc::ifreq {
            ifr_name: array::from_fn(|i| if i < name.len() { name[i] as i8 } else { 0i8 }),
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_len: 0,
                    sa_data: [0i8; 14],
                },
            },
        };

        let res = unsafe { libc::ioctl(self.fd, BIOCSETIF, ptr::addr_of_mut!(ifreq)) };
        match res {
            0 => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Returns the interface the device is bound to.
    pub fn interface(&self) -> io::Result<Interface> {
        let mut ifreq = libc::ifreq {
            ifr_name: [0i8; 16],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0,
                    sa_len: 0,
                    sa_data: [0i8; 14],
                },
            },
        };

        let res = unsafe { libc::ioctl(self.fd, BIOCGETIF, ptr::addr_of_mut!(ifreq)) };
        match res {
            0 => Ok(Interface::new(unsafe {
                CStr::from_ptr(ifreq.ifr_name.as_ptr())
            })?),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Returns statistics on packets received and dropped by the socket.
    pub fn stats(&self) -> io::Result<PacketStatistics> {
        let mut stats = bpf_stat {
            bs_recv: 0,
            bs_drop: 0,
        };

        let res = unsafe { libc::ioctl(self.fd, BIOCGSTATS, ptr::addr_of_mut!(stats)) };
        match res {
            0.. => Ok(PacketStatistics {
                received: stats.bs_recv,
                dropped: stats.bs_drop,
            }),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Sets the socket to return immediately on packet reception.
    pub fn set_immediate(&self, immediate: bool) -> io::Result<()> {
        let mut immediate: libc::c_uint = if immediate { 1 } else { 0 };

        let res = unsafe { libc::ioctl(self.fd, BIOCIMMEDIATE, ptr::addr_of_mut!(immediate)) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Enables or disables nonblocking I/O for the given socket.
    ///
    /// When enabled, calls to [`send()`](Self::send) or [`recv()`](Self::recv) will return an error
    /// of kind [`io::ErrorKind::WouldBlock`] if the socket is unable to immediately send or receive
    /// a packet.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking: libc::c_int = if nonblocking { 1 } else { 0 };

        let res = unsafe { libc::ioctl(self.fd, libc::FIONBIO, ptr::addr_of_mut!(nonblocking)) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Enables or disables capture of packets that are specifically sent out by the socket via
    /// `send()`[Self::send].
    ///
    /// When enabled, injected link-layer packets sent via [`send()`](Self::send) will appear in
    /// subsequent calls to [`recv()`](Self::recv).
    ///
    /// This option is set to disabled by default.
    pub fn set_feedback(&self, allow_feedback: bool) -> io::Result<()> {
        let mut allow_feedback: libc::c_int = if allow_feedback { 1 } else { 0 };

        let res = unsafe { libc::ioctl(self.fd, BIOCFEEDBACK, ptr::addr_of_mut!(allow_feedback)) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Locks the socket from further configuration changes.
    pub fn lock(&self) -> io::Result<()> {
        let res = unsafe { libc::ioctl(self.fd, BIOCLOCK) };
        match res {
            0.. => Ok(()),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Send a link-layer packet on the interface bound to the given socket.
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        let res = unsafe {
            libc::write(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
            )
        };
        match res {
            0.. => Ok(res as usize),
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Receive a link-layer packet.
    pub fn recv<'a>(&self, buf: &'a mut [u8]) -> io::Result<RxFrame<'a>> {
        let res = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        match res {
            0.. => {
                let data = &mut buf[..res as usize];
                RxFrameIter { rem: data }.next().ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "recv() returned corrupt frame--insufficient buffer length?",
                ))
            }
            _ => Err(io::Error::from_raw_os_error(unsafe { *libc::__error() })),
        }
    }

    /// Enable memory-mapped I/O for incoming packets.
    ///
    /// In the event of failure, the consumed `L2Socket` will automatically be closed.
    pub fn packet_rx_ring(self, buffer_size: usize) -> io::Result<L2RxMappedSocket> {
        let flags = libc::MAP_ANONYMOUS; // MAP_ANONYMOUS initializes contents to zero.
        let prot = libc::PROT_READ | libc::PROT_WRITE;

        let ringbuf = unsafe { libc::mmap(ptr::null_mut(), buffer_size * 2, prot, flags, -1, 0) };
        if ringbuf == libc::MAP_FAILED {
            let errno = unsafe { *libc::__error() };
            // Clean up socket
            unsafe { libc::close(self.fd) };
            return Err(io::Error::from_raw_os_error(errno));
        }

        let mut req = bpf_zbuf {
            bz_bufa: ringbuf,
            bz_bufb: unsafe { (ringbuf as *mut u8).add(buffer_size) as *mut libc::c_void },
            bz_buflen: buffer_size,
        };

        let res = unsafe { libc::ioctl(self.fd, BIOCSETZBUF, ptr::addr_of_mut!(req)) };
        match res {
            0.. => Ok(L2RxMappedSocket {
                l2: self,
                raw: ringbuf,
                buflen: buffer_size,
                recv_idx: ReceiveIndex::FirstBlock(0),
            }),
            _ => {
                // Clean up socket and mmap
                unsafe { libc::close(self.fd) };
                unsafe { libc::munmap(ringbuf, buffer_size * 2) };

                Err(io::Error::from_raw_os_error(unsafe { *libc::__error() }))
            }
        }
    }
}

impl Drop for L2Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

pub struct L2RxMappedSocket {
    l2: L2Socket,
    raw: *mut libc::c_void,
    buflen: usize,
    recv_idx: ReceiveIndex,
}

impl L2RxMappedSocket {
    #[inline]
    pub fn rx_ring(&mut self) -> RxRing<'_> {
        RxRing {
            block_1: self.raw,
            block_2: unsafe { (self.raw as *mut u8).add(self.buflen) as *mut libc::c_void },
            recv_idx: &mut self.recv_idx,
        }
    }

    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.l2.send(packet)
    }

    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrame<'_>> {
        let (raw, block_idx) = match self.recv_idx {
            ReceiveIndex::FirstBlock(i) => (self.raw, i),
            ReceiveIndex::SecondBlock(i) => unsafe {
                (
                    (self.raw as *mut u8).add(self.buflen) as *mut libc::c_void,
                    i,
                )
            },
        };

        let data = unsafe { RxBlock::block_parts(raw)?.1 };
        let mut iter = RxFrameIter {
            rem: &mut data[block_idx..],
        };

        let prev_len = iter.rem.len();
        let frame = iter.next();

        if frame.is_some() {
            self.recv_idx.increment(prev_len - iter.rem.len());
        } else {
            self.recv_idx.swap();
        };

        frame
    }
}

impl Drop for L2RxMappedSocket {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.raw, self.buflen * 2) };
        // close() is called on the fd when the inner l2 socket is dropped
        // It shouldn't matter whether munmap or close is called first
    }
}

pub struct RxRing<'a> {
    block_1: *mut libc::c_void,
    block_2: *mut libc::c_void,
    recv_idx: &'a mut ReceiveIndex,
}

impl<'a> RxRing<'a> {
    pub fn first_block(&'a mut self) -> Option<RxBlock<'a>> {
        let (header, data) = unsafe { RxBlock::block_parts(self.block_1)? };
        Some(RxBlock {
            header,
            data,
            is_first_block: true,
            recv_idx: &mut self.recv_idx,
        })
    }

    pub fn second_block(&'a mut self) -> Option<RxBlock<'a>> {
        let (header, data) = unsafe { RxBlock::block_parts(self.block_2)? };
        Some(RxBlock {
            header,
            data,
            is_first_block: false,
            recv_idx: &mut self.recv_idx,
        })
    }
}

pub struct RxBlock<'a> {
    header: &'a mut BpfHeader,
    data: &'a mut [u8],
    is_first_block: bool,
    recv_idx: &'a mut ReceiveIndex,
}

impl<'a> RxBlock<'a> {
    unsafe fn block_parts(buf: *mut libc::c_void) -> Option<(&'a mut BpfHeader, &'a mut [u8])> {
        let header = &mut *(buf as *mut BpfHeader);
        let buf_start = (buf as *mut u8).add(mem::size_of::<BpfHeader>());

        let user_gen = header.bzh_user_gen.load(Ordering::Acquire);
        let kernel_gen = header.bzh_kernel_gen.load(Ordering::Acquire);

        if user_gen == kernel_gen {
            None
        } else {
            let kernel_len = header.bzh_kernel_len.load(Ordering::Acquire) as usize;
            Some((header, slice::from_raw_parts_mut(buf_start, kernel_len)))
        }
    }

    #[inline]
    pub fn frames(&'a mut self) -> RxFrameIter<'a> {
        RxFrameIter { rem: self.data }
    }

    pub fn mark_read(self) {
        // Mark the recv index of the mapped socket as stale if necessary
        if self.is_first_block {
            if let ReceiveIndex::FirstBlock(_) = self.recv_idx {
                *self.recv_idx = ReceiveIndex::SecondBlock(0);
            }
        } else {
            if let ReceiveIndex::SecondBlock(_) = self.recv_idx {
                *self.recv_idx = ReceiveIndex::FirstBlock(0);
            }
        }

        // Mark the block as ready to be written to by the kernel
        let kernel_gen = self.header.bzh_kernel_gen.load(Ordering::Acquire);
        self.header
            .bzh_user_gen
            .store(kernel_gen, Ordering::Release);
    }
}

pub struct RxFrameIter<'a> {
    rem: &'a mut [u8],
}

impl<'a> Iterator for RxFrameIter<'a> {
    type Item = RxFrame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem.len() < mem::size_of::<bpf_xhdr>() {
            return None;
        }

        let hdr_bytes = &self.rem[..mem::size_of::<bpf_xhdr>()];
        let hdr = unsafe { &*(hdr_bytes.as_ptr() as *const bpf_xhdr) };

        let caplen = hdr.bh_caplen as usize;
        let datalen = hdr.bh_datalen as usize;
        let hdrlen = hdr.bh_hdrlen as usize;
        let tstamp = hdr.bh_tstamp;

        let offset_to_start = hdrlen.saturating_sub(mem::size_of::<bpf_xhdr>());
        let unpadded_len = hdrlen + caplen;
        let padded_len = BPF_WORDALIGN(unpadded_len);
        let padding = padded_len - unpadded_len;

        if self.rem.len() < padded_len {
            return None;
        }

        let rem = mem::replace(&mut self.rem, &mut []);
        let rem = &mut rem[offset_to_start..];
        let (pkt, rem) = rem.split_at_mut(caplen);

        self.rem = rem.get_mut(padding..).unwrap_or(&mut []);
        Some(RxFrame {
            data: pkt,
            orig_len: datalen,
            timestamp: tstamp,
        })
    }
}

pub struct RxFrame<'a> {
    data: &'a mut [u8],
    orig_len: usize,
    timestamp: bpf_ts,
}

impl RxFrame<'_> {
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data
    }

    #[inline]
    pub fn original_len(&self) -> usize {
        self.orig_len
    }

    #[inline]
    pub fn frame_len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn truncated(&self) -> bool {
        self.original_len() != self.frame_len()
    }

    pub fn timestamp(&self) -> bpf_ts {
        self.timestamp
    }
}

// TODO: need to provide ergonomic semantics for writing BPF programs within rust.
