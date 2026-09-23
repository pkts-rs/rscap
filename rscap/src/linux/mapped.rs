// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Structures used for memory-mapped packet sockets.
//!
//! These structures transparently perform the necessary `setsockopt(PACKET_RX_RING)` and `mmap()`
//! procedures to enable zero-copy transmission and reception of packets over a socket.

use std::ptr::NonNull;
use std::sync::atomic::{self, Ordering};
use std::time::Duration;
use std::{cmp, io, mem, ptr, slice};

/// Specifies block and frame size/count for a memory-mapped socket.
#[derive(Clone, Copy)]
pub struct BlockConfig {
    /// The size of each block allocated to the ring buffer. Must be a multiple of PAGE_SIZE
    /// (which depends on the architecture of your runtime, but is usually 4096), and should be
    /// a power of 2.
    ///
    /// To ensure correct operation, this value should be at least `frame_size` + 32
    block_size: u32,
    /// The number of blocks allocated to the ring buffer.
    block_cnt: u32,
    /// The maximum size of the frames that store each packet. Must be a multiple of
    /// [`libc::TPACKET_ALIGNMENT`] (i.e., 16).
    ///
    /// This value is related to the snap length of a packet (but should not be confused with it!);
    /// the frame contains header and address information in addition to packet data. To guarantee
    /// that packets with a maximum snaplen (`65535`) will be received, a `frame_size` of at least
    /// `65648` should be used. Note that using a larger `frame_size` will not result in wasted
    /// space at the end of each packet for RX rings--frames are dynamically sized to take up the
    /// minimum space needed to represent a packet.
    frame_size: u32,

    // TODO: ^ what about for TX rings?
    frame_cnt: u32,

    map_length: usize,
}

impl BlockConfig {
    /// Constructs a new [`BlockConfig`] from the given parameters.
    ///
    /// The parameters have the following restrictions:
    /// - `block_size` must be a power-of-two multiple of the page size of the machine (often 4096).
    /// - `frame_size` must be a multiple of 16, and must be ab.
    ///
    /// This method checks for overflowing sizes; it is generally guaranteed to succeed as long as
    /// `block_size` * `block_cnt` does not exceed 2^31.
    pub fn new(block_size: u32, block_cnt: u32, frame_size: u32) -> io::Result<Self> {
        let Some(map_length) = (block_size as usize).checked_mul(block_cnt as usize) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overflowing total ring size",
            ));
        };

        // Check the case that a user maps TX+RX ring
        if map_length.checked_mul(2).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overflowing total ring size",
            ));
        }

        let Some(frame_cnt) = (block_size / frame_size).checked_mul(block_cnt) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overflowing total frame count",
            ));
        };

        Ok(BlockConfig {
            block_size,
            block_cnt,
            frame_size,
            frame_cnt,
            map_length,
        })
    }

    /// The configured size of each memory block.
    #[inline]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// The configured number of memory blocks to be used.
    #[inline]
    pub fn block_cnt(&self) -> u32 {
        self.block_cnt
    }

    /// The configured maximum number of bytes each frame can take up.
    #[inline]
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    /// The total number of frames that can be stored in the memory-mapped region.
    #[inline]
    pub fn frame_cnt(&self) -> u32 {
        self.frame_cnt
    }

    /// The total size (in bytes) of the memory-mapped region.
    #[inline]
    pub fn map_length(&self) -> usize {
        self.map_length
    }
}

/// A reception-oriented ring buffer associated with a socket.
pub struct PacketRxRing {
    ring_start: NonNull<u8>,
    block_size: usize,
    block_cnt: usize,
    block_idx: usize,
    frame_offset: usize,
    rem_frames: usize,
    priv_size: usize,
}

impl PacketRxRing {
    /// Constructs a new `PacketRxRing` instance from a raw memory-mapped segment and configuration.
    pub(crate) unsafe fn new(
        ring_start: NonNull<u8>,
        config: BlockConfig,
        priv_size: usize,
    ) -> Self {
        PacketRxRing {
            ring_start,
            block_size: config.block_size() as usize,
            block_cnt: config.block_cnt() as usize,
            block_idx: 0,
            frame_offset: 0,
            rem_frames: 0,
            priv_size,
        }
    }

    pub(crate) fn ring_start(&self) -> NonNull<u8> {
        self.ring_start
    }

    pub(crate) fn ring_size(&self) -> usize {
        self.block_cnt * self.block_size
    }

    pub fn next_frame(&mut self) -> Option<RxFrame<'_>> {
        if self.frame_offset == self.block_size {
            let block_start = unsafe { self.ring_start.add(self.block_idx * self.block_size) };
            let status_ptr = unsafe {
                block_start
                    .add(mem::offset_of!(
                        crate::linux::tpacket_block_desc,
                        hdr.bh1.block_status
                    ))
                    .cast::<u32>()
            };

            // Mark the current block as finished so the kernel can fill it again
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Release);
            unsafe {
                ptr::write_volatile(status_ptr.as_ptr(), libc::TP_STATUS_KERNEL);
            }

            self.block_idx = (self.block_idx + 1) % self.block_cnt;
            self.frame_offset = 0;
        }

        let block_start = unsafe { self.ring_start.add(self.block_idx * self.block_size) };

        if self.frame_offset == 0 {
            // Need to check if block is ready for reading
            let status_ptr = unsafe {
                block_start
                    .add(mem::offset_of!(
                        crate::linux::tpacket_block_desc,
                        hdr.bh1.block_status
                    ))
                    .cast::<u32>()
            };
            let status = unsafe { ptr::read_volatile(status_ptr.as_ptr().cast_const()) };
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Acquire);

            if status & crate::linux::TP_STATUS_USER == 0 {
                return None;
            }

            let hdr = unsafe {
                block_start
                    .add(mem::offset_of!(crate::linux::tpacket_block_desc, hdr.bh1))
                    .cast::<crate::linux::tpacket_hdr_v1>()
                    .as_ref()
            };

            self.rem_frames = hdr.num_pkts as usize;
            self.frame_offset = hdr.offset_to_first_pkt as usize;
        }

        assert!(self.frame_offset < self.block_size);
        assert!(self.rem_frames > 0);

        self.rem_frames -= 1;

        let frame_hdr = unsafe {
            block_start
                .add(self.frame_offset)
                .cast::<crate::linux::tpacket3_hdr>()
                .as_ref()
        };

        let ll_addr = unsafe {
            block_start
                .add(self.frame_offset)
                .add(tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>()))
                .cast::<libc::sockaddr_ll>()
                .read()
        };

        let timestamp = Duration::from_secs(frame_hdr.tp_sec.into())
            + Duration::from_nanos(frame_hdr.tp_nsec.into());

        self.frame_offset = if self.rem_frames == 0 {
            self.block_size
        } else {
            frame_hdr.tp_next_offset as usize
        };

        let original_len = frame_hdr.tp_len as usize;

        let packet = unsafe {
            slice::from_raw_parts_mut(
                block_start
                    .add(self.frame_offset)
                    .add(frame_hdr.tp_mac.into())
                    .as_ptr(),
                frame_hdr.tp_snaplen as usize,
            )
        };

        let status_flags = frame_hdr.tp_status;
        let rxhash = frame_hdr.hv1.tp_rxhash;
        let vlan_tci = frame_hdr.hv1.tp_vlan_tci;
        let vlan_tpid = frame_hdr.hv1.tp_vlan_tpid;

        Some(RxFrame {
            ll_addr,
            packet,
            original_len,
            timestamp,
            status_flags,
            rxhash,
            vlan_tci,
            vlan_tpid,
        })
    }

    pub fn rx_block(&mut self) -> Option<RxBlock<'_>> {
        if self.frame_offset == self.block_size {
            let block_start = unsafe { self.ring_start.add(self.block_idx * self.block_size) };
            let status_ptr = unsafe {
                block_start
                    .add(mem::offset_of!(
                        crate::linux::tpacket_block_desc,
                        hdr.bh1.block_status
                    ))
                    .cast::<u32>()
            };

            // Mark the current block as finished so the kernel can fill it again
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Release);
            unsafe {
                ptr::write_volatile(status_ptr.as_ptr(), libc::TP_STATUS_KERNEL);
            }

            self.block_idx = (self.block_idx + 1) % self.block_cnt;
            self.frame_offset = 0;
        }

        let block_start = unsafe { self.ring_start.add(self.block_idx * self.block_size) };

        if self.frame_offset == 0 {
            // Need to check if block is ready for reading
            let status_ptr = unsafe {
                block_start
                    .add(mem::offset_of!(
                        crate::linux::tpacket_block_desc,
                        hdr.bh1.block_status
                    ))
                    .cast::<u32>()
            };
            let status = unsafe { ptr::read_volatile(status_ptr.as_ptr().cast_const()) };
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Acquire);

            if status & crate::linux::TP_STATUS_USER == 0 {
                return None;
            }

            let hdr = unsafe {
                block_start
                    .add(mem::offset_of!(crate::linux::tpacket_block_desc, hdr.bh1))
                    .cast::<crate::linux::tpacket_hdr_v1>()
                    .as_ref()
            };

            self.rem_frames = hdr.num_pkts as usize;
            self.frame_offset = hdr.offset_to_first_pkt as usize;
        }

        let block_data =
            unsafe { slice::from_raw_parts_mut(block_start.as_ptr(), self.block_size) };

        Some(RxBlock {
            block_data,
            frame_offset: &mut self.frame_offset,
            rem_frames: &mut self.rem_frames,
            priv_size: self.priv_size,
        })
    }
}

pub struct RxBlock<'a> {
    block_data: &'a mut [u8],
    frame_offset: &'a mut usize,
    rem_frames: &'a mut usize,
    priv_size: usize,
}

impl<'a> RxBlock<'a> {
    fn header(&self) -> &libc::tpacket_block_desc {
        unsafe {
            self.block_data[..mem::size_of::<libc::tpacket_block_desc>()]
                .align_to::<libc::tpacket_block_desc>()
                .1
                .get(0)
                .unwrap()
        }
    }

    // TODO: it may be useful to have a function that splits out RxBlock from associated priv_data
    // so that accesses can happen simultaneously to block frames and private data.

    pub fn priv_data(&self) -> &[u8] {
        let hdr = self.header();
        let priv_start = hdr.offset_to_priv as usize;
        &self.block_data[priv_start..priv_start + self.priv_size]
    }

    pub fn priv_data_mut(&mut self) -> &mut [u8] {
        let hdr = self.header();
        let priv_start = hdr.offset_to_priv as usize;
        &mut self.block_data[priv_start..priv_start + self.priv_size]
    }

    pub fn next_frame(&mut self) -> Option<RxFrame<'_>> {
        if *self.frame_offset == self.block_data.len() {
            return None;
        }

        assert!(*self.frame_offset < self.block_data.len());
        assert!(*self.rem_frames > 0);

        *self.rem_frames -= 1;

        let frame_hdr = unsafe {
            self.block_data[*self.frame_offset
                ..*self.frame_offset + mem::size_of::<crate::linux::tpacket3_hdr>()]
                .align_to::<crate::linux::tpacket3_hdr>()
                .1[0]
        };

        let ll_offset =
            *self.frame_offset + tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>());
        let ll_addr = unsafe {
            self.block_data[ll_offset..ll_offset + mem::size_of::<libc::sockaddr_ll>()]
                .align_to::<libc::sockaddr_ll>()
                .1[0]
        };

        let timestamp = Duration::from_secs(frame_hdr.tp_sec.into())
            + Duration::from_nanos(frame_hdr.tp_nsec.into());

        *self.frame_offset = if *self.rem_frames == 0 {
            self.block_data.len()
        } else {
            frame_hdr.tp_next_offset as usize
        };

        let original_len = frame_hdr.tp_len as usize;

        // for cooked packets, tp_mac == tp_net so no issue here
        let pkt_start = *self.frame_offset + usize::from(frame_hdr.tp_mac);
        let packet = &mut self.block_data[pkt_start..pkt_start + frame_hdr.tp_snaplen as usize];

        let status_flags = frame_hdr.tp_status;
        let rxhash = frame_hdr.hv1.tp_rxhash;
        let vlan_tci = frame_hdr.hv1.tp_vlan_tci;
        let vlan_tpid = frame_hdr.hv1.tp_vlan_tpid;

        Some(RxFrame {
            ll_addr,
            packet,
            original_len,
            timestamp,
            status_flags,
            rxhash,
            vlan_tci,
            vlan_tpid,
        })
    }
}

/// A reception frame capable of conveying a single packet.
pub struct RxFrame<'a> {
    ll_addr: libc::sockaddr_ll,
    packet: &'a mut [u8],
    original_len: usize,
    timestamp: Duration,
    status_flags: u32,
    rxhash: u32,
    vlan_tci: u32,
    vlan_tpid: u16,
}

impl<'a> RxFrame<'a> {
    /// A zero-copy slice of the contents of the received packet.
    pub fn data(&self) -> &[u8] {
        self.packet
    }

    /// A mutable zero-copy slice of the contents of the received packet.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.packet
    }

    /// Indicates whether the packet exceeded the frame size and had to be truncated.
    pub fn is_truncated(&self) -> bool {
        self.original_len > self.packet.len()
    }

    /// The time the packet was received, measured as duration since the Unix epoch.
    #[inline]
    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    /// The Layer 2 socket address of the received packet.
    #[inline]
    pub fn ll_addr(&self) -> libc::sockaddr_ll {
        self.ll_addr
    }

    /// The non-truncated length of the packet (if the packet had to be truncated to fit the frame).
    #[inline]
    pub fn original_len(&self) -> usize {
        self.original_len
    }

    /// Indicates that the packet exceeded the frame's size and can be read in its entirity using `recvfrom()`.
    ///
    /// Note that this flag is only set if `set_copy_thresh()` has been enabled for the socket.
    #[inline]
    pub fn is_copied(&self) -> bool {
        self.status_flags & crate::linux::TP_STATUS_COPY != 0
    }

    /// Indicates there have been dropped packets since the last call to `packet_statistics()` was made
    /// on the socket.
    #[inline]
    pub fn dropped_packets(&self) -> bool {
        self.status_flags & crate::linux::TP_STATUS_LOSING != 0
    }

    /// Indicates that the packet's Internet/Transport-layer checksums will be done in hardware (and
    /// therefore should not be expected to be valid).
    ///
    /// This option is applicable to outgoing IP packets when checksum offloading is enabled.
    #[inline]
    pub fn offloaded_checksum(&self) -> bool {
        self.status_flags & crate::linux::TP_STATUS_CSUMNOTREADY != 0
    }

    /// Indicates that at least the transport header checksum has been validated by the operating system.
    ///
    /// NOTE: a return value of `false` does not necessarily mean that the packet's checksum was invalid,
    /// just that it was not checked by the operating system. In this case, the checksum may be calculated
    /// and determined to be valid or invalid in userspace.
    #[inline]
    pub fn checksum_valid(&self) -> bool {
        self.status_flags & crate::linux::TP_STATUS_CSUM_VALID != 0
    }

    /// The VLAN TCI value associated with the packet, if such a value exists.
    #[inline]
    pub fn vlan_tci(&self) -> Option<u32> {
        if self.status_flags & crate::linux::TP_STATUS_VLAN_VALID != 0 {
            Some(self.vlan_tci)
        } else {
            None
        }
    }

    /// The VLAN TPID value associated with the packet, if such a value exists.
    #[inline]
    pub fn vlan_tpid(&self) -> Option<u16> {
        if self.status_flags & crate::linux::TP_STATUS_VLAN_TPID_VALID != 0 {
            Some(self.vlan_tpid)
        } else {
            None
        }
    }

    /// The RX Hash, a hash of the packet used to select which fanout socket to send the packet to.
    ///
    /// See [`set_packet_fanout()`](super::l2::L2Socket::set_fanout()) for more information on the
    /// RX Hash.
    #[inline]
    pub fn rx_hash(&self) -> u32 {
        self.rxhash
    }
}

/// A reception-oriented ring buffer associated with a socket.
pub struct PacketTxRing {
    ring_start: NonNull<u8>,
    block_size: usize,
    block_cnt: usize,
    block_idx: usize,
    frame_size: usize,
    frame_cnt: usize,
    frame_idx: usize,
}

impl PacketTxRing {
    /// Constructs a new `PacketTxRing` instance from a raw memory-mapped segment and configuration.
    pub(crate) unsafe fn new(ring_start: NonNull<u8>, config: BlockConfig) -> Self {
        PacketTxRing {
            ring_start,
            block_size: config.block_size() as usize,
            block_cnt: config.block_cnt() as usize,
            block_idx: 0,
            frame_size: config.frame_size() as usize,
            frame_cnt: config.frame_cnt() as usize,
            frame_idx: 0,
        }
    }

    pub(crate) fn ring_start(&self) -> NonNull<u8> {
        self.ring_start
    }

    pub(crate) fn ring_size(&self) -> usize {
        self.block_cnt * self.block_size
    }

    /// Retrieves the next transmission frame located at the given offset.
    ///
    /// The behavior of `get_frame()` depends on the variant of the returned transmission frame:
    /// - [`TxFrameVariant::Available`] causes the iterator to move its index to the next available
    /// frame; a subsequent call to `next_frame()` will return a frame from the next contiguous
    /// memory location.
    /// - [`TxFrameVariant::SendRequest`] and [`TxFrameVariant::Sending`] cause the iterator to stay
    /// at the current memory location; subsequent calls to `next_frame()` will repeatedly return
    /// the same frame until the kernel has handled the frame and updated its flag.
    /// - [`TxFrameVariant::WrongFormat`] causes the iterator to stay at the current memory
    /// location. When the wrongly-formatted frame is dropped, its state will be updated to
    /// [`TxFrameVariant::Available`] and returned in the next call to `next_frame()`.
    pub fn get_frame(&mut self, block_idx: usize, frame_idx: usize) -> TxFrameVariant<'_> {
        self.get_frame_impl(block_idx, frame_idx, false)
    }

    fn get_frame_impl(
        &mut self,
        block_idx: usize,
        frame_idx: usize,
        update_frame_idx: bool,
    ) -> TxFrameVariant<'_> {
        let frame_data = unsafe {
            self.ring_start
                .add(block_idx * self.block_size)
                .add(frame_idx * self.frame_size)
        };

        if update_frame_idx {
            self.frame_idx += 1;
        }

        let status_ptr = unsafe {
            frame_data
                .add(mem::offset_of!(crate::linux::tpacket3_hdr, tp_status))
                .cast::<u32>()
        };

        let status = unsafe { ptr::read_volatile(status_ptr.as_ptr().cast_const()) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Acquire);

        if status & libc::TP_STATUS_SEND_REQUEST > 0 {
            return TxFrameVariant::SendRequest;
        } else if status & libc::TP_STATUS_SENDING > 0 {
            return TxFrameVariant::Sending;
        } else {
            let header = unsafe { frame_data.cast::<crate::linux::tpacket3_hdr>().as_mut() };

            let data = unsafe {
                slice::from_raw_parts_mut(
                    frame_data
                        .add(tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>()))
                        .as_ptr(),
                    self.frame_size - tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>()),
                )
            };

            // Zero out length, snaplen and next_offset fields to make valid
            header.tp_len = 0;
            header.tp_snaplen = 0;
            header.tp_next_offset = 0;
            header.tp_mac = 0;
            header.tp_net = 0;

            if status == libc::TP_STATUS_AVAILABLE {
                TxFrameVariant::Available(TxFrame { header, data })
            } else {
                debug_assert!(status & libc::TP_STATUS_WRONG_FORMAT > 0);
                TxFrameVariant::WrongFormat(InvalidTxFrame { header, data })
            }
        }
    }

    pub fn next_frame(&mut self) -> Option<TxFrame<'_>> {
        if self.frame_idx == self.frame_cnt {
            self.block_idx = (self.block_idx + 1) % self.block_cnt;
            self.frame_idx = 0;
        }

        let frame = match self.get_frame_impl(self.block_idx, self.frame_idx, true) {
            TxFrameVariant::Available(t) => Some(t),
            TxFrameVariant::WrongFormat(i) => Some(i.into_available()),
            TxFrameVariant::SendRequest | TxFrameVariant::Sending => None,
        }?;

        Some(frame)
    }
}

/// A transmission frame capable of conveying a single packet.
pub struct TxFrame<'a> {
    header: &'a mut crate::linux::tpacket3_hdr,
    data: &'a mut [u8],
}

impl<'a> TxFrame<'a> {
    /// Returns the mutable slice for storing a packet in.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data
    }

    /// Sets the length of the packet to `packet_len` and marks the given packet as ready to send.
    ///
    /// Note that this method does not explicitly send the packet; a call to `send()` or `poll()`
    /// is necessary for ready packets to actually be sent.
    pub fn set_length(&mut self, packet_len: usize) {
        self.header.tp_len = cmp::max(packet_len, self.data.len()) as u32;
        self.header.tp_snaplen = packet_len as u32;
    }
}

impl Drop for TxFrame<'_> {
    fn drop(&mut self) {
        atomic::compiler_fence(Ordering::Release);
        self.header.tp_status = libc::TP_STATUS_SEND_REQUEST;
    }
}

/// A transmission frame that has been marked as invalid by the kernel.
pub struct InvalidTxFrame<'a> {
    header: &'a mut crate::linux::tpacket3_hdr,
    data: &'a mut [u8],
}

impl<'a> InvalidTxFrame<'a> {
    /// Returns the network packet previously scheduled to be sent that resulted in an invalid
    /// transmission frame designation.
    pub fn packet(&self) -> &[u8] {
        &self.data[..self.header.tp_len as usize]
    }

    /// A zero-copy slice of the contents of the invalid packet.
    #[inline]
    pub fn into_available(self) -> TxFrame<'a> {
        self.header.tp_status = libc::TP_STATUS_AVAILABLE;
        TxFrame {
            header: self.header,
            data: self.data,
        }
    }
}

/// An individual transmission frame in one of its possible states.
///
/// The variant represents the state of the frame _at the time the frame is accessed_. The kernel
/// may modify the underlying state of a [`SendRequest`](TxFrameVariant::SendRequest) or
/// [`Sending`](TxFrameVariant::Sending) frame at any time, so they should not be relied on as an
/// indicator of state over time. Instead, call [`PacketTxFrameIter::next_frame()`] each time state
/// needs to be checked.
pub enum TxFrameVariant<'a> {
    /// An unused transmission frame, suitable for writing a packet to.
    Available(TxFrame<'a>),
    /// A transmission frame that has been marked as ready to send by the user.
    SendRequest,
    /// A transmission frame that is being processed and sent out by the kernel.
    Sending,
    /// A transmission frame that could not be sent by the kernel due to errors in packet structure.
    WrongFormat(InvalidTxFrame<'a>),
}

// ==============================================
//              Helper Functions
// ==============================================

const fn tpacket_align(len: usize) -> usize {
    // identical to libc::TPACKET_ALIGN(), but const and safe
    (len + crate::linux::TPACKET_ALIGNMENT - 1) & !(crate::linux::TPACKET_ALIGNMENT - 1)
}
