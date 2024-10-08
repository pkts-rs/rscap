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

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, mem, slice};

/// An index pointing to a particular frame within a `MappedSocket` block.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameIndex {
    /// The index of the block currently being read/written.
    pub blocks_index: usize,
    /// The byte offset to the frame within the specified block (`None` indicates the first frame).
    pub frame_offset: Option<usize>,
}

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

        let Some(frame_cnt_usize) = map_length.checked_div(frame_size as usize) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overflowing total frame count",
            ));
        };

        let Ok(frame_cnt) = u32::try_from(frame_cnt_usize) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overflowing total frame size",
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

/// The OSI layer used by the TPACKET_RX_RING.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsiLayer {
    /// Link-layer packet.
    L2,
    /// Network-layer packet.
    L3,
}

/// A reception-oriented ring buffer associated with a socket.
pub struct PacketTxRing {
    ring_start: *mut u8,
    block_size: usize,
    blocks: Vec<PacketTxBlock>,
}

impl PacketTxRing {
    /// Constructs a new `PacketTxRing` instance from a raw memory-mapped segment and configuration.
    pub(crate) unsafe fn new(ring_start: *mut u8, config: BlockConfig) -> Self {
        let frame_size = config.frame_size as usize;
        let block_cnt = config.block_cnt as usize;
        let block_size = config.block_size as usize;

        debug_assert!(block_size >= mem::size_of::<crate::linux::tpacket_block_desc>());

        let mut blocks = Vec::new();

        for i in 0..block_cnt {
            let block_slice = slice::from_raw_parts_mut(ring_start.add(block_size * i), block_size);
            let (description_bytes, block_slice) =
                block_slice.split_at_mut(mem::size_of::<crate::linux::tpacket_block_desc>());

            // SAFETY: each block must begin with an initialized tpacket_block_desc
            let block_description = unsafe {
                (description_bytes.as_mut_ptr() as *mut crate::linux::tpacket_block_desc)
                    .as_mut()
                    .unwrap()
            };

            debug_assert!(block_description.version == 1);

            let first_frame_offset =
                unsafe { block_description.hdr.bh1.offset_to_first_pkt as usize };
            let frames = &mut block_slice[first_frame_offset..];

            blocks.push(PacketTxBlock {
                description: block_description,
                frames,
                frame_size,
            });
        }

        Self {
            ring_start,
            blocks,
            block_size,
        }
    }

    #[inline]
    pub(crate) unsafe fn mapped_start(&mut self) -> *mut u8 {
        self.ring_start
    }

    #[inline]
    pub(crate) fn mapped_size(&self) -> usize {
        self.block_size * self.blocks.len()
    }

    /// A mutable slice of the transmission blocks the ring is composed of.
    #[inline]
    pub fn blocks(&mut self) -> &mut [PacketTxBlock] {
        &mut self.blocks
    }

    #[inline]
    pub(crate) fn blocks_cnt(&self) -> usize {
        self.blocks.len()
    }

    pub(crate) fn next_frame(&mut self, mut index: FrameIndex) -> (TxFrameVariant<'_>, FrameIndex) {
        let frame_offset = match index.frame_offset {
            Some(o) => o,
            None => {
                index.blocks_index = (index.blocks_index + 1) % self.blocks.len();
                let block = &mut self.blocks[index.blocks_index];
                block.block_header().offset_to_first_pkt as usize
            }
        };

        let block = &mut self.blocks[index.blocks_index];

        let (frame, new_offset) =
            PacketTxFrameIter::next_with_offset(block.frames, block.frame_size, frame_offset);

        index.frame_offset = new_offset;

        (frame, index)
    }
}

/// An individual block in a reception-oriented ring buffer.
pub struct PacketTxBlock {
    description: &'static mut crate::linux::tpacket_block_desc,
    frames: &'static mut [u8],
    frame_size: usize,
}

impl PacketTxBlock {
    #[inline]
    fn block_header(&self) -> &crate::linux::tpacket_hdr_v1 {
        // SAFETY: the `tpacket_bd_hdr_u` union has only one variant, so this access is memory-safe.
        unsafe { &self.description.hdr.bh1 }
    }

    /// The sequence number of the block.
    #[inline]
    pub fn seq(&self) -> u64 {
        self.block_header().seq_num
    }

    /// The number of packets contained within the block.
    #[inline]
    pub fn packet_cnt(&self) -> usize {
        self.block_header().num_pkts as usize
    }

    /// Returns an iterator over the packets contained within the block.
    #[inline]
    pub fn packets(&mut self) -> PacketTxFrameIter<'_> {
        let first_offset = self.block_header().offset_to_first_pkt as usize;
        PacketTxFrameIter {
            frames: self.frames,
            frame_size: self.frame_size,
            curr_offset: Some(first_offset),
        }
    }
}

/// An iterator over frames within a given transmission block.
pub struct PacketTxFrameIter<'a> {
    frames: &'a mut [u8],
    frame_size: usize,
    curr_offset: Option<usize>,
}

impl<'a> PacketTxFrameIter<'a> {
    /// Retrieves the next available transmission frame (or `None` if no frames remain).
    ///
    /// The behavior of `next_frame()` depends on the variant of the returned transmission frame:
    /// - [`TxFrameVariant::Available`] causes the iterator to move its index to the next available
    /// frame; a subsequent call to `next_frame()` will return a frame from the next contiguous
    /// memory location.
    /// - [`TxFrameVariant::SendRequest`] and [`TxFrameVariant::Sending`] cause the iterator to stay
    /// at the current memory location; subsequent calls to `next_frame()` will repeatedly return
    /// the same frame until the kernel has handled the frame and updated its flag.
    /// - [`TxFrameVariant::WrongFormat`] causes the iterator to stay at the current memory
    /// location. When the wrongly-formatted frame is dropped, its state will be updated to
    /// [`TxFrameVariant::Available`] and returned in the next call to `next_frame()`.
    #[inline]
    pub fn next_frame(&'a mut self) -> Option<TxFrameVariant<'a>> {
        let (frame, new_offset) =
            Self::next_with_offset(self.frames, self.frame_size, self.curr_offset?);
        if let TxFrameVariant::Available(_) = frame {
            self.curr_offset = new_offset;
        }
        Some(frame)
    }

    /// Indicates whether any frames are left to iterate over.
    pub fn has_remaining_frames(&self) -> bool {
        self.curr_offset.is_some()
    }

    fn next_with_offset(
        frames: &'a mut [u8],
        frame_size: usize,
        offset: usize,
    ) -> (TxFrameVariant<'a>, Option<usize>) {
        let frames_len = frames.len();

        let curr_frame_data = &mut frames[offset..];

        let (header_data, rem) = curr_frame_data
            .split_at_mut(tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>()));
        // SAFETY: tpacket3_header must be present at this data offset
        let header = unsafe {
            (header_data.as_mut_ptr() as *mut crate::linux::tpacket3_hdr)
                .as_mut()
                .unwrap()
        };

        // TX_RING omits `sockaddr_ll` from its frame

        let frame_end = offset + frame_size;
        let next_offset = if frame_end < frames_len {
            Some(frame_end)
        } else {
            None
        };

        // SAFETY: packet is permitted to be stored in the remaining bytes of data after `mac_offset`
        let packet = &mut rem[..frame_end];

        let frame_variant = match header.tp_status {
            crate::linux::TP_STATUS_AVAILABLE => {
                header.tp_next_offset = 0;
                header.tp_len = 0;
                header.tp_snaplen = 0;
                TxFrameVariant::Available(TxFrame { header, packet })
            }
            crate::linux::TP_STATUS_SEND_REQUEST => TxFrameVariant::SendRequest,
            crate::linux::TP_STATUS_SENDING => TxFrameVariant::Sending,
            crate::linux::TP_STATUS_WRONG_FORMAT => {
                TxFrameVariant::WrongFormat(InvalidTxFrame { header, packet })
            }
            _ => TxFrameVariant::WrongFormat(InvalidTxFrame { header, packet }),
        };

        (frame_variant, next_offset)
    }
}

/// An individual transmission frame.
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

/// A transmission frame capable of conveying a single packet.
pub struct TxFrame<'a> {
    header: &'a mut crate::linux::tpacket3_hdr,
    packet: &'a mut [u8],
}

impl TxFrame<'_> {
    /// A zero-copy slice of the contents of the packet to be sent.
    ///
    /// The returned slice should only be used to write
    /// Once a packet has been written into this slice, the length of the packet must also be set
    /// using [`send()`](Self::send()) for the packet to be correctly transmitted.
    #[inline]
    pub fn data(&mut self) -> &mut [u8] {
        self.packet
    }

    /// Sets the length of the packet and marks it as ready to be transmitted.
    ///
    /// The length of the packet must not exceed the length of the writable data slice (returned by
    /// [`data()`](Self::data())).
    #[inline]
    pub fn send(self, packet_length: u32) {
        assert!(packet_length as usize <= self.packet.len());

        self.header.tp_len = packet_length;
        self.header.tp_snaplen = packet_length;
        self.header.tp_status = crate::linux::TP_STATUS_SEND_REQUEST;
    }
}

/// A transmission frame that has been marked as invalid by the kernel.
///
/// When dropped, this structure will mark its frame as available for use in subsequent packet
/// transmissions.
pub struct InvalidTxFrame<'a> {
    header: &'a mut crate::linux::tpacket3_hdr,
    packet: &'a mut [u8],
}

impl InvalidTxFrame<'_> {
    /// A zero-copy slice of the contents of the invalid packet.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.packet
    }
}

impl Drop for InvalidTxFrame<'_> {
    fn drop(&mut self) {
        self.header.tp_len = 0;
        self.header.tp_snaplen = 0;
        self.header.tp_status = crate::linux::TP_STATUS_AVAILABLE;
    }
}

/// The availability status of a given RX block or frame.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PacketRxStatus {
    /// The block is unavailable and/or being written to by the kerne.
    Kernel,
    /// The block/frame is ready for use.
    User,
}

/// A reception-oriented ring buffer associated with a socket.
pub struct PacketRxRing {
    ring_start: *mut u8,
    block_size: usize,
    blocks: Vec<PacketRxBlock>,
}

impl PacketRxRing {
    /// Constructs a new `PacketRxRing` instance from a raw memory-mapped segment and configuration.
    pub(crate) unsafe fn new(
        ring_start: *mut u8,
        config: BlockConfig,
        priv_size: usize,
        osi_layer: OsiLayer,
    ) -> Self {
        let frame_size = config.frame_size as usize;
        let block_cnt = config.block_cnt as usize;
        let block_size = config.block_size as usize;

        debug_assert!(frame_size >= mem::size_of::<crate::linux::tpacket_block_desc>());

        let mut blocks = Vec::new();

        for i in 0..block_cnt {
            let block_slice = slice::from_raw_parts_mut(ring_start.add(block_size * i), block_size);
            let (description_bytes, block_slice) =
                block_slice.split_at_mut(mem::size_of::<crate::linux::tpacket_block_desc>());

            // SAFETY: each block must begin with an initialized tpacket_block_desc
            let block_description = unsafe {
                (description_bytes.as_mut_ptr() as *mut crate::linux::tpacket_block_desc)
                    .as_mut()
                    .unwrap()
            };

            debug_assert!(block_description.version == 1);

            let priv_offset = block_description.offset_to_priv as usize
                - mem::size_of::<crate::linux::tpacket_block_desc>();
            let first_frame_offset =
                unsafe { block_description.hdr.bh1.offset_to_first_pkt as usize };

            let (uninit_priv_data, frames) = block_slice.split_at_mut(first_frame_offset);

            // SAFETY: private data is initialized to 0 when `mmap` is first called and determined solely by the user thereafter.
            let priv_data = &mut uninit_priv_data[priv_offset..priv_offset + priv_size];

            blocks.push(PacketRxBlock {
                description: block_description,
                frames,
                priv_data,
                osi_layer,
            });
        }

        Self {
            ring_start,
            blocks,
            block_size,
        }
    }

    #[inline]
    pub(crate) unsafe fn mapped_start(&mut self) -> *mut u8 {
        self.ring_start
    }

    #[inline]
    pub(crate) fn mapped_size(&self) -> usize {
        self.block_size * self.blocks.len()
    }

    /// A mutable slice of the transmission blocks the ring is composed of.
    #[inline]
    pub fn blocks(&mut self) -> &mut [PacketRxBlock] {
        &mut self.blocks
    }

    #[inline]
    pub(crate) fn blocks_cnt(&self) -> usize {
        self.blocks.len()
    }

    pub(crate) fn next_frame(
        &mut self,
        mut index: FrameIndex,
    ) -> Option<(RxFrame<'_>, FrameIndex)> {
        let frame_offset = match index.frame_offset {
            Some(o) => o,
            None => {
                let block_index = (index.blocks_index + 1) % self.blocks.len();
                let block = &mut self.blocks[index.blocks_index];
                if (block.block_header().block_status & crate::linux::TP_STATUS_USER) == 0 {
                    return None; // No data from the next block is ready to be read yet
                }

                let frame_offset = block.block_header().offset_to_first_pkt as usize;

                index.blocks_index = block_index;
                index.frame_offset = Some(frame_offset);
                frame_offset
            }
        };

        let block = &mut self.blocks[index.blocks_index];

        let (frame, new_offset) = PacketRxFrameIter::next_with_offset(
            block.frames,
            block.packet_cnt(),
            block.block_header().offset_to_first_pkt as usize,
            frame_offset,
            block.osi_layer,
        )?;

        let next_index = FrameIndex {
            blocks_index: index.blocks_index,
            frame_offset: new_offset,
        };

        Some((frame, next_index))
    }
}

/// An individual block in a reception-orieented ring buffer.
pub struct PacketRxBlock {
    description: &'static mut crate::linux::tpacket_block_desc,
    priv_data: &'static mut [u8],
    frames: &'static mut [u8],
    osi_layer: OsiLayer,
}

impl PacketRxBlock {
    #[inline]
    fn block_header(&self) -> &crate::linux::tpacket_hdr_v1 {
        // SAFETY: the `tpacket_bd_hdr_u` union has only one variant, so this access is memory-safe.
        unsafe { &self.description.hdr.bh1 }
    }

    // TODO: this needs to be atomically accessed--we might want to wrap the
    // entire PacketRxBlock as a typestate of ready or not
    /// The sequence number of the block.
    #[inline]
    pub fn seq(&self) -> u64 {
        self.block_header().seq_num
    }

    /// The availability status of the block.
    #[inline]
    pub fn status(&self) -> PacketRxStatus {
        if (self.block_header().block_status & crate::linux::TP_STATUS_USER) != 0 {
            PacketRxStatus::User
        } else {
            PacketRxStatus::Kernel
        }
    }

    /// The number of packets contained within the block.
    #[inline]
    pub fn packet_cnt(&self) -> usize {
        self.block_header().num_pkts as usize
    }

    /// Returns an iterator over the packets contained within the block.
    pub fn packets(&mut self) -> PacketRxFrameIter<'_> {
        let remainder = self.block_header().num_pkts as usize;
        let init_offset = self.block_header().offset_to_first_pkt as usize;

        PacketRxFrameIter {
            frames: self.frames,
            frame_cnt: remainder,
            init_offset,
            curr_offset: Some(init_offset),
            pkt_layer: self.osi_layer,
        }
    }

    #[inline]
    pub fn private_data(&mut self) -> &mut [u8] {
        self.priv_data
    }
}

/// An iterator over frames within a given reception block.
pub struct PacketRxFrameIter<'a> {
    frames: &'a mut [u8],
    frame_cnt: usize,
    init_offset: usize,
    curr_offset: Option<usize>,
    pkt_layer: OsiLayer,
}

impl<'a> PacketRxFrameIter<'a> {
    /// Retrieves the next available reception frame (or `None` if no frames remain).
    pub fn next_frame(&'a mut self) -> Option<RxFrame<'a>> {
        let (frame, new_offset) = Self::next_with_offset(
            self.frames,
            self.frame_cnt,
            self.init_offset,
            self.curr_offset?,
            self.pkt_layer,
        )?;

        self.frame_cnt -= 1;
        self.curr_offset = new_offset;
        Some(frame)
    }

    fn next_with_offset(
        frames: &'a mut [u8],
        frame_cnt: usize,
        init_offset: usize,
        curr_offset: usize,
        pkt_layer: OsiLayer,
    ) -> Option<(RxFrame<'a>, Option<usize>)> {
        if frame_cnt == 0 {
            return None;
        }

        // `frames` was initially shifted forward by `offset_to_first_pkt` bytes
        // This, combined with the current frame shift and the packet header and sockaddr shifts, gives us our final adjusted offset value
        let full_offset = init_offset
            + curr_offset
            + tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>())
            + mem::size_of::<libc::sockaddr_ll>();

        let curr_frame_data = &mut frames[curr_offset..];

        let (header_data, rem) = curr_frame_data
            .split_at_mut(tpacket_align(mem::size_of::<crate::linux::tpacket3_hdr>()));
        // SAFETY: tpacket3_header must be present at this data offset
        let header = unsafe {
            (header_data.as_mut_ptr() as *mut crate::linux::tpacket3_hdr)
                .as_mut()
                .unwrap()
        };

        let (sockaddr_data, rem) = rem.split_at_mut(mem::size_of::<libc::sockaddr_ll>());
        // SAFETY: sockaddr_ll must be present at this data offset
        let sockaddr = unsafe {
            (sockaddr_data.as_mut_ptr() as *mut libc::sockaddr_ll)
                .as_mut()
                .unwrap()
        };

        let pkt_offset = match pkt_layer {
            OsiLayer::L2 => header.tp_mac as usize - full_offset,
            OsiLayer::L3 => header.tp_net as usize - full_offset,
        };

        let (padding, rem) = rem.split_at_mut(pkt_offset);

        // SAFETY: packet is guaranteed to be stored in `tp_len` bytes of data at `pkt_offset`
        let packet = &mut rem[..header.tp_len as usize];

        let new_offset = if (header.tp_next_offset as usize) < full_offset {
            None
        } else {
            Some(header.tp_next_offset as usize)
        };

        Some((
            RxFrame {
                header,
                sockaddr,
                padding,
                packet,
            },
            new_offset,
        ))
    }
}

/// A reception frame capable of conveying a single packet.
pub struct RxFrame<'a> {
    header: &'a mut crate::linux::tpacket3_hdr,
    sockaddr: &'a mut libc::sockaddr_ll,
    padding: &'a mut [u8],
    packet: &'a mut [u8],
}

impl RxFrame<'_> {
    /// A zero-copy slice of the contents of the received packet.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.packet
    }

    /// A mutable zero-copy slice of the contents of the received packet.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.packet
    }

    /// Padding bytes following header info and immediately preceeding packet data.
    #[inline]
    pub fn padding(&mut self) -> &mut [u8] {
        self.padding
    }

    /// The time the packet was received.
    #[inline]
    pub fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.header.tp_sec as u64, self.header.tp_nsec)
    }

    /// The Layer 2 socket address of the received packet.
    #[inline]
    pub fn sockaddr_ll(&self) -> libc::sockaddr_ll {
        *self.sockaddr
    }

    /// Indicates whether the packet exceeded the frame size and had to be truncated.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.header.tp_len != self.header.tp_snaplen
    }

    /// The non-truncated length of the packet (if the packet had to be truncated to fit the frame).
    #[inline]
    pub fn snaplen(&self) -> usize {
        self.header.tp_snaplen as usize
    }

    /// Indicates that the packet exceeded the frames size and can be read in its entirity using `recvfrom()`.
    ///
    /// Note that this flag is only set if `set_copy_thresh()` has been enabled for the socket.
    #[inline]
    pub fn is_copied(&self) -> bool {
        (self.header.tp_status & crate::linux::TP_STATUS_COPY) != 0
    }

    /// Indicates there have been dropped packets since the last call to `packet_statistics()` was made
    /// on the socket.
    #[inline]
    pub fn dropped_packets(&self) -> bool {
        (self.header.tp_status & crate::linux::TP_STATUS_LOSING) != 0
    }

    /// Indicates that the packet's Internet/Transport-layer checksums will be done in hardware (and
    /// therefore should not be expected to be valid).
    ///
    /// This option is applicable to outgoing IP packets when checksum offloading is enabled.
    #[inline]
    pub fn offloaded_checksum(&self) -> bool {
        (self.header.tp_status & crate::linux::TP_STATUS_CSUMNOTREADY) != 0
    }

    /// Indicates that at least the transport header checksum has been validated by the operating system.
    ///
    /// NOTE: a return value of `false` does not necessarily mean that the packet's checksum was invalid,
    /// just that it was not checked by the operating system. In this case, the checksum may be calculated
    /// and determined to be valid or invalid in userspace.
    #[inline]
    pub fn checksum_valid(&self) -> bool {
        (self.header.tp_status & crate::linux::TP_STATUS_CSUM_VALID) != 0
    }

    /// The VLAN TCI value associated with the packet, if such a value exists.
    #[inline]
    pub fn vlan_tci(&self) -> Option<u32> {
        if (self.header.tp_status & crate::linux::TP_STATUS_VLAN_VALID) != 0 {
            Some(self.header.hv1.tp_vlan_tci)
        } else {
            None
        }
    }

    /// The VLAN TPID value associated with the packet, if such a value exists.
    #[inline]
    pub fn vlan_tpid(&self) -> Option<u16> {
        if (self.header.tp_status & crate::linux::TP_STATUS_VLAN_TPID_VALID) != 0 {
            Some(self.header.hv1.tp_vlan_tpid)
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
        self.header.hv1.tp_rxhash
    }
}

// ==============================================
//              Helper Functions
// ==============================================

const fn tpacket_align(len: usize) -> usize {
    // identical to libc::TPACKET_ALIGN(), but const and safe
    (len + crate::linux::TPACKET_ALIGNMENT - 1) & !(crate::linux::TPACKET_ALIGNMENT - 1)
}
