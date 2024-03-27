use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{mem, slice};

/// An index pointing to a particular frame within a `*MappedSocket`` block.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FrameIndex {
    /// The index of the block currently being read/written.
    pub blocks_index: usize,
    /// The byte offset to the frame within the specified block (`None` indicates the first frame).
    pub frame_offset: Option<usize>,
}

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
    /// space at the end of each packet--frames are dynamically sized to take up the minimum space
    /// needed to represent a packet.
    frame_size: u32,

    frame_cnt: u32,

    map_length: usize,
}

impl BlockConfig {
    #[inline]
    pub fn new(block_size: u32, block_cnt: u32, frame_size: u32) -> Result<Self, &'static str> {
        let Some(map_length) = (block_size as usize).checked_mul(block_cnt as usize) else {
            return Err("invalid overflowing total packet ring size");
        };

        // Check the case that a user maps TX+RX ring
        if map_length.checked_mul(2).is_none() {
            return Err("total packet ring would overflow memory requirements");
        }

        let Some(frame_cnt_usize) = map_length.checked_div(frame_size as usize) else {
            return Err("invalid overflowing total frame count");
        };

        let Ok(frame_cnt) = u32::try_from(frame_cnt_usize) else {
            return Err("invalid oversized total frame size");
        };

        Ok(BlockConfig {
            block_size,
            block_cnt,
            frame_size,
            frame_cnt,
            map_length,
        })
    }

    #[inline]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    #[inline]
    pub fn block_cnt(&self) -> u32 {
        self.block_cnt
    }

    #[inline]
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    #[inline]
    pub fn frame_cnt(&self) -> u32 {
        self.frame_cnt
    }

    #[inline]
    pub fn map_length(&self) -> usize {
        self.map_length
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsiLayer {
    /// Link-layer packet.
    L2,
    /// Network-layer packet.
    L3,
}

pub struct PacketTxRing {
    ring_start: *mut u8,
    block_size: usize,
    blocks: Vec<PacketTxBlock>,
}

impl PacketTxRing {
    /// The passed
    #[inline]
    pub(crate) unsafe fn new(
        ring_start: *mut u8,
        frame_size: usize,
        block_cnt: usize,
        block_size: usize,
    ) -> Self {
        debug_assert!(block_size >= mem::size_of::<libc::tpacket_block_desc>());

        let mut blocks = Vec::new();

        for i in 0..block_cnt {
            let block_slice = slice::from_raw_parts_mut(ring_start.add(block_size * i), block_size);
            let (description_bytes, block_slice) =
                block_slice.split_at_mut(mem::size_of::<libc::tpacket_block_desc>());

            // SAFETY: each block must begin with an initialized tpacket_block_desc
            let block_description = unsafe {
                (description_bytes.as_mut_ptr() as *mut libc::tpacket_block_desc)
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
            PacketTxFrameIter::next_offset(block.frames, block.frame_size, frame_offset);

        index.frame_offset = new_offset;

        (frame, index)
    }
}

pub struct PacketTxBlock {
    description: &'static mut libc::tpacket_block_desc,
    frames: &'static mut [u8],
    frame_size: usize,
}

impl PacketTxBlock {
    #[inline]
    fn block_header(&self) -> &libc::tpacket_hdr_v1 {
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

    /*
    /// Retrieves and permanently consumes the next packet in the block. Any call to [`Self::packets`]
    /// following this will not include the retrieved packet.
    #[inline]
    pub fn pop_packet<'a>(&'a mut self) -> Option<PacketTxFrame<'a>> {
        let (frame, next_frame_idx) = PacketTxFrameIter::next_offset(
            self.frames,
            self.frame_size,
        )?;
        self.curr_frame_offset = next_frame_idx;
        unsafe {
            self.description.hdr.bh1.num_pkts -= 1;
        }
        Some(frame)
    }
    */
}

pub struct PacketTxFrameIter<'a> {
    frames: &'a mut [u8],
    frame_size: usize,
    curr_offset: Option<usize>,
}

impl<'a> PacketTxFrameIter<'a> {
    #[inline]
    pub fn next(&'a mut self) -> Option<TxFrameVariant<'a>> {
        let Some(offset) = self.curr_offset else {
            return None;
        };

        let (frame, new_offset) = Self::next_offset(self.frames, self.frame_size, offset);
        self.curr_offset = new_offset;
        Some(frame)
    }

    pub fn has_remaining_frames(&self) -> bool {
        self.curr_offset.is_some()
    }

    #[inline]
    fn next_offset(
        frames: &'a mut [u8],
        frame_size: usize,
        offset: usize,
    ) -> (TxFrameVariant<'a>, Option<usize>) {
        let frames_len = frames.len();

        let curr_frame_data = &mut frames[offset..];

        let (header_data, rem) =
            curr_frame_data.split_at_mut(tpacket_align(mem::size_of::<libc::tpacket3_hdr>()));
        // SAFETY: tpacket3_header must be present at this data offset
        let header = unsafe {
            (header_data.as_mut_ptr() as *mut libc::tpacket3_hdr)
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
            libc::TP_STATUS_AVAILABLE => {
                header.tp_next_offset = 0;
                header.tp_len = 0;
                header.tp_snaplen = 0;
                TxFrameVariant::Available(TxFrame { header, packet })
            }
            libc::TP_STATUS_SEND_REQUEST => TxFrameVariant::SendRequest,
            libc::TP_STATUS_SENDING => TxFrameVariant::Sending,
            libc::TP_STATUS_WRONG_FORMAT => {
                TxFrameVariant::WrongFormat(InvalidTxFrame { header, packet })
            }
            _ => TxFrameVariant::WrongFormat(InvalidTxFrame { header, packet }),
        };

        (frame_variant, next_offset)
    }
}

pub enum TxFrameVariant<'a> {
    Available(TxFrame<'a>),
    SendRequest,
    Sending,
    WrongFormat(InvalidTxFrame<'a>),
}

pub struct TxFrame<'a> {
    header: &'a mut libc::tpacket3_hdr,
    packet: &'a mut [u8],
}

impl TxFrame<'_> {
    /// A zero-copy slice of the contents of the packet to be sent.
    ///
    /// The returned slice should only be used to write
    /// Once a packet has been written into this slice, the length of the packet must also be sent
    /// using [`Self::set_length`].
    #[inline]
    pub fn data(&mut self) -> &mut [u8] {
        self.packet
    }

    /// Sets the length of the packet and marks it as ready to be transmitted.
    ///
    /// The length of the packet must not exceed the length of the writable data slice (returned by `data()`).
    #[inline]
    pub fn send(self, packet_length: u32) {
        assert!(packet_length as usize <= self.packet.len());

        self.header.tp_len = packet_length;
        self.header.tp_snaplen = packet_length;
        self.header.tp_status = libc::TP_STATUS_SEND_REQUEST;
    }
}

pub struct InvalidTxFrame<'a> {
    header: &'a mut libc::tpacket3_hdr,
    packet: &'a mut [u8],
}

impl InvalidTxFrame<'_> {
    /// A zero-copy slice of the contents of the packet to be sent.
    ///
    /// The returned slice should only be used to write
    /// Once a packet has been written into this slice, the length of the packet must also be sent
    /// using [`Self::set_length`].
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.packet
    }
}

impl Drop for InvalidTxFrame<'_> {
    fn drop(&mut self) {
        self.header.tp_len = 0;
        self.header.tp_snaplen = 0;
        self.header.tp_status = libc::TP_STATUS_AVAILABLE;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PacketRxStatus {
    Kernel,
    User,
}

pub struct PacketRxRing {
    ring_start: *mut u8,
    block_size: usize,
    blocks: Vec<PacketRxBlock>,
}

impl PacketRxRing {
    #[inline]
    pub(crate) unsafe fn new(
        ring_start: *mut u8,
        block_cnt: usize,
        block_size: usize,
        priv_size: usize,
        osi_layer: OsiLayer,
    ) -> Self {
        debug_assert!(block_size >= mem::size_of::<libc::tpacket_block_desc>());

        let mut blocks = Vec::new();

        for i in 0..block_cnt {
            let block_slice = slice::from_raw_parts_mut(ring_start.add(block_size * i), block_size);
            let (description_bytes, block_slice) =
                block_slice.split_at_mut(mem::size_of::<libc::tpacket_block_desc>());

            // SAFETY: each block must begin with an initialized tpacket_block_desc
            let block_description = unsafe {
                (description_bytes.as_mut_ptr() as *mut libc::tpacket_block_desc)
                    .as_mut()
                    .unwrap()
            };

            debug_assert!(block_description.version == 1);

            let priv_offset = block_description.offset_to_priv as usize
                - mem::size_of::<libc::tpacket_block_desc>();
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

    #[inline]
    pub fn blocks(&mut self) -> &mut [PacketRxBlock] {
        &mut self.blocks
    }

    #[inline]
    pub fn blocks_cnt(&self) -> usize {
        self.blocks.len()
    }

    #[inline]
    pub(crate) fn next_frame(
        &mut self,
        mut index: FrameIndex,
    ) -> Option<(RxFrame<'_>, FrameIndex)> {
        let frame_offset = match index.frame_offset {
            Some(o) => o,
            None => {
                let block_index = (index.blocks_index + 1) % self.blocks.len();
                let block = &mut self.blocks[index.blocks_index];
                if (block.block_header().block_status & libc::TP_STATUS_USER) == 0 {
                    return None; // No data from the next block is ready to be read yet
                }

                let frame_offset = block.block_header().offset_to_first_pkt as usize;

                index.blocks_index = block_index;
                index.frame_offset = Some(frame_offset);
                frame_offset
            }
        };

        let block = &mut self.blocks[index.blocks_index];

        let (frame, new_offset) = PacketRxFrameIter::next_offset(
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

pub struct PacketRxBlock {
    description: &'static mut libc::tpacket_block_desc,
    priv_data: &'static mut [u8],
    frames: &'static mut [u8],
    osi_layer: OsiLayer,
}

impl PacketRxBlock {
    #[inline]
    fn block_header(&self) -> &libc::tpacket_hdr_v1 {
        // SAFETY: the `tpacket_bd_hdr_u` union has only one variant, so this access is memory-safe.
        unsafe { &self.description.hdr.bh1 }
    }

    /// The sequence number of the block.
    #[inline]
    pub fn seq(&self) -> u64 {
        self.block_header().seq_num
    }

    /// The availability status of the block.
    #[inline]
    pub fn status(&self) -> PacketRxStatus {
        if (self.block_header().block_status & libc::TP_STATUS_USER) != 0 {
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
    #[inline]
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

pub struct PacketRxFrameIter<'a> {
    frames: &'a mut [u8],
    frame_cnt: usize,
    init_offset: usize,
    curr_offset: Option<usize>,
    pkt_layer: OsiLayer,
}

impl<'a> PacketRxFrameIter<'a> {
    #[inline]
    pub fn next(&'a mut self) -> Option<RxFrame<'a>> {
        let Some(offset) = self.curr_offset else {
            return None;
        };

        let (frame, new_offset) = Self::next_offset(
            self.frames,
            self.frame_cnt,
            self.init_offset,
            offset,
            self.pkt_layer,
        )?;
        self.frame_cnt -= 1;
        self.curr_offset = new_offset;
        Some(frame)
    }

    #[inline]
    fn next_offset(
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
        let full_offset = init_offset as usize
            + curr_offset
            + tpacket_align(mem::size_of::<libc::tpacket3_hdr>())
            + mem::size_of::<libc::sockaddr_ll>();

        let curr_frame_data = &mut frames[curr_offset..];

        let (header_data, rem) =
            curr_frame_data.split_at_mut(tpacket_align(mem::size_of::<libc::tpacket3_hdr>()));
        // SAFETY: tpacket3_header must be present at this data offset
        let header = unsafe {
            (header_data.as_mut_ptr() as *mut libc::tpacket3_hdr)
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

        // SAFETY: packet is guaranteed to be stored in `tp_len` bytes of data at `pkt_offset`
        let packet = &mut rem[pkt_offset..pkt_offset + header.tp_len as usize];

        let new_offset = if (header.tp_next_offset as usize) < full_offset {
            None
        } else {
            Some(header.tp_next_offset as usize)
        };

        Some((
            RxFrame {
                header,
                sockaddr,
                packet,
            },
            new_offset,
        ))
    }
}

pub struct RxFrame<'a> {
    header: &'a mut libc::tpacket3_hdr,
    sockaddr: &'a mut libc::sockaddr_ll,
    packet: &'a mut [u8],
}

impl RxFrame<'_> {
    /// A zero-copy slice of the contents of the received packet.
    #[inline]
    pub fn data(&mut self) -> &mut [u8] {
        self.packet
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
        (self.header.tp_status & libc::TP_STATUS_COPY) != 0
    }

    /// Indicates there have been dropped packets since the last call to `packet_statistics()` was made
    /// on the socket.
    #[inline]
    pub fn dropped_packets(&self) -> bool {
        (self.header.tp_status & libc::TP_STATUS_LOSING) != 0
    }

    /// Indicates that the packet's Internet/Transport-layer checksums will be done in hardware (and
    /// therefore should not be expected to be valid).
    ///
    /// This option is applicable to outgoing IP packets when checksum offloading is enabled.
    #[inline]
    pub fn offloaded_checksum(&self) -> bool {
        (self.header.tp_status & libc::TP_STATUS_CSUMNOTREADY) != 0
    }

    /// Indicates that at least the transport header checksum has been validated by the operating system.
    ///
    /// NOTE: a return value of `false` does not necessarily mean that the packet's checksum was invalid,
    /// just that it was not checked by the operating system. In this case, the checksum may be calculated
    /// and determined to be valid or invalid in userspace.
    #[inline]
    pub fn checksum_valid(&self) -> bool {
        (self.header.tp_status & libc::TP_STATUS_CSUM_VALID) != 0
    }

    /// The VLAN TCI value associated with the packet, if such a value exists.
    #[inline]
    pub fn vlan_tci(&self) -> Option<u32> {
        if (self.header.tp_status & libc::TP_STATUS_VLAN_VALID) != 0 {
            Some(self.header.hv1.tp_vlan_tci)
        } else {
            None
        }
    }

    /// The VLAN TPID value associated with the packet, if such a value exists.
    #[inline]
    pub fn vlan_tpid(&self) -> Option<u16> {
        if (self.header.tp_status & libc::TP_STATUS_VLAN_TPID_VALID) != 0 {
            Some(self.header.hv1.tp_vlan_tpid)
        } else {
            None
        }
    }

    /// The RX Hash, a hash of the packet used to select which fanout socket to send the packet to.
    ///
    /// See [`L2Socket::fanout()`] for more information on the RX Hash.
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
    (len + libc::TPACKET_ALIGNMENT - 1) & !(libc::TPACKET_ALIGNMENT - 1)
}
