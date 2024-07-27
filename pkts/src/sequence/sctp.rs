
use core::{cmp::Ordering, mem};

#[cfg(feature = "std")]
use std::collections::{BTreeMap, VecDeque};

use super::{PktFilterDynFn, Sequence, SequenceObject, UnboundedSequence};
use crate::layers::sctp::{DataChunkFlags, SctpRef};
use crate::prelude::FromBytesRef;
use crate::utils;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::collections::{BTreeMap, VecDeque};
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

pub struct SctpSegments<const RWND: usize, const FRAG_CNT: usize> {
    frags: [SctpFragment; FRAG_CNT],
    frags_start: usize,
    frags_len: usize,
    reorder: [ReorderBuffer; RWND],
    reorder_start: usize,
    curr_stream_seq: u16,
    started: bool,
}

impl<const RWND: usize, const FRAG_CNT: usize> Default for SctpSegments<RWND, FRAG_CNT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RWND: usize, const FRAG_CNT: usize> SctpSegments<RWND, FRAG_CNT> {
    pub fn new() -> Self {
        Self {
            frags: core::array::from_fn(|_| SctpFragment::default()),
            frags_start: 0,
            frags_len: 0,
            reorder: core::array::from_fn(|_| ReorderBuffer {
                occupied: false,
                ordered: false,
                // fragment_idx: None,
                data: [0; 65535],
                len: 0,
            }),
            reorder_start: 0,
            curr_stream_seq: 0,
            started: false,
        }
    }

    pub fn get(&mut self) -> Option<&[u8]> {
        if self.reorder[self.reorder_start].occupied {
            // There's an entry ready to be received

            let len = self.reorder[self.reorder_start].len;
            // let fragment_idx = self.reorder[self.reorder_start].fragment_idx;
            self.reorder[self.reorder_start].occupied = false;
            if self.reorder[self.reorder_start].ordered {
                self.curr_stream_seq += 1;
            }

            let old_idx = self.reorder_start;
            self.reorder_start = (old_idx + 1) % RWND;
            Some(&self.reorder[old_idx].data[..len])
        } else {
            None
        }
    }

    pub fn put(&mut self, data: &[u8], stream_seq: u16, tsn: u32, flags: DataChunkFlags) {
        if !self.started {
            self.started = true;
            self.curr_stream_seq = stream_seq; // BUG: what if the first frame arrives out of order?
        }

        let diff = self.curr_stream_seq.diff_wrapped(stream_seq) as usize;
        if !flags.contains(DataChunkFlags::UNORDERED) && diff >= RWND {
            return; // Drop packet--not within receive window
        }

        if flags.contains(DataChunkFlags::BEGIN_FRAGMENT)
            && flags.contains(DataChunkFlags::END_FRAGMENT)
        {
            // The packet isn't a fragment--it only needs to be reordered
            if flags.contains(DataChunkFlags::UNORDERED) {
                // The packet isn't a fragment, and doesn't need to be reordered
                todo!()
            }
            let rwnd_idx = (self.reorder_start + diff) % RWND;
            self.reorder[rwnd_idx].occupied = true;
            self.reorder[rwnd_idx].data[..data.len()].copy_from_slice(data);
            self.reorder[rwnd_idx].len = data.len();
        } else {
            let frag_idx;

            // Get the index of where we will write this fragment, evicting
            // an old fragment buffer if needed
            'outer: {
                for i in 0..self.frags_len {
                    let idx = (self.frags_start + i) % FRAG_CNT;
                    // If cell is occupied and the stream sequence number matches
                    if self.frags[idx].total_len > 0 && self.frags[idx].stream_seq == stream_seq {
                        frag_idx = idx;
                        break 'outer;
                    }
                }

                if self.frags_len == FRAG_CNT {
                    frag_idx = self.frags_start;
                    self.frags_start = (self.frags_start + 1) % FRAG_CNT;
                    self.frags[frag_idx].clear(); // Evict the old fragment entry
                } else {
                    frag_idx = (self.frags_start + self.frags_len) % FRAG_CNT;
                    self.frags_len += 1;
                }

                self.frags[frag_idx].stream_seq = stream_seq;
            }

            let frag = &mut self.frags[frag_idx];
            frag.insert(
                data,
                tsn,
                (
                    flags.contains(DataChunkFlags::BEGIN_FRAGMENT),
                    flags.contains(DataChunkFlags::END_FRAGMENT),
                ),
            );

            if frag.is_complete() {
                let rwnd_idx = (self.reorder_start + diff) % RWND;
                self.reorder[rwnd_idx].occupied = true;
                self.reorder[rwnd_idx].data[..frag.total_len].copy_from_slice(&frag.buf[4..]);
                self.reorder[rwnd_idx].len = frag.total_len;
            }
        }
    }
}

struct ReorderBuffer {
    pub occupied: bool,
    pub ordered: bool,
    //    pub fragment_idx: Option<usize>,
    pub data: [u8; 65535],
    pub len: usize,
}

trait WrappingCmp {
    type Other: Sized;

    fn gt_wrapped(&self, other: Self::Other) -> bool;

    fn lt_wrapped(&self, other: Self::Other) -> bool;
}

trait WrappingDiff {
    type Other: Sized;

    fn diff_wrapped(&self, other: Self::Other) -> Self::Other;
}

impl WrappingDiff for u32 {
    type Other = u32;

    #[inline]
    fn diff_wrapped(&self, other: Self::Other) -> Self::Other {
        if *self <= other {
            other - *self
        } else {
            (u32::MAX - *self) + other
        }
    }
}

impl WrappingCmp for u32 {
    type Other = u32;

    #[inline]
    fn gt_wrapped(&self, other: Self::Other) -> bool {
        self.diff_wrapped(other) >= (1 << 31)
    }

    #[inline]
    fn lt_wrapped(&self, other: Self::Other) -> bool {
        *self != other && !self.gt_wrapped(other)
    }
}

impl WrappingDiff for u16 {
    type Other = u16;

    #[inline]
    fn diff_wrapped(&self, other: Self::Other) -> Self::Other {
        if *self <= other {
            other - *self
        } else {
            (u16::MAX - *self) + other
        }
    }
}

impl WrappingCmp for u16 {
    type Other = u16;

    #[inline]
    fn gt_wrapped(&self, other: Self::Other) -> bool {
        self.diff_wrapped(other) >= (1 << 15)
    }

    #[inline]
    fn lt_wrapped(&self, other: Self::Other) -> bool {
        *self != other && !self.gt_wrapped(other)
    }
}

// Length: 2 bytes. If 0, no more fragments
// TSN: 2 bytes (just take 2 LSB)
// 4 byte overhead, potentially for every single 4-byte chunk: 65535 * 2 (plus 2 extra bytes for final null length) = 65536 * 2
// #[cfg(not(feature = "alloc"))]
pub struct SctpFragment {
    buf: [u8; 65536 * 2], // Must be this size to handle the case where a packet of size 65535 is fragmented into fragments of minimum length (4 bytes, assuming padding is used efficiently)
    last_frag_idx: usize,
    begin_recvd: bool,
    end_recvd: bool,
    begin_tsn: u32,
    end_tsn: u32,
    // stream_id: u16, // removed--each stream should use its own SctpSequence to reassemble
    stream_seq: u16,
    total_len: usize, // The cumulative length of all fragments stored in `buf`. If zero, the fragment is empty
}

// #[cfg(not(feature = "alloc"))]
impl SctpFragment {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.last_frag_idx = 0;
        self.total_len = 0;
        self.begin_recvd = false;
        self.end_recvd = false;
        self.total_len = 0;
    }

    fn append_link(&mut self, data: &[u8], offset: usize, tsn_truncated: u16) {
        // Add the link list header and data to the buffer
        self.buf[offset..offset + 2].copy_from_slice(tsn_truncated.to_be_bytes().as_slice());
        self.buf[offset + 2..offset + 4]
            .copy_from_slice((data.len() as u16).to_be_bytes().as_slice());
        self.buf[offset + 4..offset + data.len() + 4].copy_from_slice(data);

        // Set the next link to a length of 0, signifying the end of the linked list
        self.buf[offset + data.len() + 4..offset + data.len() + 6].copy_from_slice(&[0, 0]);

        // Finally, update the linked list end pointer
        self.last_frag_idx += data.len() + 4;
    }

    fn insert_link(&mut self, data: &[u8], offset: usize, tsn_truncated: u16) {
        let displacement = data.len() + 4;

        // First, move the existing links in the list so that the inserted link doesn't overwrite them...
        self.shift_links(offset, offset + displacement);

        // Then, insert the new link
        self.buf[offset..offset + 2].copy_from_slice(tsn_truncated.to_be_bytes().as_slice());
        self.buf[offset + 2..offset + 4]
            .copy_from_slice((data.len() as u16).to_be_bytes().as_slice());
        self.buf[offset + 4..offset + data.len() + 4].copy_from_slice(data);
    }

    fn shift_links(&mut self, start: usize, new_start: usize) {
        match new_start.cmp(&start) {
            Ordering::Less => {
                let shift_left = start - new_start;

                // Links are moving to the left
                for i in start..self.last_frag_idx + 2 {
                    // Starting from the left, shift each byte left
                    self.buf[i - shift_left] = self.buf[i];
                }

                // Update the end pointer (since the links have shifted left)
                self.last_frag_idx -= shift_left;
            }
            Ordering::Greater => {
                // start < new_start
                let shift_right = new_start - start;

                // Links are moving to the right
                for i in (start..self.last_frag_idx + 2).rev() {
                    // Starting from the right,, shift each byte right
                    self.buf[i + shift_right] = self.buf[i];
                }

                // Update the end pointer (since the links have shifted right)
                self.last_frag_idx += shift_right;
            }
            _ => (),
        }
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        let first = FragHeader::new(&self.buf);
        // If the Beginning fragment & Ending fragment are received, and
        // all TSNs in between the two have been received (and therefore
        // merged into the first link), the fragments are complete.
        self.begin_recvd && self.end_recvd && first.tsn() == (self.end_tsn & 0xFFFF) as u16
    }

    pub fn insert(&mut self, frag: &[u8], tsn: u32, frag_flags: (bool, bool)) {
        let tsn_truncated = (tsn & 0xFFFF) as u16;
        let beginning = frag_flags.0;
        let ending = frag_flags.1;

        if self.total_len == 0 {
            if frag.len() > 65535 {
                return; // Drop the packet--too long
            }

            // No packets have been received yet--add incoming as first packet
            self.begin_recvd |= beginning;
            self.end_recvd |= ending;
            self.begin_tsn = tsn;
            self.end_tsn = tsn;

            self.append_link(frag, 0, tsn_truncated);
        } else {
            if self.total_len + frag.len() > 65535 {
                return; // Too much data to reassemble
            }

            if beginning && self.begin_recvd {
                return; // we already have the beginning fragment
            }

            if ending && self.end_recvd {
                return; // we already have the ending fragment
            }

            if tsn.lt_wrapped(self.begin_tsn) && self.begin_recvd {
                return; // fragment TSN was before beginning fragment
            }

            if tsn.gt_wrapped(self.end_tsn) && self.end_recvd {
                return; // fragment TSN was after ending fragment
            }

            if tsn.lt_wrapped(self.begin_tsn) && tsn.diff_wrapped(self.end_tsn) >= 16384 {
                return; // fragment difference exceeds max possible reassembly window width
            }

            if tsn.gt_wrapped(self.end_tsn) && self.begin_tsn.diff_wrapped(tsn) >= 16384 {
                return; // fragment difference exceeds max possible reassembly window width
            }

            let first_trunc_tsn = u16::from_be_bytes(self.buf[2..4].try_into().unwrap());
            if tsn_truncated.lt_wrapped(first_trunc_tsn) && self.begin_recvd {
                return; // The TSN indicates this fragment is a duplicate we've already merged in
            }

            if tsn.gt_wrapped(self.end_tsn) {
                // The fragment goes at the end of the linked list
                self.append_link(frag, self.last_frag_idx, tsn_truncated);
                self.end_tsn = tsn;
            } else {
                // The fragment goes somewhere before the end of the linked list
                let mut node = FragHeader::new(frag);
                while node.tsn().gt_wrapped(tsn_truncated) {
                    node = node.next().expect("internal error: invariant failed (end of SCTP fragment linked list unexpectedly reached)");
                }

                if node.tsn() == tsn_truncated {
                    return; // Fragment is a duplicate--discard
                }

                self.insert_link(frag, node.header_offset(), tsn_truncated);

                // If the fragment was the first in line, update the beginning TSN
                if tsn.lt_wrapped(self.begin_tsn) {
                    self.begin_tsn = tsn;
                }
            }

            self.begin_recvd |= beginning;
            self.end_recvd |= ending;

            // Now check to see if we can merge a few of the first data segments together
            if self.begin_recvd {
                // This incurs an extra memcpy-like shift in bytes, which is a bit expensive...
                // but it would have to happen anyways--we eventually have to concatenate all of
                // the individual fragments together. Might as well do it on the fly so that our
                // linked list doesn't get longer and longer and thereby take longer to traverse.

                let first = FragHeader::new(frag);
                let first_tsn = first.tsn();
                let mut new_first_tsn = first_tsn;
                let mut new_first_len = first.data_length();
                let next = first.next().expect("internal error: invariant failed (linked list missing second SCTP fragment immediately after inserting it)");
                let mut next_offset = next.header_offset();
                let mut next_len = next.data_length();
                let mut next_tsn = next.tsn();
                while first_tsn.wrapping_add(1) == next_tsn {
                    // Remove the header of the second link. This effectively combines the data
                    // of the second link with the first link as long as we update the length field.
                    self.shift_links(next_offset + 4, next_offset);
                    new_first_tsn = next_tsn; // Update the TSN value of the first link.
                    new_first_len += next_len; // Update the length field of the first link.
                    next_offset += next_len as usize; // Update the offset to the 2nd link in list.

                    let next = FragHeader {
                        data: &self.buf,
                        offset: next_offset,
                    };
                    if next.data_length() == 0 {
                        break; // We've reached the end of the linked list
                    }

                    next_len = next.data_length();
                    next_tsn = next.tsn();
                }

                if first_tsn != new_first_tsn {
                    // Now we need to write our new first length to the linked list bytes
                    self.buf[0..2].copy_from_slice(new_first_len.to_be_bytes().as_slice());
                    // We also need to write our new TSN value
                    self.buf[2..4].copy_from_slice(first_tsn.to_be_bytes().as_slice());
                }
            }
        }

        self.total_len += frag.len();
    }
}

// #[cfg(not(feature = "alloc"))]
impl Default for SctpFragment {
    fn default() -> Self {
        Self {
            buf: [0; 65536 * 2],
            last_frag_idx: 0,
            begin_recvd: false,
            end_recvd: false,
            begin_tsn: 0,
            end_tsn: 0,
            stream_seq: 0,
            total_len: 0,
        }
    }
}

struct FragHeader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> FragHeader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        FragHeader { data, offset: 0 }
    }

    pub fn data_length(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("internal error: FragHeader::data_length() out of bounds"),
        )
    }

    pub fn tsn(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2).expect("internal error: FragHeader::tsn() out of bounds"),
        )
    }

    /*
    pub fn data(&self) -> &'a [u8] {
        let len = self.data_length() as usize;
        self.data
            .get(4..4 + len)
            .expect("internal error: FragHeader::data() out of bounds")
    }
    */

    pub fn header_offset(&self) -> usize {
        self.offset
    }

    pub fn next(&self) -> Option<FragHeader<'a>> {
        let next_offset = 4 + self.data_length() as usize;
        let next_len = u16::from_be_bytes(
            utils::to_array(self.data, next_offset)
                .expect("internal error: FragHeader::next() out of bounds"),
        );
        if next_len > 0 {
            Some(FragHeader {
                data: &self.data[next_offset..],
                offset: self.offset + next_offset,
            })
        } else {
            None
        }
    }

    /*
    pub fn next_offset(&self) -> usize {
        self.offset + 4 + self.data_length() as usize
    }
    */
}

struct SctpFragmentEntry {
    tsn: u32,
    flags: DataChunkFlags,
    data: Vec<u8>,
}

// Note: it is the caller's responsibility to ensure that packets are input from the same src/dst port, in the same direction, and from the same stream identifier.
// The `SctpDefrag` is only responsible for ensuring packets of a stream come in order (unless the unordered bit is set) and are defragmented.
#[cfg(feature = "alloc")]
pub struct SctpSequence<const WINDOW: usize = 25> {
    filter: Option<Box<PktFilterDynFn>>,
    fragments: BTreeMap<Option<u16>, Vec<SctpFragmentEntry>>,
    stream_seq: Option<u16>,
    unordered: utils::ArrayRing<Vec<u8>, WINDOW>,
    out: VecDeque<Vec<u8>>,
    first_retrieved: bool,
}

#[cfg(feature = "alloc")]
impl<const WINDOW: usize> SctpSequence<WINDOW> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SctpSequence {
            filter: None,
            fragments: BTreeMap::new(),
            stream_seq: None,
            unordered: utils::ArrayRing::new(),
            out: VecDeque::new(),
            first_retrieved: false,
        }
    }

    fn put_unordered(&mut self, stream_seq: u16, data: Vec<u8>) {
        match self.stream_seq {
            None => {
                self.stream_seq = Some(stream_seq.wrapping_add(1));
                self.out.push_back(data);
            }
            Some(base_seq) => {
                let seq = stream_seq;
                let seq_diff = if seq >= base_seq {
                    seq - base_seq
                } else {
                    seq + (u16::MAX - base_seq) + 1
                };
                if seq_diff < WINDOW as u16 {
                    self.unordered.insert(data, seq_diff as usize);
                    todo!()
                }
                // else silently discard the packet--its outside of our window
            }
        }
    }

    fn frags_complete(frags: &[SctpFragmentEntry]) -> bool {
        let mut i = frags.iter();

        let start_tsn = loop {
            match i.next() {
                Some(frag) => {
                    if frag.flags.contains(DataChunkFlags::BEGIN_FRAGMENT) {
                        break frag.tsn;
                    }
                }
                None => return false,
            }
        };

        for (idx, frag) in i.enumerate() {
            if frag.tsn != start_tsn + idx as u32 + 1 {
                return false;
            }

            if frag.flags.contains(DataChunkFlags::END_FRAGMENT) {
                return true;
            }
        }

        false
    }
}

#[cfg(feature = "alloc")]
impl<const WINDOW: usize> SequenceObject for SctpSequence<WINDOW> {
    #[inline]
    fn set_filter_raw(&mut self, filt: Option<fn(&[u8]) -> bool>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(f)),
            None => None,
        }
    }

    #[inline]
    fn filter(&self) -> Option<&PktFilterDynFn> {
        match &self.filter {
            Some(f) => Some(f.as_ref()),
            None => None,
        }
    }

    fn put_and_get_unchecked<'a>(&'a mut self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        let sctp = SctpRef::from_bytes_unchecked(pkt);

        let _data_chunks = sctp.payload_chunks();
        // if data_chunks.count() > 1 {}
        todo!()
    }
    /*
    fn put_and_get_unchecked<'a>(&mut self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        todo!()
    }
    */

    fn put_unfiltered_unchecked(&mut self, pkt: &[u8]) {
        let sctp = SctpRef::from_bytes_unchecked(pkt);

        for payload in sctp.payload_chunks() {
            let flags = payload.flags();
            if flags.contains(DataChunkFlags::BEGIN_FRAGMENT)
                && flags.contains(DataChunkFlags::END_FRAGMENT)
            {
                if flags.contains(DataChunkFlags::UNORDERED) {
                    self.out.push_back(Vec::from(payload.user_data()));
                } else {
                    self.put_unordered(payload.stream_seq(), Vec::from(payload.user_data()));
                }
            } else {
                let tsn = payload.tsn();
                let ssn = if flags.contains(DataChunkFlags::UNORDERED) {
                    None
                } else {
                    Some(payload.stream_seq())
                };

                let frags = self.fragments.entry(ssn).or_default();

                match frags.binary_search_by(|frag| frag.tsn.cmp(&tsn)) {
                    Ok(idx) => {
                        // Swap out existing value with new one
                        let mut p = SctpFragmentEntry {
                            tsn,
                            flags,
                            data: Vec::from(payload.user_data()),
                        };
                        mem::swap(&mut p, frags.get_mut(idx).unwrap());
                    }
                    Err(idx) => frags.insert(
                        idx,
                        SctpFragmentEntry {
                            tsn,
                            flags,
                            data: Vec::from(payload.user_data()),
                        },
                    ),
                }

                // Now reassemble the fragments if they're complete
                if Self::frags_complete(frags) {
                    let mut reassembled = Vec::new();
                    let mut beginning_seen = false;
                    for entry in frags {
                        if entry.flags.contains(DataChunkFlags::UNORDERED) {
                            beginning_seen = true;
                        }

                        if beginning_seen {
                            reassembled.append(&mut entry.data);
                        }

                        if entry.flags.contains(DataChunkFlags::END_FRAGMENT) {
                            break;
                        }
                    }

                    if let Some(valid_ssn) = ssn {
                        self.put_unordered(valid_ssn, reassembled);
                    } else {
                        // flags.unordered() == true
                        self.out.push_back(reassembled);
                    }

                    self.fragments.remove(&ssn);
                }
            }
        }
    }

    #[inline]
    fn get(&mut self) -> Option<&[u8]> {
        if self.first_retrieved {
            self.out.pop_front();
        } else {
            self.first_retrieved = true;
        }

        match self.out.front() {
            Some(f) => Some(f.as_slice()),
            None => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl Sequence for SctpSequence {
    type In<'a> = SctpRef<'a>;
}

#[cfg(feature = "alloc")]
impl UnboundedSequence for SctpSequence {
    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filt: Option<F>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(move |i| f(SctpRef::from_bytes_unchecked(i)))),
            None => None,
        }
    }
}
