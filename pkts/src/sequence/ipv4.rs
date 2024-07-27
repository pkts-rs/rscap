use core::{cmp, mem};

#[cfg(feature = "std")]
use std::collections::{BTreeMap, VecDeque};

use super::{PktFilterDynFn, Sequence, SequenceObject, UnboundedSequence};
use crate::layers::ip::{Ipv4Flags, Ipv4Ref};
use crate::layers::traits::*;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::collections::{BTreeMap, VecDeque};
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

/// A [`Sequence`] type that handles defragmentation of IPv4 packets.
/// This Sequence guarantees that packets returned from it will be
/// defragmented and have message bounds preserved, though it does
/// not mandate any particular ordering of packets (since IPv4 does
/// not guarantee in-order packet delivery).
pub struct Ipv4Sequence<const FRAG_CNT: usize> {
    #[cfg(feature = "alloc")]
    filter: Option<Box<PktFilterDynFn>>,
    #[cfg(not(feature = "alloc"))]
    filter: Option<fn(&[u8]) -> bool>,
    fragments: Ipv4Fragments<FRAG_CNT>,
}

pub const IPV4_DEFAULT_FRAG_CNT: usize = 16;

impl Default for Ipv4Sequence<IPV4_DEFAULT_FRAG_CNT> {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv4Sequence<IPV4_DEFAULT_FRAG_CNT> {
    /// Create a new `Ipv4Sequence` instance.
    #[inline]
    pub fn new() -> Self {
        Ipv4Sequence {
            filter: None,
            fragments: Ipv4Fragments::new(),
        }
    }
}

impl<const FRAG_CNT: usize> Ipv4Sequence<FRAG_CNT> {
    #[inline]
    pub fn new_with_bound() -> Self {
        Ipv4Sequence {
            filter: None,
            fragments: Ipv4Fragments::new(),
        }
    }
}

impl<const FRAG_CNT: usize> SequenceObject for Ipv4Sequence<FRAG_CNT> {
    #[inline]
    #[cfg(feature = "alloc")]
    fn set_filter_raw(&mut self, filt: Option<fn(&[u8]) -> bool>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(f)),
            None => None,
        }
    }

    #[inline]
    #[cfg(not(feature = "alloc"))]
    fn set_filter_raw(&mut self, filter: Option<fn(&[u8]) -> bool>) {
        self.filter = filter;
    }

    #[inline]
    #[cfg(feature = "alloc")]
    fn filter(&self) -> Option<&PktFilterDynFn> {
        match &self.filter {
            Some(f) => Some(f.as_ref()),
            None => None,
        }
    }

    #[inline]
    #[cfg(not(feature = "alloc"))]
    fn filter(&self) -> Option<&PktFilterDynFn> {
        match &self.filter {
            Some(f) => Some(f),
            None => None,
        }
    }

    fn put_and_get_unchecked<'a>(&'a mut self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        match self.filter() {
            Some(drop_pkt) if drop_pkt(pkt) => return None,
            _ => (),
        }

        let ipv4 = Ipv4Ref::from_bytes_unchecked(pkt);
        let mf = ipv4.flags().contains(Ipv4Flags::MORE_FRAGMENTS);
        let fo = ipv4.frag_offset() as usize;
        if !mf && fo == 0 {
            let ihl = cmp::max(ipv4.ihl() as usize, 5) * 4;
            let tl = cmp::max(ipv4.packet_length() as usize, ihl);
            let data = pkt.get(ihl..tl).expect("IPv4 Defragment instance encountered packet containing fewer bytes than advertised in its Total Length field");
            Some(data)
        } else {
            self.put_unfiltered_unchecked(pkt);
            self.get()
        }
    }

    fn put_unfiltered_unchecked(&mut self, pkt: &[u8]) {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(pkt);
        let ihl = cmp::max(ipv4.ihl() as usize, 5) * 4;
        let tl = cmp::max(ipv4.packet_length() as usize, ihl);
        let data = pkt.get(ihl..tl).expect("IPv4 Defragment instance encountered packet containing fewer bytes than advertised in its Total Length field");

        let id = ipv4.identifier();
        let mf = ipv4.flags().contains(Ipv4Flags::MORE_FRAGMENTS);
        let fo = ipv4.frag_offset() as usize;

        self.fragments.put(data, id, mf, fo);
    }

    fn get(&mut self) -> Option<&[u8]> {
        self.fragments.get()
    }
}

impl<const FRAG_CNT: usize> Sequence for Ipv4Sequence<FRAG_CNT> {
    type In<'a> = Ipv4Ref<'a>;
}

#[cfg(feature = "alloc")]
impl<const FRAG_CNT: usize> UnboundedSequence for Ipv4Sequence<FRAG_CNT> {
    #[inline]
    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filt: Option<F>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(move |i| f(Ipv4Ref::from_bytes_unchecked(i)))),
            None => None,
        }
    }
}

// TODO: allow multiple fragmented packets with different ids to be handled simultaneously
#[cfg(feature = "alloc")]
struct Ipv4Fragments<const FRAG_CNT: usize> {
    fragments: BTreeMap<u16, Ipv4Fragment>,
    insert_order: VecDeque<u16>,
    reassembled: Vec<u8>,
    retrieved: bool,
}

#[cfg(feature = "alloc")]
impl<const FRAG_CNT: usize> Ipv4Fragments<FRAG_CNT> {
    #[inline]
    pub fn new() -> Self {
        Ipv4Fragments {
            fragments: BTreeMap::new(),
            insert_order: VecDeque::new(),
            reassembled: Vec::new(),
            retrieved: true,
        }
    }

    #[inline]
    pub fn get(&mut self) -> Option<&[u8]> {
        if self.retrieved {
            None
        } else {
            self.retrieved = true;
            Some(self.reassembled.as_slice())
        }
    }

    pub fn put(&mut self, data: &[u8], id: u16, mf: bool, fo: usize) {
        let is_fragment = mf || fo != 0;
        if fo != 0 && (data.len() % 8 != 0) || data.is_empty() {
            return; // Invalid fragmentation
                    // TODO: shouldn't this be checked as part of Ipv4::validate()????
        }

        // If we know we're going to need to take out a fragment and insert a
        // new one with different values, just reuse the struct and avoid
        // reallocation costs.
        let reused = if is_fragment
            && self.insert_order.len() >= FRAG_CNT
            && !self.fragments.contains_key(&id)
        {
            let remove_idx = self.insert_order.pop_back().expect("internal error: fragments and insert_order counts became unaligned in Ipv4Sequence");
            let mut removed = self.fragments.remove(&remove_idx).expect("internal error: insert_order contained index not found in fragments of Ipv4Sequence");
            removed.clear();
            Some(removed)
        } else {
            None
        };

        if !is_fragment {
            self.reassembled.clear();
            self.reassembled.extend_from_slice(data); // TODO: is there a more efficient way to do this? Maybe a memcpy?
            self.retrieved = false;
        } else {
            let mut total_fragments = self.fragments.len();
            if !self.fragments.contains_key(&id) {
                self.insert_order.push_front(id);
                total_fragments = self.fragments.len() + 1;
            }
            let frag = self
                .fragments
                .entry(id)
                .or_insert(reused.unwrap_or(Ipv4Fragment::new()));
            frag.last_frag_seen |= !mf;
            let data_offset = fo * 8;
            let data_end = data_offset + data.len();

            if data_offset < frag.data.len() {
                let end = cmp::min(frag.data.len() - data_offset, data.len());
                frag.data[data_offset..].copy_from_slice(&data[..end]);
            }
            if data_offset > frag.data.len() {
                frag.data
                    .extend(core::iter::repeat(0).take(data_offset - frag.data.len()));
            }
            if data_end > frag.data.len() {
                frag.data
                    .extend_from_slice(&data[frag.data.len() - data_offset..]);
            }

            let mut frag_end = data_end / 8;
            let frag_bit_end = frag_end % 32;
            let new_rcvbt_len = (frag_end + 31) / 32;

            // First, add u32 chunks as needed to the bitmap
            if frag.rcvbt.len() < new_rcvbt_len {
                frag_end = frag.rcvbt.len() * 32;
                if frag.rcvbt.len() + 1 < new_rcvbt_len {
                    // 2 or more extra chunks--fill in all but the last chunk
                    frag.rcvbt.extend(
                        core::iter::repeat(u32::MAX).take(new_rcvbt_len - frag.rcvbt.len()),
                    );
                }
                // Fill the last chunk based on end bit offset
                frag.rcvbt.push(!(u32::MAX >> frag_bit_end));
            }

            let rcvbt_start = fo / 32;
            let rcvbt_end = (frag_end + 31) / 32;
            let frag_bit_start = fo % 32;
            let frag_bit_end = frag_end % 32;
            if rcvbt_start + 1 < rcvbt_end {
                // Start and end are in different u32 chunks
                // Update the first chunk based on start bit offset
                frag.rcvbt[rcvbt_start] |= u32::MAX >> frag_bit_start;
                if rcvbt_start + 2 < rcvbt_end {
                    // If more than 2 chunks, fill in all but the first and last chunks
                    for i in rcvbt_start + 1..rcvbt_end - 1 {
                        frag.rcvbt[i] = u32::MAX;
                    }
                }
                // Update the last chunk based off end bit offset
                frag.rcvbt[rcvbt_end - 1] |= !(u32::MAX >> frag_bit_end);
            } else {
                // Start and end are within the same u32 chunk--update only the bits in between start and end
                frag.rcvbt[rcvbt_start] |=
                    !(u32::MAX >> frag_bit_end) & (u32::MAX >> frag_bit_start);
            }

            if frag.rdl >= data_offset && frag.rdl < data_end {
                frag.rdl = data_end;
                let mut rcvbt_idx = frag.rdl / (32 * 8);
                while rcvbt_idx < frag.rcvbt.len() && frag.rcvbt[rcvbt_idx] == u32::MAX {
                    rcvbt_idx += 1;
                }
                frag.rdl = rcvbt_idx * (32 * 8);
                if rcvbt_idx < frag.rcvbt.len() {
                    // Now count the number of leading ones in the last u32 chunk to bring rdl to its final position
                    frag.rdl += (frag.rcvbt[rcvbt_idx].leading_ones() as usize) * 8;
                }
            }

            if frag.last_frag_seen && frag.rdl == frag.data.len() {
                mem::swap(&mut self.reassembled, &mut frag.data);
                self.retrieved = false;
                frag.clear();
                if total_fragments >= 64 {
                    // NOTE: limits saving of old allocated fragment contexts so that no more than ~4MB is reserved. This DOES NOT stop intentional resource exhaustion attacks from malicious packets; FRAG_CNT ultimately deals with that.
                    self.fragments.remove(&id);
                    for (idx, val) in self.insert_order.iter().enumerate() {
                        if *val == id {
                            self.insert_order.remove(idx);
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "alloc")]
struct Ipv4Fragment {
    rdl: usize, // Received Data Length (last seen received bit before unreceived data)
    data: Vec<u8>,
    rcvbt: Vec<u32>, // bitmap of 8192 possible frag offsets
    last_frag_seen: bool,
}

#[cfg(feature = "alloc")]
impl Ipv4Fragment {
    #[inline]
    pub fn new() -> Self {
        Ipv4Fragment {
            rdl: 0,
            data: Vec::new(),
            rcvbt: Vec::new(),
            last_frag_seen: false,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.rdl = 0;
        self.data.clear();
        self.rcvbt.clear();
        self.last_frag_seen = false;
    }
}

#[cfg(not(feature = "alloc"))]
struct Ipv4Fragments<const FRAG_CNT: usize> {
    fragments: [Ipv4Fragment; FRAG_CNT],
    fragments_len: usize,
    fragments_start: usize,
    unfragmented: ([u8; 65536], usize),
    ready_idx: Option<usize>, // `None` indicates that the ready buffer is in `unfragmented`
    ready: bool,
}

#[cfg(not(feature = "alloc"))]
impl<const FRAG_CNT: usize> Ipv4Fragments<FRAG_CNT> {
    #[inline]
    pub fn new() -> Self {
        Ipv4Fragments {
            fragments: core::array::from_fn(|_| Ipv4Fragment::default()),
            fragments_len: 0,
            fragments_start: 0,
            unfragmented: ([0; 65536], 0),
            ready_idx: None,
            ready: false,
        }
    }

    #[inline]
    pub fn get(&mut self) -> Option<&[u8]> {
        if self.ready {
            self.ready = false;
            match self.ready_idx {
                None => Some(&self.unfragmented.0[..self.unfragmented.1]),
                Some(idx) => Some(&self.fragments[idx].buf[..self.fragments[idx].len]),
            }
        } else {
            None
        }
    }

    pub fn put(&mut self, data: &[u8], id: u16, mf: bool, fo: usize) {
        let is_fragment = mf || fo != 0;

        if fo != 0 && (data.len() % 8 != 0) || data.len() == 0 {
            return; // Invalid fragmentation
                    // TODO: shouldn't this be checked as part of Ipv4::validate()????
        }

        if !is_fragment {
            self.unfragmented.0[..data.len()].copy_from_slice(data);
            self.unfragmented.1 = data.len();
        } else {
            let frag_idx;

            // Get the index of where we will write this fragment, evicting
            // an old fragment buffer if needed
            'outer: {
                for i in 0..self.fragments_len {
                    let idx = (self.fragments_start + i) % FRAG_CNT;
                    if self.fragments[idx].id == id {
                        frag_idx = idx;
                        break 'outer;
                    }
                }

                if self.fragments_len == FRAG_CNT {
                    frag_idx = self.fragments_start;
                    self.fragments_start = (self.fragments_start + 1) % FRAG_CNT;
                    self.fragments[frag_idx].clear(); // Evict the old fragment entry
                } else {
                    frag_idx = (self.fragments_start + self.fragments_len) % FRAG_CNT;
                    self.fragments_len += 1;
                }

                self.fragments[frag_idx].id = id;
            }

            let frag = &mut self.fragments[frag_idx];
            let data_offset = fo * 8;
            let data_end = data_offset + data.len();
            let frag_end = data_end / 8;
            let prev_rdl = frag.rdl;

            if !mf {
                frag.len = data_end;
            }

            // Copy the fragment data into the buffer
            frag.buf[data_offset..data_end].copy_from_slice(data);

            // Now update the rcvbt bitmap to indicate data is in the buffer
            let rcvbt_start = fo / 32;
            let rcvbt_end = (frag_end + 31) / 32;
            let frag_bit_start = fo % 32;
            let frag_bit_end = frag_end % 32;
            if rcvbt_start + 1 < rcvbt_end {
                // Start and end are in different u32 chunks
                // Update the first chunk based on start bit offset
                frag.rcvbt[rcvbt_start] |= u32::MAX >> frag_bit_start;
                if rcvbt_start + 2 < rcvbt_end {
                    // If more than 2 chunks, fill in all but the first and last chunks
                    for i in rcvbt_start + 1..rcvbt_end - 1 {
                        frag.rcvbt[i] = u32::MAX;
                    }
                }
                // Update the last chunk based off end bit offset
                frag.rcvbt[rcvbt_end - 1] |= !(u32::MAX >> frag_bit_end);
            } else {
                // Start and end are within the same u32 chunk--update only the bits in between start and end
                frag.rcvbt[rcvbt_start] |=
                    !(u32::MAX >> frag_bit_end) & (u32::MAX >> frag_bit_start);
            }

            if frag.rdl >= data_offset && frag.rdl < data_end {
                frag.rdl = data_end;
                let mut rcvbt_idx = frag.rdl / (32 * 8);
                while rcvbt_idx < frag.rcvbt.len() && frag.rcvbt[rcvbt_idx] == u32::MAX {
                    rcvbt_idx += 1;
                }
                frag.rdl = rcvbt_idx * (32 * 8);
                if rcvbt_idx < frag.rcvbt.len() {
                    // Now count the number of leading ones in the last u32 chunk to bring rdl to its final position
                    frag.rdl += (frag.rcvbt[rcvbt_idx].leading_ones() as usize) * 8;
                }
            }

            // If the packet's last fragment has been observed,
            // *and* it is fully reassembled, *and* it hasn't already
            // been returned, return it. We check to make sure it hasn't
            // already been returned because a wayward fragment could
            // still arrive and result in the packet being delivered twice.
            if frag.len != 0 && frag.rdl == frag.buf.len() && prev_rdl != frag.rdl {
                self.ready = true;
                self.ready_idx = Some(frag_idx);
            }
        }
    }
}

#[cfg(not(feature = "alloc"))]
struct Ipv4Fragment {
    id: u16,
    buf: [u8; 65536],
    len: usize,
    rcvbt: [u32; 256], // bitmap of 8192 possible frag offsets
    rdl: usize,
}

#[cfg(not(feature = "alloc"))]
impl Ipv4Fragment {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.id = 0;
        // No need to clear self.buf--rcvbt makes sure old data is never read
        self.len = 0;
        self.rcvbt.iter_mut().for_each(|b| *b = 0); // compiles to memset
        self.rdl = 0;
    }
}

#[cfg(not(feature = "alloc"))]
impl Default for Ipv4Fragment {
    #[inline]
    fn default() -> Self {
        Self {
            id: 0,
            buf: [0; 65536],
            len: 0,
            rcvbt: [0; 256],
            rdl: 0,
        }
    }
}
