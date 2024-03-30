// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Packet defragmentation and re-ordering via [`Sequence`]s.
//!
//! Some protocols allow for messages to be fragmented into several
//! packets, and others additionally account for re-ordering of packets
//! after they have arrived at an endpoint. The [`Sequence`] type can be
//! used to perform defragmentation and reordering such that messages
//! are returned in the correct sequence and with the proper message
//! boundaries (where applicable).
//!
//! Passing packets through Sequence types ensure that the following
//! three properties are fulfilled if they are part of the given [`Layer`]'s
//! protocol:
//!
//! 1. Packets are rearranged to conform to a particular order (such as
//! sequence numbers for [`Tcp`])
//! 2. Packets that are marked as fragmented are reassembled
//! 3. Message bounds are maintained where appropriate (for example,
//! [`Sctp`] data chunks are returned on a chunk-by-chunk basis instead
//! of being combined into one continuous stream like TCP does).
//!
//! Sequences are relatively straightforward, with simple `put()` and `get()`
//! operations to pass packets into a streamm and retrieve payloads data,
//! respectively:
//!
//! TODO: example here
//!
//! Sequences can optionally have filters added to automatically discard
//! packets based on field values:
//!
//! TODO: example here
//!
//! When parsing raw data flows, it is often useful to perform defragmentation
//! and reordering operations on a chain of multiple layers, such as handling
//! IPv4 fragmentation _and_ TCP reordering on the same packet. The [`LayeredSequence`]
//! struct allows for multiple Sequence types to be chained sequentially in this
//! manner such that each Sequence acts on the payload contents returned from
//! the Sequence type before it.
//!
//! TODO: example here
//!
//! [`Sctp`]: struct@crate::layers::sctp::Sctp
//! [`Tcp`]: struct@crate::layers::tcp::Tcp

#[cfg(feature = "alloc")]
use std::collections::{hash_map::RandomState, HashMap, VecDeque};

use core::cmp::{self, Ordering};
use core::iter::Iterator;
#[cfg(feature = "alloc")]
use core::marker::PhantomData;
#[cfg(feature = "alloc")]
use core::mem;

use crate::error::*;
use crate::layers::dev_traits::*;
use crate::layers::ip::Ipv4Ref;
#[cfg(feature = "alloc")]
use crate::layers::sctp::{DataChunkFlags, SctpRef};
use crate::layers::traits::*;
#[cfg(feature = "alloc")]
use crate::utils;

type PktFilterDynFn = dyn Fn(&[u8]) -> bool;
type ValidateFn = fn(bytes: &[u8]) -> Result<(), ValidationError>;

// There are three characteristics that a packet Sequence may exhibit:
// 1. Reordering of packets relative to each other
// 2. Reassembly of fragments of a single packet
// 3. Conveying message bounds

// A Sequence may adhere to any combination of these characteristics. For example:
// - `TcpSequence` reorders packets relative to each other in a TCP stream (1), but does
//   not reassemble packets (since there is no notion of fragmentation in a TCP packet)
//   or convey message bounds (since TCP is a stream-based protocol)
// - `Ipv4Sequence` performs fragmentation reassembly (2), but it does not necessarily
//   deliver packets in order (1) or convey strict message bounds (3).
// - `SctpSequence` exhibits all three of these characteristics--it reorders packets in
//   a given stream, reassembles individual fragmented packets within that stream and
//   upholds Data Chunk boundaries in the data it returns.

/// An object-safe subset of methods used for Sequence types (see [`Sequence`] for more
/// details on general use). This trait is primarily used to enable the creation of
/// [`LayeredSequence`] types.
pub trait SequenceObject {
    /// Processes the incoming `pkt` relative to the current sequence's state, performing
    /// defragmentation and reordering as necessary. The sequence will not check the packet's
    /// contents before processing it and will assume that it is not malformed or otherwise
    /// invalid.
    ///
    /// # Safety
    ///
    /// It is up to the caller of this method to ensure that `pkt` is not malformed. A packet
    /// that does not conform to the required layer type may lead to a panic condition, or it
    /// may alter the stream of output packets in an unexpected way.
    #[inline]
    fn put_unchecked(&mut self, pkt: &[u8]) {
        match self.filter() {
            Some(should_discard_packet) if should_discard_packet(pkt) => (),
            _ => self.put_unfiltered_unchecked(pkt),
        }
    }

    /// Both processes the incoming `pkt` and returns the next upper-layer packet in a
    /// zero-copy manner. This method has the potential to be much more efficient than
    /// calls to [`Sequence::put()`] and [`SequenceObject::get()`], but only under
    /// particular circumstances. Zero-copy will only happen if:
    /// 1. The inserted packet is not fragmented (only applicable if fragmentation occurs
    /// in the protocol, such as for [`Ipv4Sequence`]).
    /// 2. The inserted packet is the next required packet in order (only applicable if
    /// the Sequence enforces ordering on the packets, such as for `TcpSequence`).
    /// 3. There are no outstanding packets that can be fetched from the sequence using
    /// [`SequenceObject::get()`].
    ///
    /// If any of the above conditions are _not_ met, the packet will be copied into internal
    /// buffers and processed like normal, and the method will optionally return a packet that
    /// has been reassembled/reordered in internal buffers. If all of the conditions _are_ met,
    /// the returned packet will be a sub-slice of `pkt`, and no bytes will be copied into
    /// internal buffers.
    ///
    /// # Panics
    ///
    /// This method will not check the incoming packet's contents before processing it. It is
    /// up to the caller of this method to ensure that `pkt` is not malformed. A packet that
    /// does not conform to the required layer type may lead to a panic condition, or it may
    /// alter the stream of output packets in an unexpected way.
    fn put_and_get_unchecked<'a>(&'a mut self, pkt: &'a [u8]) -> Option<&'a [u8]>;

    /// Processes the incoming `pkt` relative to the current sequence's state, performing
    /// defragmentation and reordering as necessary. The sequence will not check the packet's
    /// contents before processing it and will assume that it is not malformed or otherwise
    /// invalid.
    ///
    /// This method will bypass the Sequence's filter (if any filter is set), such that
    /// packets that would otherwise be discarded due to the filter are allowed through.
    fn put_unfiltered_unchecked(&mut self, pkt: &[u8]);

    /// Retrieves the next packet from the Sequence, or returns None if there are no more packets
    /// that are ready to be fetched.
    ///
    /// Each invocation of `get()` always returns the next in-order packet--each packet will
    /// only be returned once.
    fn get(&mut self) -> Option<&[u8]>;

    /// Retrieves the filter being used by the Sequence type, or None if no filter has been applied.
    fn filter(&self) -> Option<&PktFilterDynFn>;

    /// Sets the filter of the Sequence type, discarding any current filter in place.
    ///
    /// Note that this filter type operates on a raw slice of bytes; to set a filter that operates
    /// on the input packet type, see [`set_filter()`](UnboundedSequence::set_filter()).
    fn set_filter_raw(&mut self, filter: Option<fn(&[u8]) -> bool>);
}

pub trait Sequence: SequenceObject + Sized {
    type In<'a>: LayerRef<'a> + Validate;

    /// Processes the incoming `pkt` relative to the current sequence's state, performing
    /// defragmentation and reordering as necessary.
    #[inline]
    fn put(&mut self, pkt: Self::In<'_>) {
        self.put_unchecked(pkt.into());
    }

    /// Both processes the incoming `pkt` and returns the next upper-layer packet in a
    /// zero-copy manner. This method has the potential to be much more efficient than
    /// calls to [`Sequence::put()`] and [`SequenceObject::get()`], but only under
    /// particular circumstances. Zero-copy will only happen if:
    /// 1. The inserted packet is not fragmented (only applicable if fragmentation occurs
    /// in the protocol, such as for [`Ipv4Sequence`]).
    /// 2. The inserted packet is the next required packet in order (only applicable if
    /// the Sequence enforces ordering on the packets, such as for `TcpSequence`).
    /// 3. There are no outstanding packets that can be fetched from the sequence using
    /// [`SequenceObject::get()`].
    ///
    /// If any of the above conditions are _not_ met, the packet will be copied into internal
    /// buffers and processed like normal, and the method will optionally return a packet that
    /// has been reassembled/reordered in internal buffers. If all of the conditions _are_ met,
    /// the returned packet will be a sub-slice of `pkt`, and no bytes will be copied into
    /// internal buffers.
    fn put_and_get<'a>(&'a mut self, pkt: Self::In<'a>) -> Option<&'a [u8]> {
        self.put_and_get_unchecked(pkt.into())
    }

    /// Processes the incoming `pkt` relative to the current sequence's state, performing
    /// defragmentation and reordering as necessary.
    ///
    /// This method will bypass the Sequence's filter (if any filter is set), such that
    /// packets that would otherwise be discarded due to the filter are allowed through.
    #[inline]
    fn put_unfiltered(&mut self, pkt: Self::In<'_>) {
        self.put_unchecked(pkt.into());
    }
}

#[cfg(feature = "alloc")]
pub trait UnboundedSequence: Sequence {
    /// Sets the filter of the Sequence type, discarding any current filter in place.
    fn set_filter<F: Fn(Self::In<'_>) -> bool + 'static>(&mut self, filter: Option<F>);

    /// Sets the filter of the Sequence type, discarding any current filter in place,
    /// and returns the sequence type as its output.
    ///
    /// This variant of [`set_filter()`](UnboundedSequence::set_filter()) is useful for creating
    /// [`LayeredSequence`] instances:
    ///
    /// ```
    /// let seq = LayeredSequence::new(Ipv4Sequence::new().with_filter(|ip| !(ip.src() == 0 || ip.dst() == 0)), true)
    ///         .add_bounded(StcpSequence::new().with_filter(|sctp| sctp.sport() == 4321 && sctp.verify_tag() == 1111));
    /// ```
    #[inline]
    fn with_filter<F: Fn(Self::In<'_>) -> bool + 'static>(mut self, filter: Option<F>) -> Self {
        self.set_filter(filter);
        self
    }
}

/// A variation of the `first_mut()` slice method that retrieves the first two
/// mut references, if they exist.
#[inline]
fn first_two_mut<T>(slice: &mut [T]) -> Option<(&mut T, &mut T)> {
    if let Some((f, rem)) = slice.split_first_mut() {
        if let Some((s, _)) = rem.split_first_mut() {
            return Some((f, s));
        }
    }

    None
}

struct SequenceLayer {
    layer: Box<dyn SequenceObject>,
    validation: ValidateFn,
    bytes: Option<Vec<u8>>,
}

impl SequenceLayer {
    fn new(
        upper_layer: Box<dyn SequenceObject>,
        validation: ValidateFn,
        bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            layer: upper_layer,
            validation,
            bytes,
        }
    }
}

#[cfg(feature = "alloc")]
pub struct LayeredSequence<T: BaseLayer> {
    first: Box<dyn SequenceObject>,
    first_streambuf: Option<Vec<u8>>,
    layers: Vec<SequenceLayer>,
    _marker: PhantomData<T>,
}

#[cfg(feature = "alloc")]
impl<'b, T: LayerRef<'b>> LayeredSequence<T> {
    /// Creates a new [`LayeredSequence`] and sets `seq` as its first (outermost) layer.
    #[inline]
    pub fn new<'a, S: Sequence<In<'a> = T> + 'static>(seq: S, has_msg_bounds: bool) -> Self {
        LayeredSequence {
            first: Box::new(seq),
            first_streambuf: if has_msg_bounds {
                Some(Vec::new())
            } else {
                None
            },
            layers: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Add another [`Sequence`] that acts on the output of the current sequence(s).
    pub fn add<'a, L: LayerRef<'a> + Validate, S: Sequence<In<'a> = L> + 'static>(
        self,
        seq: S,
        has_msg_bounds: bool,
    ) -> Self {
        let streambuf = if has_msg_bounds {
            None
        } else {
            Some(Vec::new())
        };

        let mut new_self = self;
        new_self
            .layers
            .push(SequenceLayer::new(Box::new(seq), L::validate, streambuf));
        new_self
    }

    /// Append a Sequence that satisfies the message bound property.
    #[inline]
    pub fn add_bounded<'a, L: LayerRef<'a> + Validate, S: Sequence<In<'a> = L> + 'static>(
        self,
        seq: S,
    ) -> Self {
        self.add(seq, true)
    }

    /// Append a Sequence that does not satisfy the message bound property.
    #[inline]
    pub fn add_unbounded<'a, L: LayerRef<'a> + Validate, S: Sequence<In<'a> = L> + 'static>(
        self,
        seq: S,
    ) -> Self {
        self.add(seq, false)
    }

    /// Add another packet to the sequence for processing
    #[inline]
    pub fn put(&mut self, pkt: T) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_unchecked(pkt_ref)
    }

    /// Add another packet to the sequence for processing without validating
    /// the correctness of that packet.
    ///
    /// # Safety
    ///
    /// This method will not check the incoming packet's contents before processing it. It is
    /// up to the caller of this method to ensure that `pkt` is not malformed. A packet that
    /// does not conform to the required layer type may lead to a panic condition, or it may
    /// alter the stream of output packets in an unexpected way.
    pub fn put_unchecked(&mut self, pkt: &[u8]) -> Result<(), ValidationError> {
        let mut upper_layer_updated = match self.layers.first_mut() {
            Some(upper_layer) => Self::percolate_up(
                self.first.as_mut(),
                upper_layer.layer.as_mut(),
                &mut self.first_streambuf,
                &upper_layer.validation,
            )?,
            None => {
                self.first.put_unchecked(pkt);
                false
            }
        };

        let mut lower_idx = 0;
        while let Some((lower_layer, upper_layer)) = first_two_mut(&mut self.layers[lower_idx..]) {
            if !upper_layer_updated {
                break;
            }
            // Iteratively 'percolate' the packets up the various layers as defragmentation of lower layers
            // makes higher layer packets available

            upper_layer_updated = Self::percolate_up(
                lower_layer.layer.as_mut(),
                upper_layer.layer.as_mut(),
                &mut lower_layer.bytes,
                &upper_layer.validation,
            )?;
            lower_idx += 1;
        }

        Ok(())
    }

    /// Extract all available packets from a lower layer, passing them on to the
    /// next layer when appropriate.
    fn percolate_up(
        lower: &mut dyn SequenceObject,
        upper: &mut dyn SequenceObject,
        streambuf: &mut Option<Vec<u8>>,
        validate: &ValidateFn,
    ) -> Result<bool, ValidationError> {
        let mut pkts_moved = false;
        while let Some(pkt) = lower.get() {
            match streambuf {
                Some(sb) => {
                    sb.extend(pkt);
                }
                None => {
                    validate(pkt)?;
                    upper.put_unchecked(pkt);
                    pkts_moved = true;
                }
            }
        }

        if let Some(sb) = streambuf {
            loop {
                if let Err(e) = validate(sb.as_slice()) {
                    match e.class {
                        ValidationErrorClass::InsufficientBytes => break,
                        ValidationErrorClass::ExcessBytes(num_trailing) => {
                            let pkt_size = sb.len() - num_trailing;
                            upper.put_unchecked(&sb.as_slice()[..pkt_size]);
                            pkts_moved = true;
                            sb.drain(0..pkt_size);
                            // This is the only case that should loop (in case there are more packets in the stream)
                        }
                        _ => return Err(e),
                    }
                } else {
                    // validate() returned Ok(())--the packet is the *exact* length needed
                    upper.put_unchecked(sb.as_slice());
                    pkts_moved = true;
                    sb.clear();
                    break;
                }
            }
        }

        Ok(pkts_moved)
    }

    /// Retrieve an unfragmented and correctly ordered (where applicable) packet
    /// from the final Sequence of this LayeredSequence.
    pub fn get(&mut self) -> Option<&[u8]> {
        match self.layers.last_mut() {
            Some(seq) => seq.layer.get(),
            None => self.first.get(),
        }
    }
}

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
        let mf = ipv4.flags().more_fragments();
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
        let mf = ipv4.flags().more_fragments();
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
struct Ipv4Fragments<const FRAG_CNT: usize, S = RandomState> {
    fragments: HashMap<u16, Ipv4Fragment, S>,
    insert_order: VecDeque<u16>,
    reassembled: Vec<u8>,
    retrieved: bool,
}

#[cfg(feature = "alloc")]
impl<const FRAG_CNT: usize> Ipv4Fragments<FRAG_CNT> {
    #[inline]
    pub fn new() -> Self {
        Ipv4Fragments {
            fragments: HashMap::new(),
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
        if !flags.unordered() && diff >= RWND {
            return; // Drop packet--not within receive window
        }

        if flags.beginning_fragment() && flags.ending_fragment() {
            // The packet isn't a fragment--it only needs to be reordered
            if flags.unordered() {
                // The packet isn't a fragment, and doesn't need to be reordered
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
                (flags.beginning_fragment(), flags.ending_fragment()),
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

    pub fn data(&self) -> &'a [u8] {
        let len = self.data_length() as usize;
        self.data
            .get(4..4 + len)
            .expect("internal error: FragHeader::data() out of bounds")
    }

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

    pub fn next_offset(&self) -> usize {
        self.offset + 4 + self.data_length() as usize
    }
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
    fragments: HashMap<Option<u16>, Vec<SctpFragmentEntry>>,
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
            fragments: HashMap::new(),
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
                    if frag.flags.beginning_fragment() {
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

            if frag.flags.ending_fragment() {
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
            if flags.beginning_fragment() && flags.ending_fragment() {
                if flags.unordered() {
                    self.out.push_back(Vec::from(payload.user_data()));
                } else {
                    self.put_unordered(payload.stream_seq(), Vec::from(payload.user_data()));
                }
            } else {
                let tsn = payload.tsn();
                let ssn = if flags.unordered() {
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
                        if entry.flags.beginning_fragment() {
                            beginning_seen = true;
                        }

                        if beginning_seen {
                            reassembled.append(&mut entry.data);
                        }

                        if entry.flags.ending_fragment() {
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
