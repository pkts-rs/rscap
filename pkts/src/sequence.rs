// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <contact@rscap.org>

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

use std::collections::{HashMap, VecDeque};
use core::marker::PhantomData;

use core::iter::Iterator;
use core::{cmp, mem};

use crate::error::*;
use crate::layers::ip::Ipv4Ref;
use crate::layers::sctp::{DataChunkFlags, SctpRef};
use crate::layers::traits::*;
use crate::layers::traits::Validate;
use crate::utils;

type PktFilterDynFn = dyn Fn(&[u8]) -> bool;
type ValidateFn = fn (bytes: &[u8]) -> Result<(), ValidationError>;

/// Indicates
pub trait MessageBounds { }


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
    /// the Sequence enforces ordering on the packets, such as for [`TcpSequence`]).
    /// 3. There are no outstanding packets that can be fetched from the sequence using 
    /// [`SequenceObject::get()`].
    /// 
    /// If any of the above conditions are _not_ met, the packet will be copied into internal
    /// buffers and processed like normal, and the method will optionally return a packet that
    /// has been reassembled/reordered in internal buffers. If all of the conditions _are_ met,
    /// the returned packet will be a sub-slice of `pkt`, and no bytes will be copied into
    /// internal buffers.
    /// 
    /// # Safety
    /// 
    /// This method will not check the incoming packet's contents before processing it. It is
    /// up to the caller of this method to ensure that `pkt` is not malformed. A packet that 
    /// does not conform to the required layer type may lead to a panic condition, or it may
    /// alter the stream of output packets in an unexpected way.
    fn put_and_get_unchecked<'a>(&mut self, pkt: &'a [u8]) -> Option<&'a [u8]>;

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
    /// Note that this filter type operates on a raw slice of bytes; to set a filter
    /// that operates on the input packet type, see [`Sequence::set_filter()`].
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
    /// the Sequence enforces ordering on the packets, such as for [`TcpSequence`]).
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

    /// Sets the filter of the Sequence type, discarding any current filter in place.
    fn set_filter<F: Fn(Self::In<'_>) -> bool + 'static>(&mut self, filter: Option<F>);

    /// Sets the filter of the Sequence type, discarding any current filter in place,
    /// and returns the sequence type as its output.
    /// 
    /// This variant of [`Sequence::set_filter()`] is useful for creating
    /// [`LayeredSequence`] instances:
    /// 
    /// ```rs
    /// let seq = LayeredSequence::new(Ipv4Sequence::new().with_filter(|ip| !(ip.saddr() == 0 || ip.daddr() == 0)), true)
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
            return Some((f, s))
        }
    }

    return None
}

pub struct LayeredSequence<T: BaseLayer + ToSlice> {
    first: Box<dyn SequenceObject>,
    first_streambuf: Option<Vec<u8>>,
    layers: Vec<(Box<dyn SequenceObject>, ValidateFn, Option<Vec<u8>>)>,
    _marker: PhantomData<T>,
}

impl<T: BaseLayer + ToSlice> LayeredSequence<T> {
    /// Creates a new [`LayeredSequence`] and sets `seq` as its first (outermost) layer.
    #[inline]
    pub fn new<'a, S: Sequence<In<'a> = T> + 'static>(seq: S, has_msg_bounds: bool) -> Self {
        LayeredSequence {
            first: Box::new(seq),
            first_streambuf: if has_msg_bounds { Some(Vec::new()) } else { None },
            layers: Vec::new(),
            _marker: PhantomData::default(),
        }
    }

    /// Add another [`Sequence`] that acts on the output of the current sequence(s).
    #[inline]
    pub fn add<'a, L: LayerRef<'a> + Validate, S: Sequence<In<'a>=L> + 'static>(self, seq: S, has_msg_bounds: bool) -> Self {
        let streambuf = if has_msg_bounds {
            None
        } else {
            Some(Vec::new())
        };

        let mut new_self = self;
        new_self.layers.push((Box::new(seq), L::validate, streambuf));
        new_self
    }

    /// Append a Sequence that satisfies the message bound property.
    #[inline]
    pub fn add_bounded<'a, L: LayerRef<'a> + Validate, S: Sequence<In<'a>=L> + 'static>(self, seq: S) -> Self {
        self.add(seq, true)
    }

    /// Append a Sequence that does not satisfy the message bound property.
    #[inline]
    pub fn add_unbounded<'a, L: LayerRef<'a> + Validate, S: Sequence<In<'a>=L> + 'static>(self, seq: S) -> Self {
        self.add(seq, false)
    }

    /// Add another packet to the sequence for processing
    #[inline]
    pub fn put(&mut self, pkt: T) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.to_slice();
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
    #[inline]
    pub fn put_unchecked(&mut self, pkt: &[u8]) -> Result<(), ValidationError> {
        let mut upper_layer_updated = match self.layers.first_mut() {
            Some((upper, validate, _)) => Self::percolate_up(self.first.as_mut(), upper.as_mut(), &mut self.first_streambuf, validate)?,
            None => {
                self.first.put_unchecked(pkt);
                false
            }
        };

       let mut lower_idx = 0;
       while let Some(((lower, _, streambuf), (upper, validate, _))) = first_two_mut(&mut self.layers[lower_idx..]) {
            if !upper_layer_updated {
                break
            }
            // Iteratively 'percolate' the packets up the various layers as defragmentation of lower layers 
            // makes higher layer packets available

            upper_layer_updated = Self::percolate_up(lower.as_mut(), upper.as_mut(), streambuf, validate)?;
            lower_idx += 1;
        }

        Ok(())
    }

    /// Extract all available packets from a lower layer, passing them on to the
    /// next layer when appropriate.
    fn percolate_up(lower: &mut dyn SequenceObject, upper: &mut dyn SequenceObject, streambuf: &mut Option<Vec<u8>>, validate: &ValidateFn) -> Result<bool, ValidationError> {
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
                    match e.err_type {
                        ValidationErrorType::InsufficientBytes => break,
                        ValidationErrorType::ExcessBytes(num_trailing) => {
                            let pkt_size = sb.len() - num_trailing;
                            upper.put_unchecked(&sb.as_slice()[..pkt_size]);
                            pkts_moved = true;
                            sb.drain(0..pkt_size);
                            // This is the only case that should loop (in case there are more packets in the stream)
                        }
                        _ => return Err(e),
                    }
                } else { // validate() returned Ok(())--the packet is the *exact* length needed
                    upper.put_unchecked(sb.as_slice());
                    pkts_moved = true;
                    sb.clear();
                    break
                }
            }
        }

        Ok(pkts_moved)
    }

    /// Retrieve an unfragmented and correctly ordered (where applicable) packet
    /// from the final Sequence of this LayeredSequence.
    pub fn get(&mut self) -> Option<&[u8]> {
        match self.layers.last_mut() {
            Some((s, _, _)) => s.get(),
            None => self.first.get(),
        }
    }
}

/// A [`Sequence`] type that handles defragmentation of IPv4 packets.
/// This Sequence guarantees that packets returned from it will be
/// defragmented and have message bounds preserved, though it does
/// not mandate any particular ordering of packets (since IPv4 does
/// not guarantee in-order packet delivery).
pub struct Ipv4Sequence {
    filter: Option<Box<PktFilterDynFn>>,
    fragments: Ipv4Fragments,
    reassembled: VecDeque<Vec<u8>>,
    first_retrieved: bool,
}

impl Ipv4Sequence {
    /// Create a new `Ipv4Sequence` instance.
    #[inline]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Ipv4Sequence {
            filter: None,
            fragments: Ipv4Fragments::new(),
            reassembled: VecDeque::new(),
            first_retrieved: false,
        }
    }
}

impl SequenceObject for Ipv4Sequence {
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

    fn put_and_get_unchecked<'a>(&mut self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        todo!()
    }

    fn put_unfiltered_unchecked(&mut self, pkt: &[u8]) {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(pkt);
        let ihl = cmp::max(ipv4.ihl() as usize, 5) * 4;
        let tl = cmp::max(ipv4.total_length() as usize, ihl);
        let data = pkt.get(ihl..tl).expect("IPv4 Defragment instance encountered packet containing fewer bytes than advertised in its Total Length field");

        let mf = ipv4.flags().more_fragments();
        let fo = ipv4.frag_offset() as usize;

        if fo == 0 && !mf {
            self.fragments.clear();

            let payload = pkt[ihl..].to_vec();
            self.reassembled.push_back(payload);
            return
        }

        let data_start = fo * 8;
        self.fragments.put(data, data_start);
        if !mf {
            self.fragments.set_last_frag_seen();
        }

        if self.fragments.is_filled() {
            let res = self.fragments.data();
            self.fragments.clear();
            self.reassembled.push_back(res);
        }
    }

    fn get(&mut self) -> Option<&[u8]> {
        if self.first_retrieved {
            self.reassembled.pop_front();
        } else {
            self.first_retrieved = true;
        }

        match self.reassembled.front() {
            Some(f) => Some(f.as_slice()),
            None => None
        }
    }
}

impl Sequence for Ipv4Sequence {
    type In<'a> = Ipv4Ref<'a>;

    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filt: Option<F>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(move |i| f(Ipv4Ref::from_bytes_unchecked(i)))),
            None => None,
        }
    }
}

// TODO: allow multiple fragmented packets with different ids to be handled simultaneously
struct Ipv4Fragments {
    tdl: usize,
    data: Vec<u8>, // length of this is total_data_len
    rcvbt: utils::BitVec,
    last_frag_seen: bool,
}

impl Ipv4Fragments {
    #[inline]
    pub fn new() -> Self {
        Ipv4Fragments {
            tdl: 0,
            data: Vec::new(),
            rcvbt: utils::BitVec::new(),
            last_frag_seen: false,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.tdl = 0;
        self.data.clear();
        self.rcvbt.clear();
        self.last_frag_seen = false;
    }

    #[inline]
    pub fn put(&mut self, data: &[u8], start: usize) {
        if data.is_empty() {
            return;
        }

        let original_len = self.data.len();
        if original_len < start + data.len() {
            self.data[start..].copy_from_slice(&data[..(original_len - start)]);
            self.data.extend_from_slice(&data[original_len..]);
        } else {
            self.data[start..(start + data.len())]
                .copy_from_slice(&data[..(start + data.len() - start)]);
        }

        self.rcvbt.set(start, start + data.len());
    }

    #[inline]
    pub fn set_last_frag_seen(&mut self) {
        self.last_frag_seen = true;
    }

    #[inline]
    pub fn is_filled(&self) -> bool {
        self.last_frag_seen && self.rcvbt.is_filled()
    }

    #[inline]
    pub fn data(&mut self) -> Vec<u8> {
        mem::take(&mut self.data)
    }
}

/// While many normal use cases do not assume that IP messages form message boundaries (such as TCP),
/// there are instances where IPv4 packets uniquely bound messages.
/// For instance, ICMP messages are encapsulated within IPv4 packets, but they have 
/// no length field--it is determined by the IPv4 packet bound.
impl MessageBounds for Ipv4Fragments { }

// Note: it is the caller's responsibility to ensure that packets are input from the same src/dst port, in the same direction, and from the same stream identifier.
// The `SctpDefrag` is only responsible for ensuring packets of a stream come in order (unless the unordered bit is set) and are defragmented.
pub struct SctpSequence<const WINDOW: usize = 25> {
    filter: Option<Box<PktFilterDynFn>>,
    fragments: HashMap<Option<u16>, Vec<(u32, DataChunkFlags, Vec<u8>)>>,
    stream_seq: Option<u16>,
    unordered: utils::ArrayRing<Vec<u8>, WINDOW>,
    out: VecDeque<Vec<u8>>,
    first_retrieved: bool,
}

impl<const WINDOW: usize> SctpSequence<WINDOW> {
    #[inline]
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

    #[inline]
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

    fn frags_complete(frags: &[(u32, DataChunkFlags, Vec<u8>)]) -> bool {
        let mut i = frags.iter();

        let start_tsn = loop {
            match i.next() {
                Some((t, f, _)) => {
                    if f.beginning_fragment() {
                        break *t;
                    }
                }
                None => return false,
            }
        };

        for (idx, (tsn, f, _)) in i.enumerate() {
            if *tsn != start_tsn + idx as u32 + 1 {
                return false;
            }

            if f.ending_fragment() {
                return true;
            }
        }

        false
    }
}

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

    fn put_and_get_unchecked<'a>(&mut self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        todo!()
    }

    fn put_unfiltered_unchecked(&mut self, pkt: &[u8]) {
        let sctp = SctpRef::from_bytes_unchecked(pkt);

        let mut data_chunks = sctp.payload_chunks();

        while let Some(payload) = data_chunks.next() {
            let flags = payload.flags();
            if flags.beginning_fragment() && flags.ending_fragment() {
                if flags.unordered() {
                    self.out.push_back(Vec::from(payload.user_data()));
                } else {
                    self.put_unordered(payload.stream_seq(), Vec::from(payload.user_data()));
                }
            } else {
                let tsn = payload.tsn();
                let ssn = if flags.unordered() { None } else { Some(payload.stream_seq()) };

                let frags = self.fragments.entry(ssn).or_insert(Vec::new());

                match frags.binary_search_by(|(t, _, _)| t.cmp(&tsn)) {
                    Ok(idx) => {
                        // Swap out existing value with new one
                        let mut p = (tsn, flags, Vec::from(payload.user_data()));
                        mem::swap(&mut p, frags.get_mut(idx).unwrap());
                    }
                    Err(idx) => frags.insert(idx, (tsn, flags, Vec::from(payload.user_data()))),
                }

                // Now reassemble the fragments if they're complete
                if Self::frags_complete(frags) {
                    let mut reassembled = Vec::new();
                    let mut beginning_seen = false;
                    for (_, f, v) in frags {
                        if f.beginning_fragment() {
                            beginning_seen = true;
                        }

                        if beginning_seen {
                            reassembled.append(v);
                        }

                        if f.ending_fragment() {
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
            None => None
        }
    }
}

impl Sequence for SctpSequence {
    type In<'a> = SctpRef<'a>;

    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filt: Option<F>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(move |i| f(SctpRef::from_bytes_unchecked(i)))),
            None => None,
        }
    }
}

/// For most uses, SCTP messages are considered distinct and bounded.
impl MessageBounds for SctpSequence { }















/*

pub trait BaseDefragment {
    #[inline]
    fn put_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        match self.filter() {
            Some(should_discard_packet) if should_discard_packet(pkt.as_slice()) => Ok(()),
            _ => self.put_unfiltered_pkt_unchecked(pkt),
        }
    }

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError>;

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>>;

    fn filter(&self) -> Option<&PktFilterDynFn>;

    fn set_filter_raw(&mut self, filter: Option<fn(&[u8]) -> bool>);
}

pub trait Defragment<Out: LayerObject + Validate + FromBytes>: BaseDefragment {
    type In<'a>: LayerRef<'a>;

    #[inline]
    fn put_pkt(&mut self, pkt: Self::In<'_>) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_pkt_unchecked(Vec::from(pkt_ref))
    }

    #[inline]
    fn put_unfiltered_pkt(&mut self, pkt: Self::In<'_>) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_pkt_unchecked(Vec::from(pkt_ref))
    }

    #[inline]
    fn get_pkt(&mut self) -> Option<Out> {
        self.get_pkt_raw()
            .map(|pkt| Out::from_bytes_unchecked(pkt.as_ref()))
    }

    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filter: Option<F>);

    //    fn set_filter<'a>(&mut self, filter: Option<impl Fn(&Self::In<'a>) -> bool>);
}

pub struct DefragmentLayers<
    FirstIn: ToOwnedLayer + Validate,
    LastOut: LayerObject + Validate + FromBytes,
> {
    sessions: Vec<Box<dyn BaseDefragment>>,
    _in: PhantomData<FirstIn>,
    _out: PhantomData<LastOut>,
}

impl<
        'a,
        In: for<'b> LayerRef<'b> + ToOwnedLayer + Validate,
        Out: LayerObject + Validate + FromBytes,
    > DefragmentLayers<In, Out>
{
    #[inline]
    pub fn new<S: Defragment<Out, In<'a> = In> + 'static>(sequence: S) -> Self {
        DefragmentLayers {
            sessions: vec![Box::new(sequence)],
            _in: PhantomData::default(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn append<
        I: ToOwned<Owned = Out> + Validate,
        O: LayerObject + Validate + FromBytes,
        S: Defragment<Out, In<'a> = I> + 'static,
    >(
        mut self,
        sequence: S,
    ) -> DefragmentLayers<In, O> {
        self.sessions.push(Box::new(sequence));
        DefragmentLayers {
            sessions: self.sessions,
            _in: PhantomData::default(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn put_pkt(&mut self, pkt: In) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_pkt_unchecked(Vec::from(pkt_ref))
    }

    #[inline]
    pub fn put_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        let mut pkts = vec![pkt];
        let num_sessions = self.sessions.len();
        for (session_idx, session) in self.sessions.iter_mut().enumerate() {
            while let Some(pkt) = pkts.pop() {
                session.put_pkt_unchecked(pkt)?;
            }

            if session_idx + 1 == num_sessions {
                break; // Once we've reached the last session, we don't want to pull its packets
            }

            while let Some(pkt) = session.get_pkt_raw() {
                pkts.push(pkt);
            }

            if pkts.is_empty() {
                break;
            }
        }

        Ok(())
    }

    #[inline]
    pub fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        match self.sessions.last_mut() {
            None => None,
            Some(session) => session.get_pkt_raw(),
        }
    }

    #[inline]
    pub fn get_pkt(&mut self) -> Option<Out> {
        self.get_pkt_raw()
            .map(|pkt| Out::from_bytes_unchecked(pkt.as_ref()))
    }
}

pub struct Ipv4Defrag<Out: LayerObject + FromBytes + BaseLayerMetadata> {
    filter: Option<Box<PktFilterDynFn>>,
    fragments: Ipv4Fragments,
    reassembled: VecDeque<Vec<u8>>,
    _out: PhantomData<Out>,
}

impl<Out: LayerObject + FromBytes + BaseLayerMetadata> Ipv4Defrag<Out> {
    #[inline]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        /*
        assert!(Out::metadata()
            .as_any()
            .downcast_ref::<&dyn Ipv4PayloadMetadata>()
            .is_some(),
            "Ipv4Session instances can only be created for Layer types that implement `Ipv4Metadata` for their associated metadata");
        */
        // TODO: should this be a compile-time constraint??

        Ipv4Defrag {
            filter: None,
            fragments: Ipv4Fragments::new(),
            reassembled: VecDeque::new(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn new_filtered(filter: fn(&[u8]) -> bool) -> Self {
        /*
        assert!(Out::metadata()
            .as_any()
            .downcast_ref::<&dyn Ipv4PayloadMetadata>()
            .is_some(),
            "Ipv4Session instances can only be created for Layer types that implement `Ipv4Metadata` for their associated metadata");
        */
        // TODO: should this be a compile-time constraint??

        Ipv4Defrag {
            filter: Some(Box::new(filter)),
            fragments: Ipv4Fragments::new(),
            reassembled: VecDeque::new(),
            _out: PhantomData::default(),
        }
    }
}

impl<Out: LayerObject + FromBytes + BaseLayerMetadata> BaseDefragment for Ipv4Defrag<Out> {
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

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(pkt.as_slice());
        let ihl = cmp::max(ipv4.ihl() as usize, 5) * 4;
        let tl = cmp::max(ipv4.total_length() as usize, ihl);
        let data = pkt.get(ihl..tl).expect("IPv4 Defragment instance encountered packet containing fewer bytes than advertised in its Total Length field");

        let mf = ipv4.flags().more_fragments();
        let fo = ipv4.frag_offset() as usize;

        if fo == 0 && !mf {
            self.fragments.clear();

            Out::validate_current_layer(&pkt[ihl..])?;
            let payload = pkt[ihl..].to_vec();
            self.reassembled.push_back(payload);
            return Ok(());
        }

        let data_start = fo * 8;
        self.fragments.put(data, data_start);
        if !mf {
            self.fragments.set_last_frag_seen();
        }

        if self.fragments.is_filled() {
            let res = self.fragments.data();
            self.fragments.clear();
            self.reassembled.push_back(res);
        }

        Ok(())
    }

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        self.reassembled.pop_front()
    }
}

// Note that this effectively closes `Ipv4Session` to implementation of `Defragment`
// by other `Layer` types unless they implement StatelessLayer
impl<L: LayerObject + BaseLayerMetadata + FromBytes> Defragment<L> for Ipv4Defrag<L> {
    type In<'a> = Ipv4Ref<'a>;

    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filt: Option<F>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(move |i| f(Ipv4Ref::from_bytes_unchecked(i)))),
            None => None,
        }
    }
}

// TODO: allow multiple fragmented packets with different ids to be handled simultaneously
struct Ipv4Fragments {
    tdl: usize,
    data: Vec<u8>, // length of this is total_data_len
    rcvbt: utils::BitVec,
    last_frag_seen: bool,
}

impl Ipv4Fragments {
    #[inline]
    pub fn new() -> Self {
        Ipv4Fragments {
            tdl: 0,
            data: Vec::new(),
            rcvbt: utils::BitVec::new(),
            last_frag_seen: false,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.tdl = 0;
        self.data.clear();
        self.rcvbt.clear();
        self.last_frag_seen = false;
    }

    #[inline]
    pub fn put(&mut self, data: &[u8], start: usize) {
        if data.is_empty() {
            return;
        }

        let original_len = self.data.len();
        if original_len < start + data.len() {
            self.data[start..].copy_from_slice(&data[..(original_len - start)]);
            self.data.extend_from_slice(&data[original_len..]);
        } else {
            self.data[start..(start + data.len())]
                .copy_from_slice(&data[..(start + data.len() - start)]);
        }

        self.rcvbt.set(start, start + data.len());
    }

    #[inline]
    pub fn set_last_frag_seen(&mut self) {
        self.last_frag_seen = true;
    }

    #[inline]
    pub fn is_filled(&self) -> bool {
        self.last_frag_seen && self.rcvbt.is_filled()
    }

    #[inline]
    pub fn data(&mut self) -> Vec<u8> {
        mem::take(&mut self.data)
    }
}

/*
// TODO: where would a TcpDefrag start its seq/ack values at? Maybe more things have to be sessions than initially intended...
pub struct TcpDefrag<Out: LayerObject + FromBytes + BaseLayerMetadata> {
    filter: Option<Box<dyn Fn(&[u8]) -> bool>>,
    fragments: VecDeque<Vec<u8>>,
    reassembled: VecDeque<Vec<u8>>,
    seq: u32,
    _out: PhantomData<Out>,
}

impl<Out: LayerObject + FromBytes + BaseLayerMetadata> TcpDefrag<Out> {
    #[inline]
    pub fn new() -> Self {
        todo!()
    }

    #[inline]
    pub fn new_filtered(filter: fn(&[u8]) -> bool) -> Self {
        todo!()
    }
}

impl<Out: LayerObject + FromBytes + BaseLayerMetadata> BaseDefragment
    for TcpDefrag<Out>
{
    #[inline]
    fn set_filter_raw(&mut self, filt: Option<fn(&[u8]) -> bool>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(f)),
            None => None,
        }
    }

    #[inline]
    fn filter(&self) -> Option<&Box<dyn Fn(&[u8]) -> bool>> {
        self.filter.as_ref()
    }

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        Ok(())
    }

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        self.reassembled.pop_front()
    }
}
*/

// Note: it is the caller's responsibility to ensure that packets are input from the same src/dst port, in the same direction, and from the same stream identifier.
// The `SctpDefrag` is only responsible for ensuring packets of a stream come in order (unless the unordered bit is set) and are defragmented.
pub struct SctpDefrag<Out: LayerObject + FromBytes + BaseLayerMetadata, const WINDOW: usize = 25> {
    filter: Option<Box<PktFilterDynFn>>,
    fragments: HashMap<Option<u16>, Vec<(u32, DataChunkFlags, Vec<u8>)>>,
    stream_seq: Option<u16>,
    unordered: utils::ArrayRing<Vec<u8>, WINDOW>,
    out: VecDeque<Vec<u8>>,
    _out_type: PhantomData<Out>,
}

impl<Out: LayerObject + FromBytes + BaseLayerMetadata, const WINDOW: usize>
    SctpDefrag<Out, WINDOW>
{
    #[inline]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SctpDefrag {
            filter: None,
            fragments: HashMap::new(),
            stream_seq: None,
            unordered: utils::ArrayRing::new(),
            out: VecDeque::new(),
            _out_type: PhantomData::default(),
        }
    }

    #[inline]
    pub fn new_filtered(filter: fn(&[u8]) -> bool) -> Self {
        SctpDefrag {
            filter: Some(Box::new(filter)),
            fragments: HashMap::new(),
            stream_seq: None,
            unordered: utils::ArrayRing::new(),
            out: VecDeque::new(),
            _out_type: PhantomData::default(),
        }
    }

    #[inline]
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

    fn frags_complete(frags: &[(u32, DataChunkFlags, Vec<u8>)]) -> bool {
        let mut i = frags.iter();

        let start_tsn = loop {
            match i.next() {
                Some((t, f, _)) => {
                    if f.beginning_fragment() {
                        break *t;
                    }
                }
                None => return false,
            }
        };

        for (idx, (tsn, f, _)) in i.enumerate() {
            if *tsn != start_tsn + idx as u32 + 1 {
                return false;
            }

            if f.ending_fragment() {
                return true;
            }
        }

        false
    }
}

#[inline]
fn choose_err(
    e1: Result<(), ValidationError>,
    e2: Result<(), ValidationError>,
) -> Result<(), ValidationError> {
    match (e1, e2) {
        (_, Ok(_)) => e1, // includes (Ok(_), Ok(_))
        (Ok(_), _) => e2,
        (Err(e), _) if e.err_type == ValidationErrorType::InsufficientBytes => e1,
        (_, Err(e)) if e.err_type == ValidationErrorType::InsufficientBytes => e2,
        (Err(e), _) if e.err_type == ValidationErrorType::InvalidValue => e1,
        (_, Err(e)) if e.err_type == ValidationErrorType::InvalidValue => e2,
        _ => e1, // ValidationErrorType::ExcessBytes(_)
    }
}

impl<Out: LayerObject + FromBytes + BaseLayerMetadata, const WINDOW: usize> BaseDefragment
    for SctpDefrag<Out, WINDOW>
{
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

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        let sctp = SctpRef::from_bytes_unchecked(pkt.as_slice());

        let mut data_chunks = sctp.payload_chunks();

        let mut res = Ok(());
        while let Some(payload) = data_chunks.next() {
            let flags = payload.flags();
            if flags.beginning_fragment() && flags.ending_fragment() {
                res = choose_err(res, Out::validate(payload.user_data()));

                if flags.unordered() {
                    self.out.push_back(Vec::from(payload.user_data()));
                } else {
                    self.put_unordered(payload.stream_seq(), Vec::from(payload.user_data()));
                }
            } else {
                let tsn = payload.tsn();
                let ssn = if flags.unordered() { None } else { Some(payload.stream_seq()) };

                let frags = self.fragments.entry(ssn).or_insert(Vec::new());

                match frags.binary_search_by(|(t, _, _)| t.cmp(&tsn)) {
                    Ok(idx) => {
                        // Swap out existing value with new one
                        let mut p = (tsn, flags, Vec::from(payload.user_data()));
                        mem::swap(&mut p, frags.get_mut(idx).unwrap());
                    }
                    Err(idx) => frags.insert(idx, (tsn, flags, Vec::from(payload.user_data()))),
                }

                // Now reassemble the fragments if they're complete
                if Self::frags_complete(frags) {
                    let mut reassembled = Vec::new();
                    let mut beginning_seen = false;
                    for (_, f, v) in frags {
                        if f.beginning_fragment() {
                            beginning_seen = true;
                        }

                        if beginning_seen {
                            reassembled.append(v);
                        }

                        if f.ending_fragment() {
                            break;
                        }
                    }

                    res = choose_err(res, Out::validate(reassembled.as_slice()));
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

        res
    }

    #[inline]
    fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }
}

*/
