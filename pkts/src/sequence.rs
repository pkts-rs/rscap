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

pub mod ipv4;
pub mod sctp;

use core::marker::PhantomData;

use crate::error::*;
use crate::layers::dev_traits::*;
use crate::layers::traits::*;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

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
