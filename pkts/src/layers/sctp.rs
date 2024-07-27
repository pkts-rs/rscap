// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The Stream Control Transmission Protocol (SCTP) and related data structures.
//!
//!

use core::iter::Iterator;
use core::{cmp, iter, mem, slice};

use crate::layers::dev_traits::*;
use crate::layers::traits::*;
use crate::layers::*;
use crate::utils;

use bitflags::bitflags;

use pkts_macros::{Layer, LayerRef, StatelessLayer};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

// Chunk Types
const CHUNK_TYPE_DATA: u8 = 0;
const CHUNK_TYPE_INIT: u8 = 1;
const CHUNK_TYPE_INIT_ACK: u8 = 2;
const CHUNK_TYPE_SACK: u8 = 3;
const CHUNK_TYPE_HEARTBEAT: u8 = 4;
const CHUNK_TYPE_HEARTBEAT_ACK: u8 = 5;
const CHUNK_TYPE_ABORT: u8 = 6;
const CHUNK_TYPE_SHUTDOWN: u8 = 7;
const CHUNK_TYPE_SHUTDOWN_ACK: u8 = 8;
const CHUNK_TYPE_ERROR: u8 = 9;
const CHUNK_TYPE_COOKIE_ECHO: u8 = 10;
const CHUNK_TYPE_COOKIE_ACK: u8 = 11;
const CHUNK_TYPE_SHUTDOWN_COMPLETE: u8 = 14;

// INIT Chunk Options
const INIT_OPT_IPV4_ADDRESS: u16 = 5;
const INIT_OPT_IPV6_ADDRESS: u16 = 6;
const INIT_OPT_COOKIE_PRESERVATIVE: u16 = 9;
const INIT_OPT_HOSTNAME_ADDR: u16 = 11;
const INIT_OPT_SUPP_ADDR_TYPES: u16 = 12;

// INIT ACK Chunk Options
const INIT_ACK_OPT_STATE_COOKIE: u16 = 7;
const INIT_ACK_OPT_IPV4_ADDRESS: u16 = 5;
const INIT_ACK_OPT_IPV6_ADDRESS: u16 = 6;
const INIT_ACK_OPT_UNRECOGNIZED_PARAM: u16 = 8;
const INIT_ACK_OPT_HOSTNAME_ADDR: u16 = 11;

// ERROR/ABORT Chunk Options
const ERR_CODE_INVALID_STREAM_ID: u16 = 1;
const ERR_CODE_MISSING_MAND_PARAM: u16 = 2;
const ERR_CODE_STALE_COOKIE: u16 = 3;
const ERR_CODE_OUT_OF_RESOURCE: u16 = 4;
const ERR_CODE_UNRESOLVABLE_ADDRESS: u16 = 5;
const ERR_CODE_UNRECOGNIZED_CHUNK: u16 = 6;
const ERR_CODE_INVALID_MAND_PARAM: u16 = 7;
const ERR_CODE_UNRECOGNIZED_PARAMS: u16 = 8;
const ERR_CODE_NO_USER_DATA: u16 = 9;
const ERR_CODE_COOKIE_RCVD_SHUTTING_DOWN: u16 = 10;
const ERR_CODE_RESTART_ASSOC_NEW_ADDR: u16 = 11;
const ERR_CODE_USER_INITIATED_ABORT: u16 = 12;
const ERR_CODE_PROTOCOL_VIOLATION: u16 = 13;

/// An SCTP (Stream Control Transmission Protocol) packet.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |          Source Port          |        Destination Port       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                        Verification Tag                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                            Checksum                           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 Z                             Chunks                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(TcpMetadata)]
#[ref_type(SctpRef)]
pub struct Sctp {
    sport: u16,
    dport: u16,
    verify_tag: u32,
    chksum: Option<u32>,
    control_chunks: Vec<SctpControlChunk>,
    payload_chunks: Vec<Box<dyn LayerObject>>,
}

impl Sctp {
    /// The SCTP port number from which the packet has been sent (i.e. Source Port).
    #[inline]
    pub fn sport(&self) -> u16 {
        self.sport
    }

    /// Sets the SCTP Source Port of the packet to the given value.
    #[inline]
    pub fn set_sport(&mut self, sport: u16) {
        self.sport = sport;
    }

    /// The SCTP port number to which the packet is destined (i.e. Destination Port).
    #[inline]
    pub fn dport(&self) -> u16 {
        self.dport
    }

    /// Sets the SCTP Destination Port of the packet.
    #[inline]
    pub fn set_dport(&mut self, dport: u16) {
        self.dport = dport;
    }

    /// The Verification Tag of the packet.
    ///
    /// The recipient of an SCTP packet uses the Verification Tag to validate the packet's source.
    #[inline]
    pub fn verify_tag(&self) -> u32 {
        self.verify_tag
    }

    /// Sets the Verification Tag of the packet.
    #[inline]
    pub fn set_verify_tag(&mut self, verify_tag: u32) {
        self.verify_tag = verify_tag;
    }

    /// Retrieves the assigned CRC32c checksum for the packet, or `None` if no checksum has
    /// been assigned to the packet.
    ///
    /// By default, the SCTP checksum is automatically calculated when an [`struct@Sctp`] instance
    /// is converted to bytes, unless a checksum is pre-assigned to the instance prior to
    /// conversion. If a checksum has already been assigned to the packet, this method will return
    /// it; otherwise, it will return `None`. This means that an [`struct@Sctp`] instance created
    /// from bytes or from a [`SctpRef`] instance will still have a checksum of `None` by default,
    /// regardless of the checksum value of the underlying bytes it was created from.
    #[inline]
    pub fn chksum(&self) -> Option<u32> {
        self.chksum
    }

    /// Assigns the CRC32c checksum to be used for the packet.
    ///
    /// By default, the SCTP checksum is automatically calculated when an [`struct@Sctp`] instance
    /// is converted to bytes. This method overrides that behavior so that the provided checksum is
    /// used instead. You generally shouldn't need to use this method unless:
    ///   1. You know the expected checksum of the packet in advance and don't want the checksum
    ///      calculation to automatically run again (since it can be a costly operation), or
    ///   2. Checksum offloading is being employed for the SCTP packet and you want to zero out the
    ///      checksum field (again, avoiding unnecessary extra computation), or
    ///   3. You want to explicitly set an invalid checksum.
    #[inline]
    pub fn set_chksum(&mut self, chksum: u32) {
        self.chksum = Some(chksum);
    }

    /// Clears any previously assigned CRC32c checksum for the packet.
    ///
    /// This method guarantees that the SCTP checksum will be automatically calculated for this
    /// [`struct@Sctp`] instance whenever the packet is converted to bytes. You shouldn't need to
    /// call this method unless you've previously explicitly assigned a checksum to the packet--either
    /// through a call to [`Sctp::set_chksum()`] or through a Builder pattern. Packets converted
    /// from bytes into [`struct@Sctp`] instances from bytes or from a [`SctpRef`] instance will
    /// have a checksum of `None` by default.
    #[inline]
    pub fn clear_chksum(&mut self) {
        self.chksum = None;
    }

    /// Recalculates the checksum of the given `Sctp` packet and sets the checksum field accordingly.
    #[inline]
    pub fn generate_chksum(&mut self) {
        todo!() // TODO: should we do this, or automatically calculate the checksum when we generate the packet bytes? It's more efficient that way...
    }

    /// The list of Control Chunks contained within the packet.
    ///
    /// These chunks can be arranged in any order. Control chunks are evaluated by the peer in the
    /// same order that they are sent. All control chunks are ordered before payload chunks. Some
    /// control chunks have restrictions on what other chunks they can be bundled in the same message with:
    ///
    /// - [`SctpControlChunk::Shutdown`] and [`SctpControlChunk::ShutdownAck`] must not be bundled with any [`struct@SctpDataChunk`].
    /// This is because the Shutdown is evaulated first, and data cannot be sent after a Shutdown message.
    ///
    /// - [`SctpControlChunk::Init`], [`SctpControlChunk::InitAck`], and [`SctpControlChunk::ShutdownComplete`] must not be bundled
    /// with any other control or payload chunks.
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn control_chunks(&self) -> &Vec<SctpControlChunk> {
        &self.control_chunks
    }

    /// The mutable list of Control Chunks contained within the packet.
    ///
    /// These chunks can be arranged in any order. Control chunks are evaluated by the peer in the
    /// same order that they are sent. All control chunks are ordered before payload chunks. Some
    /// control chunks have restrictions on what other chunks they can be bundled in the same message with:
    ///
    /// - [`SctpControlChunk::Shutdown`] and [`SctpControlChunk::ShutdownAck`] must not be bundled with any [`struct@SctpDataChunk`].
    /// This is because the Shutdown is evaulated first, and data cannot be sent after a Shutdown message.
    ///
    /// - [`SctpControlChunk::Init`], [`SctpControlChunk::InitAck`], and [`SctpControlChunk::ShutdownComplete`] must not be bundled
    /// with any other control or payload chunks.
    ///
    /// Although the `rscap` library enforces these constraints where it can, this particular API may be used in such a way that
    /// they are violated. It is the responsibility of the caller of this method to ensure that the above constraints are upheld.
    #[inline]
    pub fn control_chunks_mut(&mut self) -> &mut Vec<SctpControlChunk> {
        &mut self.control_chunks
    }

    /*
    /// The list of Payload Data (DATA) Chunks contained within the packet.
    ///
    /// These chunks are ordered by increasing TSN value, and are always placed after any control chunks in the packet.
    /// A packet MUST NOT have any Payload Data Chunks when any of the below Control Chunks are present:
    ///
    /// - [`SctpControlChunk::Shutdown`]
    /// - [`SctpControlChunk::ShutdownAck`]
    /// - [`SctpControlChunk::Init`]
    /// - [`SctpControlChunk::InitAck`]
    /// - [`SctpControlChunk::ShutdownComplete`]
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn payload_chunks(&self) -> &Vec<SctpDataChunk> {
        &self.payload_chunks
    }

    /// The list of Payload Data (DATA) Chunks contained within the packet.
    ///
    /// Payload DATA chunks are ordered by increasing TSN value, and are always placed after any Control Chunks in the packet.
    /// A packet MUST NOT have any Payload Data Chunks when any of the below Control Chunks are present:
    ///
    /// - [`SctpControlChunk::Shutdown`]
    /// - [`SctpControlChunk::ShutdownAck`]
    /// - [`SctpControlChunk::Init`]
    /// - [`SctpControlChunk::InitAck`]
    /// - [`SctpControlChunk::ShutdownComplete`]
    ///
    /// Although the `rscap` library enforces these constraints where it can, this particular API may be used in such a way that
    /// they are violated. It is the responsibility of the caller of this method to ensure that the above constraints are upheld.
    #[inline]
    pub fn payload_chunks_mut(&mut self) -> &mut Vec<SctpDataChunk> {
        &mut self.payload_chunks
    }
    */
}

#[doc(hidden)]
impl FromBytesCurrent for Sctp {
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let sctp = SctpRef::from_bytes_unchecked(bytes);

        let mut control_chunks = Vec::new();
        let control_iter = sctp.control_chunks();
        for chunk in control_iter {
            control_chunks.push(chunk.into());
        }

        let mut payload_chunks = Vec::new();
        let payload_iter = sctp.payload_chunks();
        for chunk in payload_iter {
            payload_chunks.push(chunk.to_boxed_layer());
        }

        Sctp {
            sport: sctp.sport(),
            dport: sctp.dport(),
            verify_tag: sctp.verify_tag(),
            chksum: None,
            control_chunks,
            payload_chunks,
        }
    }

    fn payload_from_bytes_unchecked_default(&mut self, _bytes: &[u8]) {}
}

impl LayerLength for Sctp {
    fn len(&self) -> usize {
        8 + self.control_chunks.iter().map(|c| c.len()).sum::<usize>()
            + self.payload_chunks.iter().map(|c| c.len()).sum::<usize>()
    }
}

impl LayerObject for Sctp {
    #[inline]
    fn can_add_payload_default(&self, payload: &dyn LayerObject) -> bool {
        payload.as_any().downcast_ref::<&SctpDataChunk>().is_some()
    }

    #[inline]
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload_chunks.push(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        &self.payload_chunks
    }

    #[inline]
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        &mut self.payload_chunks
    }

    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>> {
        if index < self.payload_chunks.len() {
            Some(self.payload_chunks.remove(index))
        } else {
            None
        }
    }
}

impl ToBytes for Sctp {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        let start = bytes.len();
        bytes.extend(self.sport.to_be_bytes());
        bytes.extend(self.dport.to_be_bytes());
        bytes.extend(self.verify_tag.to_be_bytes());
        bytes.extend(self.chksum.unwrap_or(0).to_be_bytes());
        for chunk in &self.control_chunks {
            chunk.to_bytes_extended(bytes)?;
        }

        for chunk in &self.payload_chunks {
            chunk.to_bytes_checksummed(bytes, Some((Self::layer_id(), start)))?;
        }

        // TODO: set checksum here

        Ok(())
    }
}

/// An SCTP (Stream Control Transmission Protocol) packet.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |          Source Port          |        Destination Port       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                        Verification Tag                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                            Checksum                           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 Z                             Chunks                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(Sctp)]
#[metadata_type(SctpMetadata)]
pub struct SctpRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> SctpRef<'a> {
    /// The SCTP port number from which the packet has been sent (i.e. Source Port).
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    /// The SCTP port number to which the packet is destined (i.e. Destination Port).
    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    /// The Verification Tag assigned to the packet.
    ///
    /// The recipient of an SCTP packet uses the Verification Tag to validate the packet's source.
    #[inline]
    pub fn verify_tag(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    /// The CRC32c Checksum of the SCTP packet.
    #[inline]
    pub fn chksum(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    /// An iterator over the list of Control Chunks contained within the packet.
    ///
    /// These chunks can be arranged in any order. Control chunks are evaluated by the peer in the
    /// same order that they are sent. All control chunks are ordered before payload chunks. Some
    /// control chunks have restrictions on what other chunks they can be bundled in the same message with:
    ///
    /// - [`SctpControlChunk::Shutdown`] and [`SctpControlChunk::ShutdownAck`] must not be bundled with any [`struct@SctpDataChunk`].
    /// This is because the Shutdown is evaulated first, and data cannot be sent after a Shutdown message.
    ///
    /// - [`SctpControlChunk::Init`], [`SctpControlChunk::InitAck`], and [`SctpControlChunk::ShutdownComplete`] must not be bundled
    /// with any other control or payload chunks.
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn control_chunks(&self) -> ControlChunksIterRef<'a> {
        ControlChunksIterRef {
            chunk_iter: self.chunks(),
        }
    }

    /// The list of Payload Data (DATA) Chunks contained within the packet.
    ///
    /// These chunks are ordered by increasing TSN value, and are always placed after any control chunks in the packet.
    /// A packet MUST NOT have any Payload Data Chunks when any of the below Control Chunks are present:
    ///
    /// - [`SctpControlChunk::Shutdown`]
    /// - [`SctpControlChunk::ShutdownAck`]
    /// - [`SctpControlChunk::Init`]
    /// - [`SctpControlChunk::InitAck`]
    /// - [`SctpControlChunk::ShutdownComplete`]
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn payload_chunks(&self) -> DataChunksIterRef<'a> {
        DataChunksIterRef {
            chunk_iter: self.chunks(),
        }
    }

    /// The list of Control or Payload Chunks contained within the packet.
    ///
    /// These chunks should be ordered such that Control Chunks are all before Payload Chunks.
    /// However, if this `SctpRef` was created with `from_bytes_unchecked`, it is possible that
    /// these chunks may not be ordered correctly.
    #[inline]
    pub fn chunks(&self) -> ChunksIterRef<'a> {
        ChunksIterRef {
            bytes: &self.data[12..],
        }
    }
}

impl<'a> FromBytesRef<'a> for SctpRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        SctpRef { data: bytes }
    }
}

#[doc(hidden)]
impl LayerOffset for SctpRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        None // SCTP makes no indiciation of what protocol is used for its payloads
             // If we did need to provide an index, we'll want to provide an end index too...
    }
}

impl Validate for SctpRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let mut remaining = match curr_layer.get(12..) {
            Some(rem) => rem,
            None => {
                return Err(ValidationError {
                    layer: Sctp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason: "insufficient bytes in SCTP packet for Common Header",
                })
            }
        };

        let mut data_reached = false;
        let mut single_chunk = false;
        let mut shutdown = false;
        let mut chunk_cnt = 0;

        while let Some(&chunk_type) = remaining.first() {
            chunk_cnt += 1;
            let chunk_validation = match chunk_type {
                CHUNK_TYPE_DATA => {
                    data_reached = true;
                    SctpDataChunk::validate(remaining)
                }
                _ if data_reached => {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "SCTP Control Chunk not allowed after DATA Chunk in Chunks field",
                    })
                }
                CHUNK_TYPE_INIT => {
                    single_chunk = true;
                    InitChunk::validate(remaining)
                }
                CHUNK_TYPE_INIT_ACK => {
                    single_chunk = true;
                    InitAckChunk::validate(remaining)
                }
                CHUNK_TYPE_SACK => SackChunk::validate(remaining),
                CHUNK_TYPE_HEARTBEAT => HeartbeatChunk::validate(remaining),
                CHUNK_TYPE_HEARTBEAT_ACK => HeartbeatAckChunk::validate(remaining),
                CHUNK_TYPE_ABORT => AbortChunk::validate(remaining),
                CHUNK_TYPE_SHUTDOWN => {
                    shutdown = true;
                    ShutdownChunk::validate(remaining)
                }
                CHUNK_TYPE_SHUTDOWN_ACK => {
                    shutdown = true;
                    ShutdownAckChunk::validate(remaining)
                }
                CHUNK_TYPE_ERROR => ErrorChunk::validate(remaining),
                CHUNK_TYPE_COOKIE_ECHO => CookieEchoChunk::validate(remaining),
                CHUNK_TYPE_COOKIE_ACK => CookieAckChunk::validate(remaining),
                CHUNK_TYPE_SHUTDOWN_COMPLETE => {
                    single_chunk = true;
                    ShutdownCompleteChunk::validate(remaining)
                }
                _ => UnknownChunk::validate(remaining),
            };

            match chunk_validation {
                Err(e) => {
                    if let ValidationErrorClass::ExcessBytes(l) = e.class {
                        remaining = &remaining[remaining.len() - l..];
                    } else {
                        return Err(e);
                    }
                }
                Ok(()) => return Ok(()),
            }
        }

        if single_chunk && chunk_cnt > 1 {
            return Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "multiple chunks bundled in one SCTP message where only one was allowed (chunk types INIT, INIT_ACK and SHUTDOWN_COMPLETE cannot be bundled with other chunks)",
            });
        }

        if shutdown && data_reached {
            return Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason:
                    "SCTP SHUTDOWN/SHUTDOWN_ACK Chunk cannot be bundled with DATA (Payload) Chunks",
            });
        }

        Ok(()) // No optional data was found
    }

    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // Payload is always assumed to be Raw
    }
}

/// An iterator over the Control chunks of an SCTP packet.
#[derive(Clone, Copy, Debug)]
pub struct ControlChunksIterRef<'a> {
    chunk_iter: ChunksIterRef<'a>,
}

impl<'a> Iterator for ControlChunksIterRef<'a> {
    type Item = SctpControlChunkRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        for chunk in self.chunk_iter.by_ref() {
            if let ChunkRef::Control(c) = chunk {
                return Some(c);
            }
        }
        None
    }
}

/// An iterator over the Payload chunks (i.e. the DATA chunks) of an SCTP packet.
#[derive(Clone, Copy, Debug)]
pub struct DataChunksIterRef<'a> {
    chunk_iter: ChunksIterRef<'a>,
}

impl<'a> Iterator for DataChunksIterRef<'a> {
    type Item = SctpDataChunkRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        for chunk in self.chunk_iter.by_ref() {
            if let ChunkRef::Payload(c) = chunk {
                return Some(c);
            }
        }
        None
    }
}

/// An SCTP chunk (may be a Control chunk or a Payload chunk).
#[derive(Clone, Copy, Debug)]
pub enum ChunkRef<'a> {
    Control(SctpControlChunkRef<'a>),
    Payload(SctpDataChunkRef<'a>),
}

/// An iterator over all the chunks of an SCTP packet.
#[derive(Clone, Copy, Debug)]
pub struct ChunksIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for ChunksIterRef<'a> {
    type Item = ChunkRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (chunk_type, unpadded_len) =
            match (self.bytes.first(), utils::get_array::<2>(self.bytes, 2)) {
                (Some(&t), Some(&l)) => (t, u16::from_be_bytes(l)),
                _ => return None,
            };

        let len = utils::padded_length::<4>(unpadded_len as usize);
        match (self.bytes.get(..len), self.bytes.get(len..)) {
            (Some(chunk_bytes), Some(rem)) => {
                self.bytes = rem;
                if chunk_type == CHUNK_TYPE_DATA {
                    Some(ChunkRef::Payload(SctpDataChunkRef::from_bytes_unchecked(
                        chunk_bytes,
                    )))
                } else {
                    Some(ChunkRef::Control(
                        SctpControlChunkRef::from_bytes_unchecked(chunk_bytes),
                    ))
                }
            }
            _ => {
                panic!("insufficient bytes for ChunkRef in iterator.");
            }
        }
    }
}

// =============================================================================
//                             Non-Layer Components
// =============================================================================

/// An SCTP Control chunk.
#[derive(Clone, Debug)]
pub enum SctpControlChunk {
    Init(InitChunk),
    InitAck(InitAckChunk),
    Sack(SackChunk),
    Heartbeat(HeartbeatChunk),
    HeartbeatAck(HeartbeatAckChunk),
    Abort(AbortChunk),
    Shutdown(ShutdownChunk),
    ShutdownAck(ShutdownAckChunk),
    Error(ErrorChunk),
    CookieEcho(CookieEchoChunk),
    CookieAck(CookieAckChunk),
    ShutdownComplete(ShutdownCompleteChunk),
    Unknown(UnknownChunk),
}

impl SctpControlChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(SctpControlChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        SctpControlChunkRef::validate(bytes)
    }

    pub fn chunk_type(&self) -> u8 {
        match self {
            SctpControlChunk::Init(c) => c.chunk_type(),
            SctpControlChunk::InitAck(c) => c.chunk_type(),
            SctpControlChunk::Sack(c) => c.chunk_type(),
            SctpControlChunk::Heartbeat(c) => c.chunk_type(),
            SctpControlChunk::HeartbeatAck(c) => c.chunk_type(),
            SctpControlChunk::Abort(c) => c.chunk_type(),
            SctpControlChunk::Shutdown(c) => c.chunk_type(),
            SctpControlChunk::ShutdownAck(c) => c.chunk_type(),
            SctpControlChunk::Error(c) => c.chunk_type(),
            SctpControlChunk::CookieEcho(c) => c.chunk_type(),
            SctpControlChunk::CookieAck(c) => c.chunk_type(),
            SctpControlChunk::ShutdownComplete(c) => c.chunk_type(),
            SctpControlChunk::Unknown(c) => c.chunk_type(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            SctpControlChunk::Init(c) => c.len(),
            SctpControlChunk::InitAck(c) => c.len(),
            SctpControlChunk::Sack(c) => c.len(),
            SctpControlChunk::Heartbeat(c) => c.len(),
            SctpControlChunk::HeartbeatAck(c) => c.len(),
            SctpControlChunk::Abort(c) => c.len(),
            SctpControlChunk::Shutdown(c) => c.len(),
            SctpControlChunk::ShutdownAck(c) => c.len(),
            SctpControlChunk::Error(c) => c.len(),
            SctpControlChunk::CookieEcho(c) => c.len(),
            SctpControlChunk::CookieAck(c) => c.len(),
            SctpControlChunk::ShutdownComplete(c) => c.len(),
            SctpControlChunk::Unknown(c) => c.len(),
        }
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        match self {
            SctpControlChunk::Init(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::InitAck(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::Sack(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::Heartbeat(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::HeartbeatAck(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::Abort(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::Shutdown(c) => c.to_bytes_extended(bytes),
            SctpControlChunk::ShutdownAck(c) => c.to_bytes_extended(bytes),
            SctpControlChunk::Error(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::CookieEcho(c) => c.to_bytes_extended(bytes)?,
            SctpControlChunk::CookieAck(c) => c.to_bytes_extended(bytes),
            SctpControlChunk::ShutdownComplete(c) => c.to_bytes_extended(bytes),
            SctpControlChunk::Unknown(c) => c.to_bytes_extended(bytes)?,
        }

        Ok(())
    }
}

impl From<SctpControlChunkRef<'_>> for SctpControlChunk {
    #[inline]
    fn from(value: SctpControlChunkRef<'_>) -> Self {
        SctpControlChunk::from(&value)
    }
}

impl From<&SctpControlChunkRef<'_>> for SctpControlChunk {
    fn from(value: &SctpControlChunkRef<'_>) -> Self {
        match value {
            SctpControlChunkRef::Init(c) => SctpControlChunk::Init(c.into()),
            SctpControlChunkRef::InitAck(c) => SctpControlChunk::InitAck(c.into()),
            SctpControlChunkRef::Sack(c) => SctpControlChunk::Sack(c.into()),
            SctpControlChunkRef::Heartbeat(c) => SctpControlChunk::Heartbeat(c.into()),
            SctpControlChunkRef::HeartbeatAck(c) => SctpControlChunk::HeartbeatAck(c.into()),
            SctpControlChunkRef::Abort(c) => SctpControlChunk::Abort(c.into()),
            SctpControlChunkRef::Shutdown(c) => SctpControlChunk::Shutdown(c.into()),
            SctpControlChunkRef::ShutdownAck(c) => SctpControlChunk::ShutdownAck(c.into()),
            SctpControlChunkRef::Error(c) => SctpControlChunk::Error(c.into()),
            SctpControlChunkRef::CookieEcho(c) => SctpControlChunk::CookieEcho(c.into()),
            SctpControlChunkRef::CookieAck(c) => SctpControlChunk::CookieAck(c.into()),
            SctpControlChunkRef::ShutdownComplete(c) => {
                SctpControlChunk::ShutdownComplete(c.into())
            }
            SctpControlChunkRef::Unknown(c) => SctpControlChunk::Unknown(c.into()),
        }
    }
}

/// An SCTP Control chunk reference.
#[derive(Clone, Copy, Debug)]
pub enum SctpControlChunkRef<'a> {
    Init(InitChunkRef<'a>),
    InitAck(InitAckChunkRef<'a>),
    Sack(SackChunkRef<'a>),
    Heartbeat(HeartbeatChunkRef<'a>),
    HeartbeatAck(HeartbeatAckChunkRef<'a>),
    Abort(AbortChunkRef<'a>),
    Shutdown(ShutdownChunkRef<'a>),
    ShutdownAck(ShutdownAckChunkRef<'a>),
    Error(ErrorChunkRef<'a>),
    CookieEcho(CookieEchoChunkRef<'a>),
    CookieAck(CookieAckChunkRef<'a>),
    ShutdownComplete(ShutdownCompleteChunkRef<'a>),
    Unknown(UnknownChunkRef<'a>),
}

impl<'a> SctpControlChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        let chunk_type = bytes[0];
        match chunk_type {
            CHUNK_TYPE_INIT => Self::Init(InitChunkRef { data: bytes }),
            CHUNK_TYPE_INIT_ACK => Self::InitAck(InitAckChunkRef { data: bytes }),
            CHUNK_TYPE_SACK => Self::Sack(SackChunkRef { data: bytes }),
            CHUNK_TYPE_HEARTBEAT => Self::Heartbeat(HeartbeatChunkRef { data: bytes }),
            CHUNK_TYPE_HEARTBEAT_ACK => Self::HeartbeatAck(HeartbeatAckChunkRef { data: bytes }),
            CHUNK_TYPE_ABORT => Self::Abort(AbortChunkRef { data: bytes }),
            CHUNK_TYPE_SHUTDOWN => Self::Shutdown(ShutdownChunkRef { data: bytes }),
            CHUNK_TYPE_SHUTDOWN_ACK => Self::ShutdownAck(ShutdownAckChunkRef { data: bytes }),
            CHUNK_TYPE_ERROR => Self::Error(ErrorChunkRef { data: bytes }),
            CHUNK_TYPE_COOKIE_ECHO => Self::CookieEcho(CookieEchoChunkRef { data: bytes }),
            CHUNK_TYPE_COOKIE_ACK => Self::CookieAck(CookieAckChunkRef { data: bytes }),
            CHUNK_TYPE_SHUTDOWN_COMPLETE => {
                Self::ShutdownComplete(ShutdownCompleteChunkRef { data: bytes })
            }
            _ => Self::Unknown(UnknownChunkRef { data: bytes }),
        }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let chunk_type = bytes[0];
        match chunk_type {
            CHUNK_TYPE_INIT => InitChunkRef::validate(bytes),
            CHUNK_TYPE_INIT_ACK => InitAckChunkRef::validate(bytes),
            CHUNK_TYPE_SACK => SackChunkRef::validate(bytes),
            CHUNK_TYPE_HEARTBEAT => HeartbeatChunkRef::validate(bytes),
            CHUNK_TYPE_HEARTBEAT_ACK => HeartbeatAckChunkRef::validate(bytes),
            CHUNK_TYPE_ABORT => AbortChunkRef::validate(bytes),
            CHUNK_TYPE_SHUTDOWN => ShutdownChunkRef::validate(bytes),
            CHUNK_TYPE_SHUTDOWN_ACK => ShutdownAckChunkRef::validate(bytes),
            CHUNK_TYPE_ERROR => ErrorChunkRef::validate(bytes),
            CHUNK_TYPE_COOKIE_ECHO => CookieEchoChunkRef::validate(bytes),
            CHUNK_TYPE_COOKIE_ACK => CookieAckChunkRef::validate(bytes),
            CHUNK_TYPE_SHUTDOWN_COMPLETE => ShutdownCompleteChunkRef::validate(bytes),
            _ => UnknownChunkRef::validate(bytes),
        }
    }
}

/// An SCTP INIT chunk.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |    Type (1)   |  Chunk Flags  |             Length            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                            Init Tag                           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |           Advertised Receiver Window Credit (a_rwnd)          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |        Outbound Streams       |        Inbound Streams        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |           Initial Transmission Sequence Number (TSN)          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 Z             Optional or Variable-Length Parameters            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug)]
pub struct InitChunk {
    flags: u8,
    init_tag: u32,
    a_rwnd: u32,
    ostreams: u16,
    istreams: u16,
    init_tsn: u32,
    options: Vec<InitOption>,
}

impl InitChunk {
    /// Converts the given bytes into an [`InitChunk`] instance, returning an error if the bytes are
    /// not well-formed.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts the given bytes into an [`InitChunk`] instance without validating the bytes.
    ///
    /// # Panics
    ///
    /// The following method may panic if the bytes being passed in do not represent a well-formed
    /// INIT chunk (i.e. if a call to [`InitChunk::validate()`] would return an error).
    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(InitChunkRef::from_bytes_unchecked(bytes))
    }

    /// Validates the given bytes against the expected structure and syntactic values of an
    /// INIT chunk. If the bytes represent a well-formed INIT chunk, this method will return
    /// `Ok()`; otherwise, it will return a [`ValidationError`] indicating what part of the
    /// chunk was invalid.
    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        InitChunkRef::validate(bytes)
    }

    /// The Type field of the INIT chunk.
    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_INIT
    }

    /// The flags of the INIT chunk (in bytes).
    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    /// Sets the flags of the INIT chunk.
    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    /// The length (without padding) of the INIT chunk.
    #[inline]
    pub fn unpadded_len(&self) -> usize {
        20 + self.options.iter().map(|o| o.len()).sum::<usize>()
    }

    /// The length (including padding) of the INIT chunk.
    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    /// The Initiate Tag of the chunk.
    ///
    /// The Initiate Tag is stored by the recipient of the INIT tag and is subsequently transmitted
    /// as the Verification Tag of every SCTP packet for the duration of the association.
    #[inline]
    pub fn init_tag(&self) -> u32 {
        self.init_tag
    }

    /// Sets the Initiate Tag of the chunk.
    #[inline]
    pub fn set_init_tag(&mut self, init_tag: u32) {
        self.init_tag = init_tag;
    }

    /// The Advertised Receiver Window Credit (a_rwnd).
    ///
    /// This field represents the number of bytes the sender has reserved as a window for messages
    /// received in this association.
    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        self.a_rwnd
    }

    /// Sets the Advertised Receiver Window Credit (a_rwnd).
    #[inline]
    pub fn set_a_rwnd(&mut self, a_rwnd: u32) {
        self.a_rwnd = a_rwnd;
    }

    /// The number of Outbound Streams the sender of the INIT chunk wishes to create for the
    /// association.
    #[inline]
    pub fn ostreams(&self) -> u16 {
        self.ostreams
    }

    /// Sets the number of Outbound Streams advertised by the INIT chunk.
    #[inline]
    pub fn set_ostreams(&mut self, ostreams: u16) {
        self.ostreams = ostreams;
    }

    /// The number of Inbound Streams the sender of the INIT chunk will allow its peer to create for
    /// the association.
    #[inline]
    pub fn istreams(&self) -> u16 {
        self.istreams
    }

    /// Sets the number of Inbound Streams advertised by the INIT chunk.
    #[inline]
    pub fn set_istreams(&mut self, istreams: u16) {
        self.istreams = istreams;
    }

    /// The Initial Transmission Sequence Number (TSN).
    ///
    /// Indicates the TSN that the sender of the INIT chunk will begin its association with.
    #[inline]
    pub fn init_tsn(&self) -> u32 {
        self.init_tsn
    }

    /// Sets the Initial Transmission Sequence Number (TSN) of the INIT chunk.
    #[inline]
    pub fn set_init_tsn(&mut self, init_tsn: u32) {
        self.init_tsn = init_tsn;
    }

    /// The optional or variable-length parameters of the INIT chunk.
    #[inline]
    pub fn options(&self) -> &Vec<InitOption> {
        &self.options
    }

    /// A mutable reference to the optional or variable-length parameters of the INIT chunk.
    #[inline]
    pub fn options_mut(&mut self) -> &mut Vec<InitOption> {
        &mut self.options
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_INIT);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(self.init_tag.to_be_bytes());
        bytes.extend(self.a_rwnd.to_be_bytes());
        bytes.extend(self.ostreams.to_be_bytes());
        bytes.extend(self.istreams.to_be_bytes());
        bytes.extend(self.init_tsn.to_be_bytes());
        for option in &self.options {
            option.to_bytes_extended(bytes)?;
        }
        // No padding needed--options are guaranteed to be padded to 4 bytes.

        Ok(())
    }
}

impl From<InitChunkRef<'_>> for InitChunk {
    #[inline]
    fn from(value: InitChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitChunkRef<'_>> for InitChunk {
    fn from(value: &InitChunkRef<'_>) -> Self {
        let mut options = Vec::new();
        let iter = value.options_iter();
        for option in iter {
            options.push(option.into());
        }

        InitChunk {
            flags: value.flags_raw(),
            init_tag: value.init_tag(),
            a_rwnd: value.a_rwnd(),
            ostreams: value.ostreams(),
            istreams: value.istreams(),
            init_tsn: value.init_tsn(),
            options,
        }
    }
}

/// An SCTP INIT chunk reference.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |    Type (1)   |  Chunk Flags  |             Length            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                            Init Tag                           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |           Advertised Receiver Window Credit (a_rwnd)          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |        Outbound Streams       |        Inbound Streams        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |           Initial Transmission Sequence Number (TSN)          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 Z             Optional or Variable-Length Parameters            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug)]
pub struct InitChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> InitChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        InitChunkRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if bytes.len() < cmp::max(len, 20) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP INIT chunk for header and optional parameters",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "SCTP INIT chunk length was not a multiple of 4",
                    });
                }

                if len < 20 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "length field of SCTP INIT chunk was too short to cover entire header",
                    });
                }

                let mut options = &bytes[20..];
                while !options.is_empty() {
                    match InitOption::validate(options) {
                        Err(e) => {
                            if let ValidationErrorClass::ExcessBytes(extra) = e.class {
                                options = &options[options.len() - extra..];
                            } else {
                                return Err(ValidationError {
                                    layer: Sctp::name(),
                                    class: ValidationErrorClass::InvalidValue,
                                    #[cfg(feature = "error_string")]
                                    reason: e.reason,
                                });
                            }
                        }
                        _ => break,
                    }
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP INIT chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP INIT chunk for header Length field",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn init_tag(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    #[inline]
    pub fn ostreams(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    #[inline]
    pub fn istreams(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 14).unwrap())
    }

    #[inline]
    pub fn init_tsn(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 16).unwrap())
    }

    #[inline]
    pub fn options_iter(&self) -> InitOptionsIterRef<'a> {
        InitOptionsIterRef { bytes: self.data }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InitOptionsIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for InitOptionsIterRef<'a> {
    type Item = InitOptionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (opt_type, unpadded_len) = match (
            utils::get_array(self.bytes, 0).map(|&a| u16::from_be_bytes(a)),
            utils::get_array(self.bytes, 2).map(|&a| u16::from_be_bytes(a)),
        ) {
            (Some(t), Some(l)) => (t, l),
            _ => return None,
        };

        let min_len = match opt_type {
            INIT_OPT_IPV4_ADDRESS | INIT_OPT_COOKIE_PRESERVATIVE => 8,
            INIT_OPT_IPV6_ADDRESS => 20,
            INIT_OPT_HOSTNAME_ADDR | INIT_OPT_SUPP_ADDR_TYPES => 4,
            _ => 4,
        };

        if self.bytes.len() < min_len {
            self.bytes = &[]; // Not needed, but this helps further calls to the iterator to short-circuit
            return None;
        }

        let len = cmp::max(min_len, utils::padded_length::<4>(unpadded_len as usize));
        match (self.bytes.get(..len), self.bytes.get(len..)) {
            (Some(opt_bytes), Some(rem)) => {
                self.bytes = rem;
                Some(InitOptionRef::from_bytes_unchecked(opt_bytes))
            }
            _ => {
                // Just take whatever remaining bytes we can for the payload
                let opt_bytes = self.bytes;
                self.bytes = &[];
                Some(InitOptionRef::from_bytes_unchecked(opt_bytes))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum InitOption {
    Ipv4Address(u32),
    Ipv6Address(u128),
    CookiePreservative(u32),
    HostnameAddress(Vec<u8>),
    SupportedAddressTypes(Vec<u16>),
    Unknown(u16, Vec<u8>),
}

impl InitOption {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(InitOptionRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        InitOptionRef::validate(bytes)
    }

    #[inline]
    pub fn new_ipv4_address(addr: u32) -> Self {
        Self::Ipv4Address(addr)
    }

    #[inline]
    pub fn new_ipv6_address(addr: u128) -> Self {
        Self::Ipv6Address(addr)
    }

    #[inline]
    pub fn new_cookie_preservative(cookie_lifespan: u32) -> Self {
        Self::CookiePreservative(cookie_lifespan)
    }

    pub fn option_type(&self) -> u16 {
        match self {
            Self::Ipv4Address(_) => INIT_OPT_IPV4_ADDRESS,
            Self::Ipv6Address(_) => INIT_OPT_IPV6_ADDRESS,
            Self::CookiePreservative(_) => INIT_OPT_COOKIE_PRESERVATIVE,
            Self::HostnameAddress(_) => INIT_OPT_HOSTNAME_ADDR,
            Self::SupportedAddressTypes(_) => INIT_OPT_SUPP_ADDR_TYPES,
            Self::Unknown(t, _) => *t,
        }
    }

    pub fn unpadded_len(&self) -> usize {
        match self {
            Self::Ipv4Address(_) => 8,
            Self::Ipv6Address(_) => 20,
            Self::CookiePreservative(_) => 8,
            Self::HostnameAddress(h) => 4 + h.len(),
            Self::SupportedAddressTypes(addr_types) => 4 + (2 * addr_types.len()),
            Self::Unknown(_, d) => 4 + d.len(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        match self {
            Self::Ipv4Address(ipv4) => {
                bytes.extend(INIT_OPT_IPV4_ADDRESS.to_be_bytes());
                bytes.extend(8u16.to_be_bytes());
                bytes.extend(ipv4.to_be_bytes());
            }
            Self::Ipv6Address(ipv6) => {
                bytes.extend(INIT_OPT_IPV6_ADDRESS.to_be_bytes());
                bytes.extend(20u16.to_be_bytes());
                bytes.extend(ipv6.to_be_bytes());
            }
            Self::CookiePreservative(cookie_lifespan) => {
                bytes.extend(INIT_OPT_COOKIE_PRESERVATIVE.to_be_bytes());
                bytes.extend(8u16.to_be_bytes());
                bytes.extend(cookie_lifespan.to_be_bytes());
            }
            Self::HostnameAddress(addr) => {
                let unpadded_len = u16::try_from(self.unpadded_len())
                    .map_err(|_| SerializationError::length_encoding(Sctp::name()))?;
                bytes.extend(INIT_OPT_HOSTNAME_ADDR.to_be_bytes());
                bytes.extend(unpadded_len.to_be_bytes());
                bytes.extend(addr);
                bytes.extend(iter::repeat(0).take(
                    utils::padded_length::<4>(unpadded_len as usize) - unpadded_len as usize,
                ));
            }
            Self::SupportedAddressTypes(addr_types) => {
                let unpadded_len = u16::try_from(self.unpadded_len())
                    .map_err(|_| SerializationError::length_encoding(Sctp::name()))?;
                bytes.extend(INIT_OPT_SUPP_ADDR_TYPES.to_be_bytes());
                bytes.extend(unpadded_len.to_be_bytes());
                for addr_type in addr_types {
                    bytes.extend(addr_type.to_be_bytes());
                }
                bytes.extend(iter::repeat(0).take(
                    utils::padded_length::<4>(unpadded_len as usize) - unpadded_len as usize,
                ));
            }
            Self::Unknown(opt_type, data) => {
                let unpadded_len = u16::try_from(self.unpadded_len())
                    .map_err(|_| SerializationError::length_encoding(Sctp::name()))?;
                bytes.extend(opt_type.to_be_bytes());
                bytes.extend(unpadded_len.to_be_bytes());
                bytes.extend(data);
                bytes.extend(iter::repeat(0).take(
                    utils::padded_length::<4>(unpadded_len as usize) - unpadded_len as usize,
                ));
            }
        }
        Ok(())
    }
}

impl From<InitOptionRef<'_>> for InitOption {
    #[inline]
    fn from(value: InitOptionRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitOptionRef<'_>> for InitOption {
    fn from(value: &InitOptionRef<'_>) -> Self {
        match value.payload() {
            InitOptionPayloadRef::Ipv4Address(ipv4) => InitOption::Ipv4Address(ipv4),
            InitOptionPayloadRef::Ipv6Address(ipv6) => InitOption::Ipv6Address(ipv6),
            InitOptionPayloadRef::CookiePreservative(cookie) => {
                InitOption::CookiePreservative(cookie)
            }
            InitOptionPayloadRef::HostnameAddress(addr) => {
                InitOption::HostnameAddress(Vec::from(addr))
            }
            InitOptionPayloadRef::SupportedAddressTypes(mut addr_bytes) => {
                let mut v = Vec::new();
                while let (Some(&addr_arr), Some(remaining)) =
                    (utils::get_array(addr_bytes, 0), addr_bytes.get(2..))
                {
                    v.push(u16::from_be_bytes(addr_arr));
                    addr_bytes = remaining;
                }
                InitOption::SupportedAddressTypes(v)
            }
            InitOptionPayloadRef::Unknown(opt_type, value) => {
                InitOption::Unknown(opt_type, Vec::from(value))
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InitOptionRef<'a> {
    data: &'a [u8],
}

impl<'a> InitOptionRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        InitOptionRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        let header = (utils::to_array(bytes, 0), utils::to_array(bytes, 2));
        match header {
            (Some(opt_type_arr), Some(unpadded_len_arr)) => {
                let opt_type = u16::from_be_bytes(opt_type_arr);
                let unpadded_len = u16::from_be_bytes(unpadded_len_arr);
                let len = utils::padded_length::<4>(unpadded_len as usize);

                if bytes.len() < len {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason:
                            "insufficient bytes in SCTP INIT option for payload + padding bytes",
                    });
                }

                let expected_unpadded_len = match opt_type {
                    INIT_OPT_IPV4_ADDRESS => Some(8),
                    INIT_OPT_IPV6_ADDRESS => Some(20),
                    INIT_OPT_COOKIE_PRESERVATIVE => Some(8),
                    _ => None,
                };

                if let Some(e_len) = expected_unpadded_len {
                    if unpadded_len != e_len {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]            
                            reason: "SCTP INIT option Length field didn't match expected length based on Option Type",
                        });
                    }
                }

                if opt_type == INIT_OPT_SUPP_ADDR_TYPES && unpadded_len % 2 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "SCTP INIT option payload had missing or trailing byte for Supported Address Types option",
                    });
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP INIT option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP INIT option for header",
            }),
        }
    }

    #[inline]
    pub fn opt_type(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    pub fn payload(&self) -> InitOptionPayloadRef<'a> {
        match self.opt_type() {
            INIT_OPT_IPV4_ADDRESS => InitOptionPayloadRef::Ipv4Address(u32::from_be_bytes(
                utils::to_array(self.data, 4).unwrap(),
            )),
            INIT_OPT_IPV6_ADDRESS => InitOptionPayloadRef::Ipv6Address(u128::from_be_bytes(
                utils::to_array::<16>(self.data, 4).unwrap(),
            )),
            INIT_OPT_COOKIE_PRESERVATIVE => InitOptionPayloadRef::CookiePreservative(
                u32::from_be_bytes(utils::to_array(self.data, 4).unwrap()),
            ),
            INIT_OPT_HOSTNAME_ADDR => InitOptionPayloadRef::HostnameAddress(
                self.data
                    .get(4..4 + self.unpadded_len().checked_sub(4).unwrap() as usize)
                    .unwrap(),
            ),
            INIT_OPT_SUPP_ADDR_TYPES => InitOptionPayloadRef::SupportedAddressTypes(
                self.data
                    .get(4..4 + self.unpadded_len().checked_sub(4).unwrap() as usize)
                    .unwrap(),
            ),
            _ => InitOptionPayloadRef::Unknown(
                self.opt_type(),
                self.data
                    .get(4..4 + self.unpadded_len().checked_sub(4).unwrap() as usize)
                    .unwrap(),
            ),
        }
    }
}

pub enum InitOptionPayloadRef<'a> {
    Ipv4Address(u32),
    Ipv6Address(u128),
    CookiePreservative(u32),
    HostnameAddress(&'a [u8]),
    SupportedAddressTypes(&'a [u8]),
    Unknown(u16, &'a [u8]),
}

#[derive(Clone, Debug)]
pub struct InitAckChunk {
    flags: u8,
    init_tag: u32,
    a_rwnd: u32,
    ostreams: u16,
    istreams: u16,
    init_tsn: u32,
    options: Vec<InitAckOption>,
}

impl InitAckChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(InitAckChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        InitAckChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_INIT_ACK
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        20 + self.options.iter().map(|o| o.len()).sum::<usize>()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn init_tag(&self) -> u32 {
        self.init_tag
    }

    #[inline]
    pub fn set_init_tag(&mut self, init_tag: u32) {
        self.init_tag = init_tag;
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        self.a_rwnd
    }

    #[inline]
    pub fn set_a_rwnd(&mut self, a_rwnd: u32) {
        self.a_rwnd = a_rwnd;
    }

    #[inline]
    pub fn ostreams(&self) -> u16 {
        self.ostreams
    }

    #[inline]
    pub fn set_ostreams(&mut self, ostreams: u16) {
        self.ostreams = ostreams;
    }

    #[inline]
    pub fn istreams(&self) -> u16 {
        self.istreams
    }

    #[inline]
    pub fn set_istreams(&mut self, istreams: u16) {
        self.istreams = istreams;
    }

    #[inline]
    pub fn init_tsn(&self) -> u32 {
        self.init_tsn
    }

    #[inline]
    pub fn set_init_tsn(&mut self, init_tsn: u32) {
        self.init_tsn = init_tsn;
    }

    #[inline]
    pub fn options(&self) -> &Vec<InitAckOption> {
        &self.options
    }

    #[inline]
    pub fn options_mut(&mut self) -> &mut Vec<InitAckOption> {
        &mut self.options
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_INIT_ACK);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(self.init_tag.to_be_bytes());
        bytes.extend(self.a_rwnd.to_be_bytes());
        bytes.extend(self.ostreams.to_be_bytes());
        bytes.extend(self.istreams.to_be_bytes());
        bytes.extend(self.init_tsn.to_be_bytes());
        for option in &self.options {
            option.to_bytes_extended(bytes)?;
        }

        Ok(())
    }
}

impl From<InitAckChunkRef<'_>> for InitAckChunk {
    #[inline]
    fn from(value: InitAckChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitAckChunkRef<'_>> for InitAckChunk {
    fn from(value: &InitAckChunkRef<'_>) -> Self {
        let mut options = Vec::new();
        let iter = value.options_iter();
        for option in iter {
            options.push(option.into());
        }

        InitAckChunk {
            flags: value.flags_raw(),
            init_tag: value.init_tag(),
            a_rwnd: value.a_rwnd(),
            ostreams: value.ostreams(),
            istreams: value.istreams(),
            init_tsn: value.init_tsn(),
            options,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InitAckChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> InitAckChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        InitAckChunkRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if bytes.len() < cmp::max(len, 20) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP INIT ACK chunk for header and optional parameters",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "SCTP INIT ACK chunk length was not a multiple of 4",
                    });
                }

                if len < 20 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "length field of SCTP INIT ACK chunk was too short for header",
                    });
                }

                let mut options = &bytes[20..];
                while !options.is_empty() {
                    match InitAckOption::validate(options) {
                        Err(e) => {
                            if let ValidationErrorClass::ExcessBytes(extra) = e.class {
                                options = &options[options.len() - extra..];
                            } else {
                                return Err(e);
                            }
                        }
                        _ => break,
                    }
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP INIT ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP INIT ACK chunk for header Length field",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn init_tag(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    #[inline]
    pub fn ostreams(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    #[inline]
    pub fn istreams(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 14).unwrap())
    }

    #[inline]
    pub fn init_tsn(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 16).unwrap())
    }

    #[inline]
    pub fn options_iter(&self) -> InitAckOptionsIterRef<'a> {
        InitAckOptionsIterRef {
            bytes: &self.data[20..],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InitAckOptionsIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for InitAckOptionsIterRef<'a> {
    type Item = InitAckOptionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (opt_type, unpadded_len) = match (
            utils::get_array(self.bytes, 0).map(|&a| u16::from_be_bytes(a)),
            utils::get_array(self.bytes, 2).map(|&a| u16::from_be_bytes(a)),
        ) {
            (Some(t), Some(l)) => (t, l),
            _ => return None,
        };

        let min_len = match opt_type {
            INIT_ACK_OPT_IPV4_ADDRESS => 8,
            INIT_ACK_OPT_IPV6_ADDRESS => 20,
            INIT_ACK_OPT_HOSTNAME_ADDR
            | INIT_ACK_OPT_STATE_COOKIE
            | INIT_ACK_OPT_UNRECOGNIZED_PARAM => 4,
            _ => 4,
        };

        if self.bytes.len() < min_len {
            self.bytes = &[]; // Not needed, but this helps further calls to the iterator to short-circuit
            return None;
        }

        let len = cmp::max(min_len, utils::padded_length::<4>(unpadded_len as usize));
        match (self.bytes.get(..len), self.bytes.get(len..)) {
            (Some(opt_bytes), Some(rem)) => {
                self.bytes = rem;
                Some(InitAckOptionRef::from_bytes_unchecked(opt_bytes))
            }
            _ => {
                // Just take whatever remaining bytes we can for the payload
                let opt_bytes = self.bytes;
                self.bytes = &[];
                Some(InitAckOptionRef::from_bytes_unchecked(opt_bytes))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum InitAckOption {
    StateCookie(Vec<u8>),
    Ipv4Address(u32),
    Ipv6Address(u128),
    UnrecognizedParameter(InitOption),
    HostnameAddress(Vec<u8>),
    Unknown(u16, Vec<u8>),
}

impl InitAckOption {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(InitAckOptionRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        InitAckOptionRef::validate(bytes)
    }

    pub fn option_type(&self) -> u16 {
        match self {
            Self::StateCookie(_) => INIT_ACK_OPT_STATE_COOKIE,
            Self::Ipv4Address(_) => INIT_ACK_OPT_IPV4_ADDRESS,
            Self::Ipv6Address(_) => INIT_ACK_OPT_IPV6_ADDRESS,
            Self::UnrecognizedParameter(_) => INIT_ACK_OPT_UNRECOGNIZED_PARAM,
            Self::HostnameAddress(_) => INIT_ACK_OPT_HOSTNAME_ADDR,
            Self::Unknown(t, _) => *t,
        }
    }

    pub fn unpadded_len(&self) -> usize {
        match self {
            Self::StateCookie(s) => 4 + s.len(),
            Self::Ipv4Address(_) => 8,
            Self::Ipv6Address(_) => 20,
            Self::UnrecognizedParameter(p) => 4 + p.len(),
            // TODO: ^^ what if the parameter in question is between 65532-65535 bytes long? Unlikely, but could affect other implementations
            Self::HostnameAddress(h) => 4 + h.len(),
            Self::Unknown(_, v) => 4 + v.len(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        let unpadded_len = u16::try_from(self.unpadded_len())
            .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
            .to_be_bytes();

        match self {
            InitAckOption::StateCookie(c) => {
                bytes.extend(INIT_ACK_OPT_STATE_COOKIE.to_be_bytes());
                bytes.extend(unpadded_len);
                bytes.extend(c);
                bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));
            }
            InitAckOption::Ipv4Address(ipv4) => {
                bytes.extend(INIT_ACK_OPT_IPV4_ADDRESS.to_be_bytes());
                bytes.extend(unpadded_len);
                bytes.extend(ipv4.to_be_bytes());
            }
            InitAckOption::Ipv6Address(ipv6) => {
                bytes.extend(INIT_ACK_OPT_IPV6_ADDRESS.to_be_bytes());
                bytes.extend(unpadded_len);
                bytes.extend(ipv6.to_be_bytes());
            }
            InitAckOption::UnrecognizedParameter(param) => {
                bytes.extend(INIT_ACK_OPT_UNRECOGNIZED_PARAM.to_be_bytes());
                bytes.extend(unpadded_len);
                param.to_bytes_extended(bytes)?;
                // No need for padding--parameter is type-checked and guaranteed to be padded
            }
            InitAckOption::HostnameAddress(host) => {
                bytes.extend(INIT_ACK_OPT_HOSTNAME_ADDR.to_be_bytes());
                bytes.extend(unpadded_len);
                bytes.extend(host);
                bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));
            }
            InitAckOption::Unknown(t, v) => {
                bytes.extend(t.to_be_bytes());
                bytes.extend(unpadded_len);
                bytes.extend(v);
                bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));
            }
        }

        Ok(())
    }
}

impl From<InitAckOptionRef<'_>> for InitAckOption {
    #[inline]
    fn from(value: InitAckOptionRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitAckOptionRef<'_>> for InitAckOption {
    fn from(value: &InitAckOptionRef<'_>) -> Self {
        match value.payload() {
            InitAckOptionPayloadRef::StateCookie(cookie) => {
                InitAckOption::StateCookie(Vec::from(cookie))
            }
            InitAckOptionPayloadRef::Ipv4Address(ipv4) => InitAckOption::Ipv4Address(ipv4),
            InitAckOptionPayloadRef::Ipv6Address(ipv6) => InitAckOption::Ipv6Address(ipv6),
            InitAckOptionPayloadRef::UnrecognizedParameter(param) => {
                InitAckOption::UnrecognizedParameter(param.into())
            }
            InitAckOptionPayloadRef::HostnameAddress(host) => {
                InitAckOption::HostnameAddress(Vec::from(host))
            }
            InitAckOptionPayloadRef::Unknown(t, v) => InitAckOption::Unknown(t, Vec::from(v)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InitAckOptionRef<'a> {
    data: &'a [u8],
}

impl<'a> InitAckOptionRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        InitAckOptionRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        let header = (utils::to_array(bytes, 0), utils::to_array(bytes, 2));
        match header {
            (Some(opt_type_arr), Some(unpadded_len_arr)) => {
                let opt_type = u16::from_be_bytes(opt_type_arr);
                let unpadded_len = u16::from_be_bytes(unpadded_len_arr);
                let len = utils::padded_length::<4>(unpadded_len as usize);

                if bytes.len() < cmp::max(len, 4) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason:
                            "insufficient bytes in SCTP INIT ACK option for payload + padding bytes",
                    });
                }

                let expected_unpadded_len = match opt_type {
                    INIT_ACK_OPT_IPV4_ADDRESS => Some(8),
                    INIT_ACK_OPT_IPV6_ADDRESS => Some(20),
                    _ => None,
                };

                if let Some(e_len) = expected_unpadded_len {
                    if unpadded_len != e_len {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]            
                            reason: "SCTP INIT ACK option Length field didn't match expected length based on Option Type",
                        });
                    }
                } else if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "SCTP INIT ACK option Length field too short to cover header",
                    });
                }

                if opt_type == INIT_ACK_OPT_UNRECOGNIZED_PARAM {
                    // Verify that payload is actually a well-formed INIT Option
                    match InitOptionRef::validate(&bytes[4..len]) {
                        Ok(_) => (),
                        Err(_) => return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]            
                            reason: "SCTP INIT ACK Unrecognized Parameter Option had malformed INIT parameter in its payload",
                        })
                    };
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP INIT ACK Option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP INIT ACK Option for header",
            }),
        }
    }

    #[inline]
    pub fn opt_type(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    pub fn payload(&self) -> InitAckOptionPayloadRef<'a> {
        match self.opt_type() {
            INIT_ACK_OPT_IPV4_ADDRESS => InitAckOptionPayloadRef::Ipv4Address(u32::from_be_bytes(
                utils::to_array(self.data, 4).unwrap(),
            )),
            INIT_ACK_OPT_IPV6_ADDRESS => InitAckOptionPayloadRef::Ipv6Address(u128::from_be_bytes(
                utils::to_array::<16>(self.data, 4).unwrap(),
            )),
            INIT_ACK_OPT_HOSTNAME_ADDR => InitAckOptionPayloadRef::HostnameAddress(
                &self.data[4..self.unpadded_len() as usize],
            ),
            INIT_ACK_OPT_STATE_COOKIE => InitAckOptionPayloadRef::StateCookie(
                &self.data[4..4 + self.unpadded_len() as usize],
            ),
            INIT_ACK_OPT_UNRECOGNIZED_PARAM => InitAckOptionPayloadRef::UnrecognizedParameter(
                InitOptionRef::from_bytes_unchecked(&self.data[4..self.unpadded_len() as usize]),
            ),
            _ => InitAckOptionPayloadRef::Unknown(
                self.opt_type(),
                &self.data[4..self.unpadded_len() as usize],
            ),
        }
    }
}

pub enum InitAckOptionPayloadRef<'a> {
    StateCookie(&'a [u8]),
    Ipv4Address(u32),
    Ipv6Address(u128),
    UnrecognizedParameter(InitOptionRef<'a>),
    HostnameAddress(&'a [u8]),
    Unknown(u16, &'a [u8]),
}

#[derive(Clone, Debug)]
pub struct SackChunk {
    flags: u8,
    cum_tsn_ack: u32,
    a_rwnd: u32,
    gap_ack_blocks: Vec<(u16, u16)>,
    duplicate_tsns: Vec<u32>,
}

impl SackChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(SackChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        SackChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_SACK
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        16 + (self.gap_ack_blocks.len() * 4) + (self.duplicate_tsns.len() * 4)
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        self.cum_tsn_ack
    }

    #[inline]
    pub fn set_ack(&mut self, ack: u32) {
        self.cum_tsn_ack = ack;
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        self.a_rwnd
    }

    #[inline]
    pub fn set_a_rwnd(&mut self, a_rwnd: u32) {
        self.a_rwnd = a_rwnd;
    }

    #[inline]
    pub fn gap_ack_blocks(&self) -> &Vec<(u16, u16)> {
        &self.gap_ack_blocks
    }

    #[inline]
    pub fn gap_ack_blocks_mut(&mut self) -> &mut Vec<(u16, u16)> {
        &mut self.gap_ack_blocks
    }

    #[inline]
    pub fn duplicate_tsns(&self) -> &Vec<u32> {
        &self.duplicate_tsns
    }

    #[inline]
    pub fn duplicate_tsns_mut(&mut self) -> &mut Vec<u32> {
        &mut self.duplicate_tsns
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_SACK);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(self.cum_tsn_ack.to_be_bytes());
        bytes.extend(self.a_rwnd.to_be_bytes());
        bytes.extend(
            u16::try_from(self.gap_ack_blocks.len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(
            u16::try_from(self.duplicate_tsns.len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        for (gap_ack_start, gap_ack_end) in &self.gap_ack_blocks {
            bytes.extend(gap_ack_start.to_be_bytes());
            bytes.extend(gap_ack_end.to_be_bytes());
        }

        for dup_tsn in &self.duplicate_tsns {
            bytes.extend(dup_tsn.to_be_bytes());
        }
        // All parameters are multiples of 4, so no padding at end

        Ok(())
    }
}

impl From<SackChunkRef<'_>> for SackChunk {
    #[inline]
    fn from(value: SackChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&SackChunkRef<'_>> for SackChunk {
    fn from(value: &SackChunkRef<'_>) -> Self {
        let mut gap_ack_blocks = Vec::new();
        for gap_ack in value.gap_ack_blocks_iter() {
            gap_ack_blocks.push(gap_ack);
        }

        let mut duplicate_tsns = Vec::new();
        for dup_tsn in value.duplicate_tsn_iter() {
            duplicate_tsns.push(dup_tsn);
        }

        SackChunk {
            flags: value.flags_raw(),
            cum_tsn_ack: value.ack(),
            a_rwnd: value.a_rwnd(),
            gap_ack_blocks,
            duplicate_tsns,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SackChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> SackChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        SackChunkRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if bytes.len() < cmp::max(len, 16) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP SACK chunk for header and optional parameters",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "SCTP SACK chunk length must be a multiple of 4",
                    });
                }

                if len < 16 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "length field of SCTP SACK chunk was too short for header",
                    });
                }

                let (gap_ack_cnt, dup_tsn_cnt) = match (utils::to_array(bytes, 12), utils::to_array(bytes, 14)) {
                    (Some(gap_ack_cnt_arr), Some(dup_tsn_cnt_arr)) => (u16::from_be_bytes(gap_ack_cnt_arr) as usize, u16::from_be_bytes(dup_tsn_cnt_arr) as usize),
                    _ => return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP SACK chunk for Number of Duplicate TSNs field"
                    })
                };

                if 16 + (gap_ack_cnt * 4) + (dup_tsn_cnt * 4) != len {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "SCTP SACK chunk Length field did not match the total length of header + Gap Ack Blocks + Duplicate TSNs"
                    });
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP SACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP SACK chunk for header Length field",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    #[inline]
    pub fn gap_ack_block_cnt(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    #[inline]
    pub fn dup_tsn_cnt(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 14).unwrap())
    }

    #[inline]
    pub fn gap_ack_blocks_iter(&self) -> GapAckBlockIterRef<'a> {
        GapAckBlockIterRef {
            bytes: &self.data[16..],
            block_idx: 0,
            block_total: self.gap_ack_block_cnt() as usize,
        }
    }

    #[inline]
    pub fn duplicate_tsn_iter(&self) -> DuplicateTsnIterRef {
        DuplicateTsnIterRef {
            bytes: &self.data[16 + (4 * self.gap_ack_block_cnt() as usize)..],
            tsn_idx: 0,
            tsn_total: self.dup_tsn_cnt() as usize,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GapAckBlockIterRef<'a> {
    bytes: &'a [u8],
    block_idx: usize,
    block_total: usize,
}

impl<'b> Iterator for GapAckBlockIterRef<'b> {
    type Item = (u16, u16);

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_idx == self.block_total {
            return None;
        }

        let start = u16::from_be_bytes(utils::to_array(self.bytes, 0).unwrap());
        let end = u16::from_be_bytes(utils::to_array(self.bytes, 2).unwrap());
        self.bytes = &self.bytes[4..];
        self.block_idx += 1;

        Some((start, end))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DuplicateTsnIterRef<'a> {
    bytes: &'a [u8],
    tsn_idx: usize,
    tsn_total: usize,
}

impl<'b> Iterator for DuplicateTsnIterRef<'b> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.tsn_idx == self.tsn_total {
            return None;
        }

        let dup_tsn = u32::from_be_bytes(utils::to_array(self.bytes, 0).unwrap());
        self.bytes = &self.bytes[4..];
        self.tsn_idx += 1;

        Some(dup_tsn)
    }
}

#[derive(Clone, Debug)]
pub struct HeartbeatChunk {
    flags: u8,
    heartbeat: Vec<u8>,
}

impl HeartbeatChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(HeartbeatChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        HeartbeatChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_HEARTBEAT
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        8 + self.heartbeat.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn heartbeat(&self) -> &Vec<u8> {
        &self.heartbeat
    }

    #[inline]
    pub fn heartbeat_mut(&mut self) -> &mut Vec<u8> {
        &mut self.heartbeat
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_HEARTBEAT);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(1u16.to_be_bytes()); // HEARTBEAT_OPT_HEARTBEAT_INFO (the only option available for HEARTBEAT chunks)
        bytes.extend(
            u16::try_from(self.heartbeat.len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.heartbeat);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<HeartbeatChunkRef<'_>> for HeartbeatChunk {
    #[inline]
    fn from(value: HeartbeatChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&HeartbeatChunkRef<'_>> for HeartbeatChunk {
    #[inline]
    fn from(value: &HeartbeatChunkRef<'_>) -> Self {
        HeartbeatChunk {
            flags: value.flags_raw(),
            heartbeat: Vec::from(value.heartbeat_info().heartbeat()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HeartbeatChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> HeartbeatChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        HeartbeatChunkRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let unpadded_len = u16::from_be_bytes(unpadded_len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(len, 8) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP HEARTBEAT chunk for header + Heartbeat Info option",
                    });
                }
                
                #[allow(unused_variables)]
                if let Err( e) = HeartbeatInfoRef::validate(&bytes[4..len]) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: e.reason,
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason: "invalid nonzero padding values at end of SCTP HEARTBEAT chunk",
                        });
                    }
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP HEARTBEAT chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP HEARTBEAT chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn heartbeat_info(&self) -> HeartbeatInfoRef<'a> {
        HeartbeatInfoRef {
            data: self.data.get(4..).unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HeartbeatInfoRef<'a> {
    data: &'a [u8],
}

impl<'a> HeartbeatInfoRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        HeartbeatInfoRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let unpadded_len = u16::from_be_bytes(unpadded_len_arr);
                let len = utils::padded_length::<4>(unpadded_len as usize);

                if len > bytes.len() {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP HEARTBEAT chunk Heartbeat Info option for Heartbeat field + padding bytes",
                    });
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]        
                        reason: "extra bytes remain at end of SCTP HEARTBEAT chunk Heartbeat Info option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in SCTP HEARTBEAT chunk Heartbeat Info option for header",
            }),
        }
    }

    #[inline]
    pub fn opt_type(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn heartbeat(&self) -> &'a [u8] {
        &self.data[4..self.unpadded_len() as usize]
    }
}

#[derive(Clone, Debug)]
pub struct HeartbeatAckChunk {
    flags: u8,
    heartbeat: Vec<u8>,
}

impl HeartbeatAckChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(HeartbeatAckChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        HeartbeatAckChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_HEARTBEAT_ACK
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        8 + self.heartbeat.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn heartbeat(&self) -> &Vec<u8> {
        &self.heartbeat
    }

    #[inline]
    pub fn heartbeat_mut(&mut self) -> &mut Vec<u8> {
        &mut self.heartbeat
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_HEARTBEAT_ACK);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(1u16.to_be_bytes()); // HEARTBEAT_ACK_OPT_HEARTBEAT_INFO - the only option available, so we don't define it
        bytes.extend(
            u16::try_from(self.heartbeat.len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.heartbeat);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<HeartbeatAckChunkRef<'_>> for HeartbeatAckChunk {
    #[inline]
    fn from(value: HeartbeatAckChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&HeartbeatAckChunkRef<'_>> for HeartbeatAckChunk {
    #[inline]
    fn from(value: &HeartbeatAckChunkRef<'_>) -> Self {
        HeartbeatAckChunk {
            flags: value.flags_raw(),
            heartbeat: Vec::from(value.heartbeat_info().heartbeat()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HeartbeatAckChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> HeartbeatAckChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        HeartbeatAckChunkRef { data: bytes }
    }

    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if len > bytes.len() {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP HEARTBEAT ACK chunk for header + Heartbeat field",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "SCTP HEARTBEAT ACK chunk length was not a multiple of 4",
                    });
                }

                HeartbeatInfoRef::validate(&bytes[4..len])?;

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP HEARTBEAT ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP HEARTBEAT ACK chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn heartbeat_info(&self) -> HeartbeatInfoRef<'a> {
        HeartbeatInfoRef::from_bytes_unchecked(&self.data[4..])
    }
}

///
#[derive(Clone, Debug)]
pub struct AbortChunk {
    flags: AbortFlags,
    causes: Vec<ErrorCause>,
}

impl AbortChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(AbortChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ErrorChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_ABORT
    }

    #[inline]
    pub fn flags(&self) -> AbortFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: AbortFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.causes.iter().map(|c| c.len()).sum::<usize>()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn causes(&self) -> &Vec<ErrorCause> {
        &self.causes
    }

    #[inline]
    pub fn set_causes(&mut self) -> &mut Vec<ErrorCause> {
        &mut self.causes
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_ABORT);
        bytes.push(self.flags.bits());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        for cause in &self.causes {
            cause.to_bytes_extended(bytes)?;
        }

        Ok(())
    }
}

impl From<AbortChunkRef<'_>> for AbortChunk {
    #[inline]
    fn from(value: AbortChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&AbortChunkRef<'_>> for AbortChunk {
    fn from(value: &AbortChunkRef<'_>) -> Self {
        let mut causes = Vec::new();
        let iter = value.error_iter();
        for error in iter {
            causes.push(error.into());
        }

        AbortChunk {
            flags: value.flags(),
            causes,
        }
    }
}

///
#[derive(Clone, Copy, Debug)]
pub struct AbortChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> AbortChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        AbortChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason:
                            "insufficient bytes in SCTP ABORT chunk for header + Error Cause fields",
                    });
                }

                if chunk_type != CHUNK_TYPE_ABORT {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid Chunk Type field in SCTP ABORT chunk (must be equal to 6)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP ABORT chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP ABORT chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> AbortFlags {
        AbortFlags::from_bits_truncate(self.flags_raw())
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn error_iter(&self) -> ErrorCauseIterRef {
        ErrorCauseIterRef {
            bytes: &self.data[4..self.unpadded_len() as usize],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ErrorCauseIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for ErrorCauseIterRef<'a> {
    type Item = ErrorCauseRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (err_type, unpadded_len) = match (
            utils::get_array(self.bytes, 0).map(|&a| u16::from_be_bytes(a)),
            utils::get_array(self.bytes, 2).map(|&a| u16::from_be_bytes(a)),
        ) {
            (Some(t), Some(l)) => (t, l),
            _ => return None,
        };

        let min_len = match err_type {
            ERR_CODE_INVALID_STREAM_ID | ERR_CODE_STALE_COOKIE | ERR_CODE_NO_USER_DATA => 8,
            ERR_CODE_MISSING_MAND_PARAM => 8, // TODO: change to 10 once '1 or more mandatory params' is enforced
            ERR_CODE_OUT_OF_RESOURCE
            | ERR_CODE_UNRESOLVABLE_ADDRESS
            | ERR_CODE_UNRECOGNIZED_CHUNK
            | ERR_CODE_INVALID_MAND_PARAM
            | ERR_CODE_UNRECOGNIZED_PARAMS
            | ERR_CODE_COOKIE_RCVD_SHUTTING_DOWN
            | ERR_CODE_RESTART_ASSOC_NEW_ADDR
            | ERR_CODE_USER_INITIATED_ABORT
            | ERR_CODE_PROTOCOL_VIOLATION => 4,
            _ => 4,
        };

        if self.bytes.len() < min_len {
            self.bytes = &[]; // Not needed, but this helps further calls to the iterator to short-circuit
            return None;
        }

        let len = cmp::max(min_len, utils::padded_length::<4>(unpadded_len as usize));
        match (self.bytes.get(..len), self.bytes.get(len..)) {
            (Some(err_bytes), Some(rem)) => {
                self.bytes = rem;
                Some(ErrorCauseRef::from_bytes_unchecked(err_bytes))
            }
            _ => {
                // Just take whatever remaining bytes we can for the payload
                let err_bytes = self.bytes;
                self.bytes = &[];
                Some(ErrorCauseRef::from_bytes_unchecked(err_bytes))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum ErrorCause {
    InvalidStreamIdentifier(StreamIdentifierError),

    MissingMandatoryParameter(MissingParameterError),

    StaleCookie(StaleCookieError),

    OutOfResource,

    UnresolvableAddress(UnresolvableAddrError),

    UnrecognizedChunkType(UnrecognizedChunkError),

    UnrecognizedParameters(UnrecognizedParamError),

    InvalidMandatoryParameter,

    NoUserData(NoUserDataError),

    CookieDuringShutdown,

    AssociationNewAddress(AssociationNewAddrError),

    UserInitiatedAbort(UserInitiatedAbortError),

    ProtocolViolation(ProtocolViolationError),

    /// Some other error code not defined in RFC 4960.
    Unknown(GenericParam),
}

impl ErrorCause {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ErrorCauseRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ErrorCauseRef::validate(bytes)
    }

    pub fn len(&self) -> usize {
        match self {
            Self::OutOfResource | Self::CookieDuringShutdown | Self::InvalidMandatoryParameter => 4,
            Self::InvalidStreamIdentifier(_) => 8,
            Self::MissingMandatoryParameter(e) => e.len(),
            Self::StaleCookie(_) => 8,
            Self::UnresolvableAddress(e) => e.len(),
            Self::UnrecognizedChunkType(e) => e.len(),
            Self::UnrecognizedParameters(e) => e.len(),
            Self::NoUserData(_) => 8,
            Self::AssociationNewAddress(e) => e.len(),
            Self::UserInitiatedAbort(e) => e.len(),
            Self::ProtocolViolation(e) => e.len(),
            Self::Unknown(e) => e.len(),
        }
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        match self {
            ErrorCause::InvalidStreamIdentifier(e) => e.to_bytes_extended(bytes),
            ErrorCause::MissingMandatoryParameter(e) => e.to_bytes_extended(bytes)?,
            ErrorCause::StaleCookie(e) => e.to_bytes_extended(bytes),
            ErrorCause::OutOfResource => {
                bytes.extend(ERR_CODE_OUT_OF_RESOURCE.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
            }
            ErrorCause::UnresolvableAddress(e) => e.to_bytes_extended(bytes)?,
            ErrorCause::UnrecognizedChunkType(e) => e.to_bytes_extended(bytes),
            ErrorCause::InvalidMandatoryParameter => {
                bytes.extend(ERR_CODE_INVALID_MAND_PARAM.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
            }
            ErrorCause::UnrecognizedParameters(e) => e.to_bytes_extended(bytes)?,
            ErrorCause::NoUserData(e) => e.to_bytes_extended(bytes),
            ErrorCause::CookieDuringShutdown => {
                bytes.extend(ERR_CODE_COOKIE_RCVD_SHUTTING_DOWN.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
            }
            ErrorCause::AssociationNewAddress(e) => e.to_bytes_extended(bytes)?,
            ErrorCause::UserInitiatedAbort(e) => e.to_bytes_extended(bytes)?,
            ErrorCause::ProtocolViolation(e) => e.to_bytes_extended(bytes)?,
            ErrorCause::Unknown(e) => e.to_bytes_extended(bytes)?,
        }
        Ok(())
    }
}

impl From<ErrorCauseRef<'_>> for ErrorCause {
    #[inline]
    fn from(value: ErrorCauseRef<'_>) -> Self {
        ErrorCause::from(&value)
    }
}

impl From<&ErrorCauseRef<'_>> for ErrorCause {
    fn from(value: &ErrorCauseRef<'_>) -> Self {
        match value {
            ErrorCauseRef::InvalidStreamIdentifier(e) => {
                ErrorCause::InvalidStreamIdentifier(e.into())
            }
            ErrorCauseRef::MissingMandatoryParameter(e) => {
                ErrorCause::MissingMandatoryParameter(e.into())
            }
            ErrorCauseRef::StaleCookie(e) => ErrorCause::StaleCookie(e.into()),
            ErrorCauseRef::OutOfResource(_) => ErrorCause::OutOfResource,
            ErrorCauseRef::UnresolvableAddress(e) => ErrorCause::UnresolvableAddress(e.into()),
            ErrorCauseRef::UnrecognizedChunkType(e) => ErrorCause::UnrecognizedChunkType(e.into()),
            ErrorCauseRef::InvalidMandatoryParameter(_) => ErrorCause::InvalidMandatoryParameter,
            ErrorCauseRef::UnrecognizedParameters(e) => {
                ErrorCause::UnrecognizedParameters(e.into())
            }
            ErrorCauseRef::NoUserData(e) => ErrorCause::NoUserData(e.into()),
            ErrorCauseRef::CookieDuringShutdown(_) => ErrorCause::CookieDuringShutdown,
            ErrorCauseRef::AssociationNewAddress(e) => ErrorCause::AssociationNewAddress(e.into()),
            ErrorCauseRef::UserInitiatedAbort(e) => ErrorCause::UserInitiatedAbort(e.into()),
            ErrorCauseRef::ProtocolViolation(e) => ErrorCause::ProtocolViolation(e.into()),
            ErrorCauseRef::Unknown(e) => ErrorCause::Unknown(e.into()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ErrorCauseRef<'a> {
    InvalidStreamIdentifier(StreamIdentifierErrorRef<'a>),

    MissingMandatoryParameter(MissingParameterErrorRef<'a>),

    StaleCookie(StaleCookieErrorRef<'a>),

    OutOfResource(&'a [u8]),

    UnresolvableAddress(UnresolvableAddrErrorRef<'a>),

    UnrecognizedChunkType(UnrecognizedChunkErrorRef<'a>),

    InvalidMandatoryParameter(&'a [u8]),

    UnrecognizedParameters(UnrecognizedParamErrorRef<'a>),

    NoUserData(NoUserDataErrorRef<'a>),

    CookieDuringShutdown(&'a [u8]),

    AssociationNewAddress(AssociationNewAddrErrorRef<'a>),

    UserInitiatedAbort(UserInitiatedAbortErrorRef<'a>),

    ProtocolViolation(ProtocolViolationErrorRef<'a>),

    /// Some other error code not defined in RFC 4960.
    Unknown(GenericParamRef<'a>),
}

impl<'a> ErrorCauseRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        let cause_code = u16::from_be_bytes(utils::to_array(bytes, 0).unwrap());
        match cause_code {
            ERR_CODE_INVALID_STREAM_ID => {
                Self::InvalidStreamIdentifier(StreamIdentifierErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_MISSING_MAND_PARAM => Self::MissingMandatoryParameter(
                MissingParameterErrorRef::from_bytes_unchecked(bytes),
            ),
            ERR_CODE_STALE_COOKIE => {
                Self::StaleCookie(StaleCookieErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_OUT_OF_RESOURCE => Self::OutOfResource(bytes),
            ERR_CODE_UNRESOLVABLE_ADDRESS => {
                Self::UnresolvableAddress(UnresolvableAddrErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_UNRECOGNIZED_CHUNK => {
                Self::UnrecognizedChunkType(UnrecognizedChunkErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_INVALID_MAND_PARAM => Self::InvalidMandatoryParameter(bytes),
            ERR_CODE_UNRECOGNIZED_PARAMS => {
                Self::UnrecognizedParameters(UnrecognizedParamErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_NO_USER_DATA => {
                Self::NoUserData(NoUserDataErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_COOKIE_RCVD_SHUTTING_DOWN => Self::CookieDuringShutdown(bytes),
            ERR_CODE_RESTART_ASSOC_NEW_ADDR => {
                Self::AssociationNewAddress(AssociationNewAddrErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_USER_INITIATED_ABORT => {
                Self::UserInitiatedAbort(UserInitiatedAbortErrorRef::from_bytes_unchecked(bytes))
            }
            ERR_CODE_PROTOCOL_VIOLATION => {
                Self::ProtocolViolation(ProtocolViolationErrorRef::from_bytes_unchecked(bytes))
            }
            _ => Self::Unknown(GenericParamRef::from_bytes_unchecked(bytes)),
        }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let cause_code = u16::from_be_bytes(utils::to_array(bytes, 0).unwrap());
        match cause_code {
            ERR_CODE_INVALID_STREAM_ID => StreamIdentifierErrorRef::validate(bytes),
            ERR_CODE_MISSING_MAND_PARAM => MissingParameterErrorRef::validate(bytes),
            ERR_CODE_STALE_COOKIE => StaleCookieErrorRef::validate(bytes),
            ERR_CODE_UNRESOLVABLE_ADDRESS => UnresolvableAddrErrorRef::validate(bytes),
            ERR_CODE_UNRECOGNIZED_CHUNK => UnrecognizedChunkErrorRef::validate(bytes),
            ERR_CODE_UNRECOGNIZED_PARAMS => UnrecognizedParamErrorRef::validate(bytes),
            ERR_CODE_NO_USER_DATA => NoUserDataErrorRef::validate(bytes),
            ERR_CODE_RESTART_ASSOC_NEW_ADDR => AssociationNewAddrErrorRef::validate(bytes),
            ERR_CODE_USER_INITIATED_ABORT => UserInitiatedAbortErrorRef::validate(bytes),
            ERR_CODE_PROTOCOL_VIOLATION => ProtocolViolationErrorRef::validate(bytes),
            ERR_CODE_OUT_OF_RESOURCE
            | ERR_CODE_INVALID_MAND_PARAM
            | ERR_CODE_COOKIE_RCVD_SHUTTING_DOWN => match utils::to_array(bytes, 2) {
                Some(len_arr) => {
                    let len = u16::from_be_bytes(len_arr) as usize;

                    if len != 4 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason: "invalid length in SCTP Error Cause (must be equal to 4)",
                        });
                    }

                    if bytes.len() > 4 {
                        Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::ExcessBytes(bytes.len() - 4),
                            #[cfg(feature = "error_string")]
                            reason: "extra bytes remain at end of SCTP 4-byte Error Cause",
                        })
                    } else {
                        Ok(())
                    }
                }
                _ => Err(ValidationError {
                    layer: Sctp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason: "insufficient bytes in SCTP 4-byte Error Cause for header",
                }),
            },
            _ => match utils::to_array(bytes, 2) {
                Some(len_arr) => {
                    let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                    let len = utils::padded_length::<4>(unpadded_len);

                    if bytes.len() < cmp::max(8, len) {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InsufficientBytes,
                            #[cfg(feature = "error_string")]            
                            reason: "insufficient bytes in SCTP <unknown> Error Cause for header and data field",
                        });
                    }

                    if unpadded_len < 8 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]            
                            reason: "invalid length in SCTP <unknown> Error Cause (must be at least 8 bytes)",
                        });
                    }

                    if bytes.len() > len {
                        Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                            #[cfg(feature = "error_string")]
                            reason: "extra bytes remain at end of SCTP <unknown> Error Cause",
                        })
                    } else {
                        Ok(())
                    }
                }
                _ => Err(ValidationError {
                    layer: Sctp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason: "insufficient bytes in SCTP <unknown> Error Cause for header",
                }),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct StreamIdentifierError {
    stream_id: u16,
    reserved: u16,
}

impl StreamIdentifierError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(StreamIdentifierErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        StreamIdentifierErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_INVALID_STREAM_ID
    }

    #[inline]
    pub fn len(&self) -> usize {
        8
    }

    #[inline]
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    #[inline]
    pub fn set_stream_id(&mut self, stream_id: u16) {
        self.stream_id = stream_id;
    }

    #[inline]
    pub fn reserved(&self) -> u16 {
        self.reserved
    }

    #[inline]
    pub fn set_reserved(&mut self, reserved: u16) {
        self.reserved = reserved;
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_INVALID_STREAM_ID.to_be_bytes());
        bytes.extend(8u16.to_be_bytes());
        bytes.extend(self.stream_id.to_be_bytes());
        bytes.extend(self.reserved.to_be_bytes());
    }
}

impl From<StreamIdentifierErrorRef<'_>> for StreamIdentifierError {
    #[inline]
    fn from(value: StreamIdentifierErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&StreamIdentifierErrorRef<'_>> for StreamIdentifierError {
    #[inline]
    fn from(value: &StreamIdentifierErrorRef<'_>) -> Self {
        StreamIdentifierError {
            stream_id: value.stream_id(),
            reserved: value.reserved(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StreamIdentifierErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> StreamIdentifierErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        StreamIdentifierErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Invalid Stream Identifier option for header + Explanation field",
                    });
                }

                if cause_code != ERR_CODE_INVALID_STREAM_ID {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Invalid Stream Identifier Option (must be equal to 1)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid length in SCTP Invalid Stream Identifier Option (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 8),
                        #[cfg(feature = "error_string")]
                        reason:
                            "extra bytes remain at end of SCTP Invalid Stream Identifier option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Invalid Stream Identifier option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn stream_id(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn reserved(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct MissingParameterError {
    missing_params: Vec<u16>,
}

impl MissingParameterError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(MissingParameterErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        MissingParameterErrorRef::validate(bytes)
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        8 + (2 * self.missing_params.len())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn missing_params(&self) -> &Vec<u16> {
        &self.missing_params
    }

    #[inline]
    pub fn missing_params_mut(&mut self) -> &mut Vec<u16> {
        &mut self.missing_params
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(ERR_CODE_MISSING_MAND_PARAM.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(
            (u32::try_from(self.missing_params.len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?)
            .to_be_bytes(),
        );
        for param in &self.missing_params {
            bytes.extend(param.to_be_bytes());
        }
        if self.missing_params.len() % 4 != 0 {
            bytes.push(0);
            bytes.push(0);
        }
        Ok(())
    }
}

impl From<MissingParameterErrorRef<'_>> for MissingParameterError {
    #[inline]
    fn from(value: MissingParameterErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&MissingParameterErrorRef<'_>> for MissingParameterError {
    #[inline]
    fn from(value: &MissingParameterErrorRef<'_>) -> Self {
        MissingParameterError {
            missing_params: Vec::from_iter(value.missing_params_iter()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MissingParameterErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> MissingParameterErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        MissingParameterErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(8, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Missing Mandatory Parameter option for header + Missing Parameter fields",
                    });
                }

                if cause_code != ERR_CODE_MISSING_MAND_PARAM {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Missing Mandatory Parameter option (must be equal to 2)",
                    });
                }

                if unpadded_len < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid length in SCTP Missing Mandatory Parameter option (must be at least 8 bytes long)",
                    });
                }

                if unpadded_len % 2 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid length in SCTP Missing Mandatory Parameter option (must be a multiple of 2)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]            
                            reason: "invalid nonzero padding values at end of SCTP Missing Mandatory Parameter Option",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of Missing Mandatory Parameter option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Missing Mandatory Parameter option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn missing_params_cnt(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn missing_params_iter(&self) -> MissingParameterIterRef<'a> {
        MissingParameterIterRef {
            data: &self.data[4..cmp::min(
                4 + (2 * self.missing_params_cnt() as usize),
                self.data.len(),
            )],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MissingParameterIterRef<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for MissingParameterIterRef<'a> {
    type Item = u16;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match (utils::to_array(self.data, 0), self.data.get(2..)) {
            (Some(arr), Some(remaining)) => {
                self.data = remaining;
                Some(u16::from_be_bytes(arr))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StaleCookieError {
    staleness: u32,
}

impl StaleCookieError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(StaleCookieErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        StaleCookieErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_STALE_COOKIE
    }

    #[inline]
    pub fn len(&self) -> usize {
        8
    }

    #[inline]
    pub fn staleness(&self) -> u32 {
        self.staleness
    }

    #[inline]
    pub fn set_staleness(&mut self, staleness: u32) {
        self.staleness = staleness;
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_STALE_COOKIE.to_be_bytes());
        bytes.extend(8u16.to_be_bytes());
        bytes.extend(self.staleness.to_be_bytes());
    }
}

impl From<StaleCookieErrorRef<'_>> for StaleCookieError {
    #[inline]
    fn from(value: StaleCookieErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&StaleCookieErrorRef<'_>> for StaleCookieError {
    #[inline]
    fn from(value: &StaleCookieErrorRef<'_>) -> Self {
        StaleCookieError {
            staleness: value.staleness(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StaleCookieErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> StaleCookieErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        StaleCookieErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Stale Cookie option for header + Measure of Staleness field",
                    });
                }

                if cause_code != ERR_CODE_STALE_COOKIE {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "invalid cause code in SCTP Stale Cookie option (must be equal to 3)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP Stale Cookie option (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 8),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP Stale Cookie option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Stale Cookie option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn staleness(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct UnresolvableAddrError {
    addr: Vec<u8>,
}

impl UnresolvableAddrError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(UnresolvableAddrErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        UnresolvableAddrErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_UNRESOLVABLE_ADDRESS
    }

    pub fn unpadded_len(&self) -> usize {
        4 + self.addr.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn addr(&self) -> &Vec<u8> {
        &self.addr
    }

    #[inline]
    pub fn addr_mut(&mut self) -> &mut Vec<u8> {
        &mut self.addr
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(ERR_CODE_UNRESOLVABLE_ADDRESS.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.addr);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<UnresolvableAddrErrorRef<'_>> for UnresolvableAddrError {
    #[inline]
    fn from(value: UnresolvableAddrErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&UnresolvableAddrErrorRef<'_>> for UnresolvableAddrError {
    #[inline]
    fn from(value: &UnresolvableAddrErrorRef<'_>) -> Self {
        UnresolvableAddrError {
            addr: Vec::from(value.addr()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UnresolvableAddrErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> UnresolvableAddrErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        UnresolvableAddrErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Unresolvable Address option for header + Unresolvable Address field",
                    });
                }

                if cause_code != ERR_CODE_UNRESOLVABLE_ADDRESS {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Unresolvable Address option (must be equal to 5)",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid length in SCTP Unresolvable Address option (must be at least 4 bytes long)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]            
                            reason: "invalid nonzero padding values at end of SCTP Unresolvable Address 4ption",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP Unresolvable Address option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Unresolvable Address option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn addr(&self) -> &[u8] {
        &self.data[4..self.unpadded_len() as usize]
    }
}

#[derive(Clone, Debug)]
pub struct UnrecognizedChunkError {
    chunk: Vec<u8>,
}

impl UnrecognizedChunkError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(UnrecognizedChunkErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        UnrecognizedChunkErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_UNRECOGNIZED_CHUNK
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.chunk.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn chunk(&self) -> &Vec<u8> {
        &self.chunk
    }

    #[inline]
    pub fn chunk_mut(&mut self) -> &mut Vec<u8> {
        &mut self.chunk
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_STALE_COOKIE.to_be_bytes());
        bytes.extend(8u16.to_be_bytes());
        bytes.extend(&self.chunk);
    }
}

impl From<UnrecognizedChunkErrorRef<'_>> for UnrecognizedChunkError {
    #[inline]
    fn from(value: UnrecognizedChunkErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&UnrecognizedChunkErrorRef<'_>> for UnrecognizedChunkError {
    #[inline]
    fn from(value: &UnrecognizedChunkErrorRef<'_>) -> Self {
        UnrecognizedChunkError {
            chunk: Vec::from(value.chunk()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UnrecognizedChunkErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> UnrecognizedChunkErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        UnrecognizedChunkErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(8, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Unrecognized Chunk option for header + Unrecognized Chunk field",
                    });
                }

                if cause_code != ERR_CODE_UNRECOGNIZED_CHUNK {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Unrecognized Chunk option (must be equal to 6)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP Unrecognized Chunk option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Unrecognized Chunk option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn chunk(&self) -> &[u8] {
        &self.data[8..self.unpadded_len() as usize]
    }
}

#[derive(Clone, Debug)]
pub struct UnrecognizedParamError {
    params: Vec<GenericParam>,
}

impl UnrecognizedParamError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(UnrecognizedParamErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        UnrecognizedParamErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_UNRECOGNIZED_PARAMS
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.params.iter().map(|p| p.len()).sum::<usize>()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn params(&self) -> &Vec<GenericParam> {
        &self.params
    }

    #[inline]
    pub fn params_mut(&mut self) -> &mut Vec<GenericParam> {
        &mut self.params
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(ERR_CODE_UNRECOGNIZED_PARAMS.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        for param in self.params.iter() {
            param.to_bytes_extended(bytes)?;
        }

        Ok(())
    }
}

impl From<UnrecognizedParamErrorRef<'_>> for UnrecognizedParamError {
    #[inline]
    fn from(value: UnrecognizedParamErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&UnrecognizedParamErrorRef<'_>> for UnrecognizedParamError {
    fn from(value: &UnrecognizedParamErrorRef<'_>) -> Self {
        let mut params = Vec::new();
        let iter = value.params_iter();
        for param in iter {
            params.push(param.into());
        }

        UnrecognizedParamError { params }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UnrecognizedParamErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> UnrecognizedParamErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        UnrecognizedParamErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Unrecognized Parameters Option for header and Unrecognized Chunk field",
                    });
                }

                if cause_code != ERR_CODE_UNRECOGNIZED_PARAMS {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Unrecognized Parameters option (must be equal to 8)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP Unrecognized Parameters option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Unrecognized Parameters option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn params_iter(&self) -> ParamsIterRef<'a> {
        ParamsIterRef { bytes: self.data }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ParamsIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for ParamsIterRef<'a> {
    type Item = GenericParamRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match utils::to_array(self.bytes, 2) {
            Some(unpadded_len_arr) => {
                let unpadded_len = cmp::max(4, u16::from_be_bytes(unpadded_len_arr));
                let len = utils::padded_length::<4>(unpadded_len as usize);
                match (self.bytes.get(..len), self.bytes.get(len..)) {
                    (Some(param), Some(remaining)) => {
                        self.bytes = remaining;
                        Some(GenericParamRef::from_bytes_unchecked(param))
                    }
                    _ => {
                        let param = GenericParamRef::from_bytes_unchecked(self.bytes);
                        self.bytes = &[];
                        Some(param)
                    }
                }
            }
            None => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NoUserDataError {
    tsn: u32,
}

impl NoUserDataError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(NoUserDataErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        NoUserDataErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_NO_USER_DATA
    }

    #[inline]
    pub fn len(&self) -> usize {
        8
    }

    #[inline]
    pub fn tsn(&self) -> u32 {
        self.tsn
    }

    #[inline]
    pub fn set_tsn(&mut self, tsn: u32) {
        self.tsn = tsn;
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_NO_USER_DATA.to_be_bytes());
        bytes.extend(8u16.to_be_bytes());
        bytes.extend(self.tsn.to_be_bytes());
    }
}

impl From<NoUserDataErrorRef<'_>> for NoUserDataError {
    #[inline]
    fn from(value: NoUserDataErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&NoUserDataErrorRef<'_>> for NoUserDataError {
    #[inline]
    fn from(value: &NoUserDataErrorRef<'_>) -> Self {
        NoUserDataError { tsn: value.tsn() }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NoUserDataErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> NoUserDataErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        NoUserDataErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP No User Data option for header and explanation field",
                    });
                }

                if cause_code != ERR_CODE_NO_USER_DATA {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "invalid cause code in SCTP No User Data option (must be equal to 9)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP No User Data option (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 8),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP No User Data option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP No User Data option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn tsn(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct AssociationNewAddrError {
    tlvs: Vec<GenericParam>,
}

impl AssociationNewAddrError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(AssociationNewAddrErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        AssociationNewAddrErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_RESTART_ASSOC_NEW_ADDR
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.tlvs.iter().map(|p| p.len()).sum::<usize>()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn params(&self) -> &Vec<GenericParam> {
        &self.tlvs
    }

    #[inline]
    pub fn params_mut(&mut self) -> &mut Vec<GenericParam> {
        &mut self.tlvs
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(ERR_CODE_RESTART_ASSOC_NEW_ADDR.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        for tlv in self.tlvs.iter() {
            tlv.to_bytes_extended(bytes)?;
        }

        Ok(())
    }
}

impl From<AssociationNewAddrErrorRef<'_>> for AssociationNewAddrError {
    #[inline]
    fn from(value: AssociationNewAddrErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&AssociationNewAddrErrorRef<'_>> for AssociationNewAddrError {
    #[inline]
    fn from(value: &AssociationNewAddrErrorRef<'_>) -> Self {
        let mut tlvs = Vec::new();
        let iter = value.params_iter();
        for param in iter {
            tlvs.push(param.into());
        }

        AssociationNewAddrError { tlvs }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AssociationNewAddrErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> AssociationNewAddrErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        AssociationNewAddrErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Restart of Association with New Address option for header + New Address TLVs field",
                    })
                }

                if cause_code != ERR_CODE_RESTART_ASSOC_NEW_ADDR {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Restart of Association with New Address option (must be equal to 11)",
                    })
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]        
                        reason: "extra bytes remain at end of SCTP Restart of Association with New Address option",
                    })
                } else {
                    Ok(())
                }
            },
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Restart of Association with New Address option for header"
            })
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn params_iter(&self) -> ParamsIterRef<'a> {
        ParamsIterRef { bytes: self.data }
    }
}

#[derive(Clone, Debug)]
pub struct UserInitiatedAbortError {
    reason: Vec<u8>,
}

impl UserInitiatedAbortError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(UserInitiatedAbortErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        UserInitiatedAbortErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_USER_INITIATED_ABORT
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.reason.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn reason(&self) -> &Vec<u8> {
        &self.reason
    }

    #[inline]
    pub fn reason_mut(&mut self) -> &mut Vec<u8> {
        &mut self.reason
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(ERR_CODE_USER_INITIATED_ABORT.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.reason);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<UserInitiatedAbortErrorRef<'_>> for UserInitiatedAbortError {
    #[inline]
    fn from(value: UserInitiatedAbortErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&UserInitiatedAbortErrorRef<'_>> for UserInitiatedAbortError {
    #[inline]
    fn from(value: &UserInitiatedAbortErrorRef<'_>) -> Self {
        UserInitiatedAbortError {
            reason: Vec::from(value.reason()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UserInitiatedAbortErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> UserInitiatedAbortErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        UserInitiatedAbortErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP User-Initiated Abort option for header + Reason field",
                    });
                }

                if cause_code != ERR_CODE_USER_INITIATED_ABORT {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP User-Initiated Abort option (must be equal to 12)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP User-Initiated Abort option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP User-Initiated Abort option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn reason(&self) -> &[u8] {
        &self.data[8..self.unpadded_len() as usize]
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolViolationError {
    information: Vec<u8>,
}

impl ProtocolViolationError {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ProtocolViolationErrorRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ProtocolViolationErrorRef::validate(bytes)
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        ERR_CODE_PROTOCOL_VIOLATION
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.information.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn information(&self) -> &Vec<u8> {
        &self.information
    }

    #[inline]
    pub fn information_mut(&mut self) -> &mut Vec<u8> {
        &mut self.information
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(ERR_CODE_PROTOCOL_VIOLATION.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.information);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<ProtocolViolationErrorRef<'_>> for ProtocolViolationError {
    #[inline]
    fn from(value: ProtocolViolationErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&ProtocolViolationErrorRef<'_>> for ProtocolViolationError {
    #[inline]
    fn from(value: &ProtocolViolationErrorRef<'_>) -> Self {
        ProtocolViolationError {
            information: Vec::from(value.information()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProtocolViolationErrorRef<'a> {
    data: &'a [u8],
}

impl<'a> ProtocolViolationErrorRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ProtocolViolationErrorRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(8, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP Protocol Violation option for header + Additional Information field",
                    });
                }

                if cause_code != ERR_CODE_PROTOCOL_VIOLATION {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid cause code in SCTP Protocol Violation option (must be equal to 13)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP Protocol Violation option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Protocol Violation option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn information(&self) -> &[u8] {
        &self.data[8..self.unpadded_len() as usize]
    }
}

/// An optional/variable-length parameter with a type not recognized by the `pkts` library.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |         Parameter Type        |        Parameter Length       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 Z                        Parameter Value                        Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug)]
pub struct GenericParam {
    param_type: u16,
    value: Vec<u8>,
}

impl GenericParam {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(GenericParamRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        GenericParamRef::validate(bytes)
    }

    #[inline]
    pub fn param_type(&self) -> u16 {
        self.param_type
    }

    #[inline]
    pub fn set_param_type(&mut self, param_type: u16) {
        self.param_type = param_type;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.value.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    #[inline]
    pub fn value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.value
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.extend(self.param_type.to_be_bytes());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(self.value.iter());
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<GenericParamRef<'_>> for GenericParam {
    #[inline]
    fn from(value: GenericParamRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&GenericParamRef<'_>> for GenericParam {
    #[inline]
    fn from(value: &GenericParamRef<'_>) -> Self {
        GenericParam {
            param_type: value.param_type(),
            value: Vec::from(value.value()),
        }
    }
}

/// An optional/variable-length parameter for an SCTP Control chunk with a type not recognized by
/// the `pkts` library.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |         Parameter Type        |        Parameter Length       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 Z                        Parameter Value                        Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug)]
pub struct GenericParamRef<'a> {
    data: &'a [u8],
}

impl<'a> GenericParamRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        GenericParamRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(len_arr) => {
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "insufficient bytes in SCTP Parameter for header + Value field",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP Parameter (must be at least 4 bytes long)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason: "invalid nonzero padding values at end of SCTP Parameter",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP Parameter",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP Parameter for header",
            }),
        }
    }

    #[inline]
    pub fn param_type(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        &self.data[4..self.unpadded_len() as usize]
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct AbortFlags: u8 {
        const T = 0b00000001;
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownChunk {
    flags: u8,
    cum_tsn_ack: u32,
}

impl ShutdownChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ShutdownChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ShutdownChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_SHUTDOWN
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn len(&self) -> usize {
        8
    }

    #[inline]
    pub fn cum_tsn_ack(&self) -> u32 {
        self.cum_tsn_ack
    }

    #[inline]
    pub fn set_cum_tsn_ack(&mut self, ack: u32) {
        self.cum_tsn_ack = ack;
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_SHUTDOWN);
        bytes.push(self.flags);
        bytes.extend(8u16.to_be_bytes());
        bytes.extend(self.cum_tsn_ack.to_be_bytes());
    }
}

impl From<ShutdownChunkRef<'_>> for ShutdownChunk {
    #[inline]
    fn from(value: ShutdownChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&ShutdownChunkRef<'_>> for ShutdownChunk {
    #[inline]
    fn from(value: &ShutdownChunkRef<'_>) -> Self {
        ShutdownChunk {
            flags: value.flags(),
            cum_tsn_ack: value.cum_tsn_ack(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShutdownChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> ShutdownChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ShutdownChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]        
                        reason: "insufficient bytes in SCTP SHUTDOWN chunk for header + Cumulative TSN Ack field",
                    });
                }

                if chunk_type != CHUNK_TYPE_SHUTDOWN {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "invalid Chunk Type field in SCTP SHUTDOWN chunk (must be equal to 7)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP SHUTDOWN chunk (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 8),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP SHUTDOWN chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP SHUTDOWN chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn cum_tsn_ack(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownAckChunk {
    flags: u8,
}

impl ShutdownAckChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ShutdownAckChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ShutdownAckChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_SHUTDOWN_ACK
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn len(&self) -> usize {
        4
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_SHUTDOWN_ACK);
        bytes.push(self.flags);
        bytes.extend(4u16.to_be_bytes());
    }
}

impl From<ShutdownAckChunkRef<'_>> for ShutdownAckChunk {
    #[inline]
    fn from(value: ShutdownAckChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&ShutdownAckChunkRef<'_>> for ShutdownAckChunk {
    #[inline]
    fn from(value: &ShutdownAckChunkRef<'_>) -> Self {
        ShutdownAckChunk {
            flags: value.flags(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShutdownAckChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> ShutdownAckChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ShutdownAckChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if chunk_type != CHUNK_TYPE_SHUTDOWN_ACK {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]        
                        reason: "invalid Chunk Type field in SCTP SHUTDOWN ACK chunk (must be equal to 8)",
                    });
                }

                if len != 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP SHUTDOWN ACK chunk (must be equal to 4)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 4),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP SHUTDOWN ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP SHUTDOWN ACK chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }
}

#[derive(Clone, Debug)]
pub struct ErrorChunk {
    flags: u8,
    causes: Vec<ErrorCause>,
}

impl ErrorChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ErrorChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ErrorChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_ERROR
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.causes.iter().map(|c| c.len()).sum::<usize>()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.unpadded_len()
    }

    #[inline]
    pub fn causes(&self) -> &Vec<ErrorCause> {
        &self.causes
    }

    #[inline]
    pub fn set_causes(&mut self) -> &mut Vec<ErrorCause> {
        &mut self.causes
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_ERROR);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        for cause in &self.causes {
            cause.to_bytes_extended(bytes)?
        }

        Ok(())
    }
}

impl From<ErrorChunkRef<'_>> for ErrorChunk {
    #[inline]
    fn from(value: ErrorChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&ErrorChunkRef<'_>> for ErrorChunk {
    fn from(value: &ErrorChunkRef<'_>) -> Self {
        let mut causes = Vec::new();
        let iter = value.error_iter();
        for error in iter {
            causes.push(error.into());
        }

        ErrorChunk {
            flags: value.flags_raw(),
            causes,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ErrorChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> ErrorChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ErrorChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason:
                            "insufficient bytes in SCTP ERROR chunk for header + Error Causes field",
                    });
                }

                if chunk_type != CHUNK_TYPE_ERROR {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid Chunk Type field in SCTP ERROR chunk (must be equal to 9)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP ERROR chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP ERROR chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn error_iter(&self) -> ErrorCauseIterRef {
        ErrorCauseIterRef {
            bytes: &self.data[4..self.unpadded_len() as usize],
        }
    }
}

#[derive(Clone, Debug)]
pub struct CookieEchoChunk {
    flags: u8,
    cookie: Vec<u8>,
}

impl CookieEchoChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(CookieEchoChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        CookieEchoChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_COOKIE_ECHO
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        4 + self.cookie.len()
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn cookie(&self) -> &Vec<u8> {
        &self.cookie
    }

    #[inline]
    pub fn cookie_mut(&mut self) -> &mut Vec<u8> {
        &mut self.cookie
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(CHUNK_TYPE_COOKIE_ECHO);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.cookie);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<CookieEchoChunkRef<'_>> for CookieEchoChunk {
    #[inline]
    fn from(value: CookieEchoChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&CookieEchoChunkRef<'_>> for CookieEchoChunk {
    #[inline]
    fn from(value: &CookieEchoChunkRef<'_>) -> Self {
        CookieEchoChunk {
            flags: value.flags_raw(),
            cookie: Vec::from(value.cookie()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CookieEchoChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> CookieEchoChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        CookieEchoChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason:
                            "insufficient bytes in SCTP COOKIE ECHO chunk for header + Cookie field",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP COOKIE ECHO chunk (must be at least 4 octets long)",
                    });
                }

                if chunk_type != CHUNK_TYPE_COOKIE_ECHO {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid Chunk Type field in SCTP COOKIE ECHO chunk (must be equal to 10)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason:
                                "invalid nonzero padding values at end of SCTP COOKIE ECHO chunk",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP COOKIE ECHO hunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP COOKIE ECHO chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn cookie(&self) -> &[u8] {
        &self.data[4..self.unpadded_len() as usize]
    }
}

#[derive(Clone, Debug)]
pub struct CookieAckChunk {
    flags: u8,
}

impl CookieAckChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(CookieAckChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        CookieAckChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_COOKIE_ACK
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn len(&self) -> usize {
        4
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_COOKIE_ACK);
        bytes.push(self.flags);
        bytes.extend(4u16.to_be_bytes());
    }
}

impl From<CookieAckChunkRef<'_>> for CookieAckChunk {
    #[inline]
    fn from(value: CookieAckChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&CookieAckChunkRef<'_>> for CookieAckChunk {
    #[inline]
    fn from(value: &CookieAckChunkRef<'_>) -> Self {
        CookieAckChunk {
            flags: value.flags(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CookieAckChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> CookieAckChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        CookieAckChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if chunk_type != CHUNK_TYPE_COOKIE_ACK {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "invalid Chunk Type field in SCTP COOKIE ACK chunk (must be equal to 11)",
                    });
                }

                if len != 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid length in SCTP COOKIE_ACK chunk (must be equal to 4)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 4),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP COOKIE ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP COOKIE ACK chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownCompleteChunk {
    flags: ShutdownCompleteFlags,
}

impl ShutdownCompleteChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ShutdownCompleteChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ShutdownCompleteChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_SHUTDOWN_COMPLETE
    }

    #[inline]
    pub fn flags(&self) -> ShutdownCompleteFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: ShutdownCompleteFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn len(&self) -> usize {
        4
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_SHUTDOWN_COMPLETE);
        bytes.push(self.flags.bits());
        bytes.extend(4u16.to_be_bytes());
    }
}

impl From<ShutdownCompleteChunkRef<'_>> for ShutdownCompleteChunk {
    #[inline]
    fn from(value: ShutdownCompleteChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&ShutdownCompleteChunkRef<'_>> for ShutdownCompleteChunk {
    #[inline]
    fn from(value: &ShutdownCompleteChunkRef<'_>) -> Self {
        ShutdownCompleteChunk {
            flags: value.flags(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShutdownCompleteChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> ShutdownCompleteChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ShutdownCompleteChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if chunk_type != CHUNK_TYPE_SHUTDOWN_COMPLETE {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "invalid Chunk Type field in SCTP SHUTDOWN COMPLETE chunk (must be equal to 14)",
                    });
                }

                if len != 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "invalid length in SCTP SHUTDOWN COMPLETE chunk (must be equal to 4)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - 4),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP SHUTDOWN COMPLETE chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP SHUTDOWN COMPLETE chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> ShutdownCompleteFlags {
        ShutdownCompleteFlags::from_bits_truncate(self.data[1])
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct ShutdownCompleteFlags: u8 {
        const T = 0b00000001;
    }
}

/// A chunk containing a Chunk Type value that does not match any chunk type defined in RFC 4960.
///
/// ## Packet Format
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |   Chunk Type  |  Chunk Flags  |          Chunk Length         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 Z                          Chunk Value                          Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug)]
pub struct UnknownChunk {
    chunk_type: u8,
    flags: u8,
    value: Vec<u8>,
}

impl UnknownChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(UnknownChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        UnknownChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.chunk_type
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn set_flags_raw(&mut self, flags: u8) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> usize {
        self.value.len() + 4
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    #[inline]
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    #[inline]
    pub fn value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.value
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) -> Result<(), SerializationError> {
        bytes.push(self.chunk_type);
        bytes.push(self.flags);
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(Sctp::name()))?
                .to_be_bytes(),
        );
        bytes.extend(&self.value);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

impl From<UnknownChunkRef<'_>> for UnknownChunk {
    #[inline]
    fn from(value: UnknownChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&UnknownChunkRef<'_>> for UnknownChunk {
    #[inline]
    fn from(value: &UnknownChunkRef<'_>) -> Self {
        UnknownChunk {
            chunk_type: value.chunk_type(),
            flags: value.flags_raw(),
            value: Vec::from(value.value()),
        }
    }
}

/// A chunk containing a Chunk Type value that does not match any chunk type defined in RFC 4960.
///
/// ## Packet Format
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |   Chunk Type  |  Chunk Flags  |          Chunk Length         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 Z                          Chunk Value                          Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug)]
pub struct UnknownChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> UnknownChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        UnknownChunkRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(len_arr) => {
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "insufficient bytes in SCTP <unknown> chunk for header/Value field",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason:
                            "invalid length in SCTP <unknown> chunk (must be at least 4 bytes long)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason: "invalid nonzero padding values at end of SCTP <unknown> chunk",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of SCTP <unknown> chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in SCTP <unknown> chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        self.data[1]
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        &self.data[4..self.unpadded_len() as usize]
    }
}

/// An SCTP DATA chunk.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |    Type (0)   | Reserved|U|B|E|             Length            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |               Transmission Sequence Number (TSN)              |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |           Stream ID           |  Stream Sequence Number (SSN) |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                  Payload Protocol Identifier                  |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 Z                           User Data                           Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(SctpDataChunkMetadata)]
#[ref_type(SctpDataChunkRef)]
pub struct SctpDataChunk {
    flags: DataChunkFlags,
    tsn: u32,
    stream_id: u16,
    stream_seq: u16,
    proto_id: u32,
    payload: Option<Box<dyn LayerObject>>,
}

impl SctpDataChunk {
    /// Converts the given bytes into a [`struct@SctpDataChunk`] instance, returning an error if the bytes are
    /// not well-formed.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts the given bytes into a [`struct@SctpDataChunk`] instance without validating the bytes.
    ///
    /// # Panics
    ///
    /// The following method may panic if the bytes being passed in do not represent a well-formed
    /// DATA chunk (i.e. if a call to [`struct@SctpDataChunk::validate()`] would return an error).
    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(SctpDataChunkRef::from_bytes_unchecked(bytes))
    }

    /// Validates the given bytes against the expected structure and syntactic values of a
    /// DATA chunk. If the bytes represent a well-formed DATA chunk, this method will return
    /// `Ok()`; otherwise, it will return a [`ValidationError`] indicating what part of the
    /// chunk was invalid.
    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        SctpDataChunkRef::validate(bytes)
    }

    /// The Type field of the DATA chunk.
    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_DATA
    }

    /// The flags of the DATA chunk.
    #[inline]
    pub fn flags(&self) -> DataChunkFlags {
        self.flags
    }

    /// Sets the flags of the DATA chunk.
    #[inline]
    pub fn set_flags(&mut self, flags: DataChunkFlags) {
        self.flags = flags;
    }

    /// The length (without padding) of the DATA chunk.
    #[inline]
    pub fn unpadded_len(&self) -> usize {
        // TODO: chunk min length is 17. Enforce at to_bytes()
        16 + match &self.payload {
            Some(p) => p.len(),
            None => 0,
        }
    }

    /// The length (including padding) of the DATA chunk.
    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len())
    }

    /// The Transmission Sequence Number (TSN) of the DATA chunk.
    #[inline]
    pub fn tsn(&self) -> u32 {
        self.tsn
    }

    /// Sets the Transmission Sequence Number (TSN) of the DATA chunk.
    #[inline]
    pub fn set_tsn(&mut self, tsn: u32) {
        self.tsn = tsn;
    }

    /// The Stream Identifier of the DATA chunk.
    #[inline]
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Sets the Stream Identifier of the DATA chunk.
    #[inline]
    pub fn set_stream_id(&mut self, stream_id: u16) {
        self.stream_id = stream_id;
    }

    /// The Stream Sequence Number (SSN) of the DATA chunk.
    #[inline]
    pub fn stream_seq(&self) -> u16 {
        self.stream_seq
    }

    /// Sets the Stream Sequence Number (SSN) of the DATA chunk.
    #[inline]
    pub fn set_stream_seq(&mut self, stream_seq: u16) {
        self.stream_seq = stream_seq;
    }

    /// The Payload Protocol Identifier (PPID) of the DATA chunk.
    #[inline]
    pub fn proto_id(&self) -> u32 {
        self.proto_id
    }

    /// Sets the Payload Protocol Identifier (PPID) of the DATA chunk.
    #[inline]
    pub fn set_proto_id(&mut self, proto_id: u32) {
        self.proto_id = proto_id;
    }
}

impl LayerLength for SctpDataChunk {
    #[inline]
    fn len(&self) -> usize {
        16 + match &self.payload {
            Some(p) => utils::padded_length::<4>(p.len()),
            None => 0,
        }
    }
}

#[allow(unused_variables)]
impl LayerObject for SctpDataChunk {
    fn can_add_payload_default(&self, payload: &dyn LayerObject) -> bool {
        true // SCTP supports arbitrary payloads
    }

    #[inline]
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload = Some(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        match &self.payload {
            Some(p) => slice::from_ref(p),
            None => &[],
        }
    }

    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        match &mut self.payload {
            Some(p) => slice::from_mut(p),
            None => &mut [],
        }
    }

    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>> {
        if index == 0 {
            let mut ret = None;
            mem::swap(&mut ret, &mut self.payload);
            ret
        } else {
            None
        }
    }
}

impl ToBytes for SctpDataChunk {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        let start = bytes.len();
        bytes.push(0); // DATA Type = 0
        bytes.push(self.flags.bits());
        bytes.extend(
            u16::try_from(self.unpadded_len())
                .map_err(|_| SerializationError::length_encoding(SctpDataChunk::name()))?
                .to_be_bytes(),
        );
        bytes.extend(self.tsn.to_be_bytes());
        bytes.extend(self.stream_id.to_be_bytes());
        bytes.extend(self.stream_seq.to_be_bytes());
        bytes.extend(self.proto_id.to_be_bytes());
        if let Some(p) = &self.payload {
            p.to_bytes_checksummed(bytes, Some((SctpDataChunk::layer_id(), start)))?;
        }
        bytes.extend(core::iter::repeat(0).take(self.len() - self.unpadded_len()));

        Ok(())
    }
}

#[doc(hidden)]
impl FromBytesCurrent for SctpDataChunk {
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let data = SctpDataChunkRef::from_bytes_unchecked(bytes);
        SctpDataChunk {
            flags: data.flags(),
            tsn: data.tsn(),
            stream_id: data.stream_id(),
            stream_seq: data.stream_seq(),
            proto_id: data.proto_id(),
            payload: None,
        }
    }

    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        let data = SctpDataChunkRef::from_bytes_unchecked(bytes);
        self.payload = Some(Box::new(Raw::from_bytes_unchecked(data.user_data())));
    }
}

/// An SCTP DATA chunk.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |    Type (0)   |  Res  |I|U|B|E|             Length            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |               Transmission Sequence Number (TSN)              |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |           Stream ID           |  Stream Sequence Number (SSN) |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                  Payload Protocol Identifier                  |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 Z                           User Data                           Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(SctpDataChunk)]
#[metadata_type(SctpDataChunkMetadata)]
pub struct SctpDataChunkRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> SctpDataChunkRef<'a> {
    /// Converts the given bytes into a [`struct@SctpDataChunkRef`] instance, returning an error if they are
    /// not well-formed.
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts the given bytes into a [`struct@SctpDataChunkRef`] instance without validating the bytes.
    ///
    /// # Panics
    ///
    /// The following method may panic or cause a panic at some future method invocation on the
    /// instance if the bytes being passed in do not represent a well-formed DATA chunk (i.e. if a
    /// call to [`validate()`](Validate::validate()) would return an error).
    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        SctpDataChunkRef { data: bytes }
    }

    /// The Type field of the DATA chunk.
    #[inline]
    pub fn chunk_type(&self) -> u8 {
        self.data[0]
    }

    /// The flags of the DATA chunk.
    #[inline]
    pub fn flags(&self) -> DataChunkFlags {
        DataChunkFlags::from_bits_truncate(self.data[1])
    }

    /// The length (without padding) of the DATA chunk.
    #[inline]
    pub fn chunk_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    /// The length (including padding) of the DATA chunk.
    #[inline]
    pub fn chunk_len_padded(&self) -> usize {
        utils::padded_length::<4>(self.chunk_len() as usize)
    }

    /// The Transmission Sequence Number (TSN) of the DATA chunk.
    #[inline]
    pub fn tsn(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    /// Sets the Stream Identifier of the DATA chunk.
    #[inline]
    pub fn stream_id(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    /// The Stream Sequence Number (SSN) of the DATA chunk.
    #[inline]
    pub fn stream_seq(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 10).unwrap())
    }

    /// The Payload Protocol Identifier (PPID) of the DATA chunk.
    #[inline]
    pub fn proto_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    /// The User Data payload of the DATA chunk.
    #[inline]
    pub fn user_data(&self) -> &[u8] {
        self.data.get(16..self.chunk_len() as usize).unwrap()
    }

    /// The padding at the end of the DATA chunk.
    #[inline]
    pub fn padding(&self) -> &[u8] {
        &self.data[self.chunk_len() as usize..self.chunk_len_padded()]
    }
}

impl LayerOffset for SctpDataChunkRef<'_> {
    #[inline]
    fn payload_byte_index_default(bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        if bytes.len() > 16 {
            Some(16)
        } else {
            None
        }
    }
}

impl Validate for SctpDataChunkRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let len = match utils::to_array(curr_layer, 2) {
            None => {
                return Err(ValidationError {
                    layer: SctpDataChunk::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason: "SCTP DATA chunk must have a minimum of 16 bytes for its header",
                })
            }
            Some(arr) => u16::from_be_bytes(arr) as usize,
        };

        let payload_type = curr_layer[0]; // This won't panic because we've already retrieved bytes at index 2
        if payload_type != 0 {
            return Err(ValidationError {
                layer: SctpDataChunk::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid Chunk Type field in SCTP DATA chunk (must be equal to 0)",
            });
        }

        if len < 17 {
            return Err(ValidationError {
                layer: SctpDataChunk::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "packet length field had invalid value (insufficient length to cover packet header and at least one byte of data) for SCTP DATA chunk",
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let data = SctpDataChunkRef::from_bytes_unchecked(curr_layer);
        let padded_len = data.chunk_len_padded();
        if padded_len > curr_layer.len() {
            return Err(ValidationError {
                layer: SctpDataChunk::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes for User Data portion of SCTP DATA chunk",
            });
        }

        let len = data.chunk_len() as usize;

        // The payload is considered valid by default, since we count it as a [`Raw`] packet type.

        for b in curr_layer.iter().take(padded_len).skip(len) {
            if *b != 0 {
                return Err(ValidationError {
                    layer: SctpDataChunk::name(),
                    class: ValidationErrorClass::UnusualPadding,
                    #[cfg(feature = "error_string")]
                    reason: "padding at end of SCTP DATA chunk had a non-zero value",
                });
            }
        }

        if padded_len < curr_layer.len() {
            Err(ValidationError {
                layer: SctpDataChunk::name(),
                class: ValidationErrorClass::ExcessBytes(curr_layer.len() - padded_len),
                #[cfg(feature = "error_string")]
                reason: "SCTP DATA chunk had additional trailing bytes at the end of its data",
            })
        } else {
            Ok(())
        }
    }
}

bitflags! {
    /// The flags of a DATA chunk.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct DataChunkFlags: u8 {
        const R1 = 0b10000000;
        const R2 = 0b01000000;
        const R3 = 0b00100000;
        const R4 = 0b00010000;
        const IMMEDIATE = 0b00001000;
        const UNORDERED = 0b00000100;
        const BEGIN_FRAGMENT = 0b00000010;
        const END_FRAGMENT = 0b00000001;
    }
}

impl From<u8> for DataChunkFlags {
    fn from(value: u8) -> Self {
        DataChunkFlags::from_bits_truncate(value)
    }
}
