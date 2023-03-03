// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>

use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::layers::*;
use crate::utils;
use core::iter::Iterator;

use pkts_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use core::{cmp, iter};

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

// DATA Chunk flags
const DATA_CHUNK_FLAGS_IMMEDIATE_BIT: u8 = 0b_0000_1000;
const DATA_CHUNK_FLAGS_UNORDERED_BIT: u8 = 0b_0000_0100;
const DATA_CHUNK_FLAGS_BEGINNING_BIT: u8 = 0b_0000_0010;
const DATA_CHUNK_FLAGS_ENDING_BIT: u8 = 0b_0000_0001;

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

// ABORT Chunk flags
const ABORT_FLAGS_T_BIT: u8 = 0b_0000_0001;

// SHUTDOWN COMPLETE Chunk flags
const SHUTDOWN_COMPLETE_FLAGS_T_BIT: u8 = 0b_0000_0001;

///
///
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(TcpMetadata)]
#[ref_type(SctpRef)]
pub struct Sctp {
    sport: u16,
    dport: u16,
    verify_tag: u32,
    chksum: u32,
    control_chunks: Vec<ControlChunk>,
    payload_chunks: Vec<DataChunk>,
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

    /// The Verification Tag assigned to the packet.
    ///
    /// The recipient of an SCTP packet uses the Verification Tag to validate the packet's source.
    #[inline]
    pub fn verify_tag(&self) -> u32 {
        self.verify_tag
    }

    /// Sets the Verification Tag of the packet to the given value.
    #[inline]
    pub fn set_verify_tag(&mut self, verify_tag: u32) {
        self.verify_tag = verify_tag;
    }

    /// The CRC32c Checksum of the SCTP packet.
    ///
    /// By default, the checksum of an [`Sctp`] packet is not recalculated when its fields are modified.
    /// To make sure that a correct checksum is sent in a packet, use the `generate_checksum()` method
    /// before converting a packet into its corresponding bytes.
    #[inline]
    pub fn chksum(&self) -> u32 {
        self.chksum
    }

    /// Sets the Checksum of the packet to the given value.
    #[inline]
    pub fn set_chksum(&mut self, chksum: u32) {
        self.chksum = chksum;
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
    /// - [`ControlChunk::Shutdown`] and [`ControlChunk::ShutdownAck`] must not be bundled with any [`PayloadChunk`].
    /// This is because the Shutdown is evaulated first, and data cannot be sent after a Shutdown message.
    ///
    /// - [`ControlChunk::Init`], [`ControlChunk::InitAck`], and [`ControlChunk::ShutdownComplete`] must not be bundled
    /// with any other control or payload chunks.
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn control_chunks(&self) -> &Vec<ControlChunk> {
        &self.control_chunks
    }

    /// The mutable list of Control Chunks contained within the packet.
    ///
    /// These chunks can be arranged in any order. Control chunks are evaluated by the peer in the
    /// same order that they are sent. All control chunks are ordered before payload chunks. Some
    /// control chunks have restrictions on what other chunks they can be bundled in the same message with:
    ///
    /// - [`ControlChunk::Shutdown`] and [`ControlChunk::ShutdownAck`] must not be bundled with any [`PayloadChunk`].
    /// This is because the Shutdown is evaulated first, and data cannot be sent after a Shutdown message.
    ///
    /// - [`ControlChunk::Init`], [`ControlChunk::InitAck`], and [`ControlChunk::ShutdownComplete`] must not be bundled
    /// with any other control or payload chunks.
    ///
    /// Although the `rscap` library enforces these constraints where it can, this particular API may be used in such a way that
    /// they are violated. It is the responsibility of the caller of this method to ensure that the above constraints are upheld.
    #[inline]
    pub fn control_chunks_mut(&mut self) -> &mut Vec<ControlChunk> {
        &mut self.control_chunks
    }

    /// The list of Payload Data (DATA) Chunks contained within the packet.
    ///
    /// These chunks are ordered by increasing TSN value, and are always placed after any control chunks in the packet.
    /// A packet MUST NOT have any Payload Data Chunks when any of the below Control Chunks are present:
    ///
    /// - [`ControlChunk::Shutdown`]
    /// - [`ControlChunk::ShutdownAck`]
    /// - [`ControlChunk::Init`]
    /// - [`ControlChunk::InitAck`]
    /// - [`ControlChunk::ShutdownComplete`]
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn payload_chunks(&self) -> &Vec<DataChunk> {
        &self.payload_chunks
    }

    /// The list of Payload Data (DATA) Chunks contained within the packet.
    ///
    /// Payload Data chunks are ordered by increasing TSN value, and are always placed after any Control Chunks in the packet.
    /// A packet MUST NOT have any Payload Data Chunks when any of the below Control Chunks are present:
    ///
    /// - [`ControlChunk::Shutdown`]
    /// - [`ControlChunk::ShutdownAck`]
    /// - [`ControlChunk::Init`]
    /// - [`ControlChunk::InitAck`]
    /// - [`ControlChunk::ShutdownComplete`]
    ///
    /// Although the `rscap` library enforces these constraints where it can, this particular API may be used in such a way that
    /// they are violated. It is the responsibility of the caller of this method to ensure that the above constraints are upheld.
    #[inline]
    pub fn payload_chunks_mut(&mut self) -> &mut Vec<DataChunk> {
        &mut self.payload_chunks
    }
}

impl CanSetPayload for Sctp {
    #[inline]
    fn can_set_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        true // SCTP can handle arbitrary protocols
    }
}

impl FromBytesCurrent for Sctp {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let sctp = SctpRef::from_bytes_unchecked(bytes);

        let mut control_chunks = Vec::new();
        let mut control_iter = sctp.control_chunks();
        while let Some(chunk) = control_iter.next() {
            control_chunks.push(chunk.into());
        }

        let mut payload_chunks = Vec::new();
        let mut payload_iter = sctp.payload_chunks();
        while let Some(chunk) = payload_iter.next() {
            payload_chunks.push(chunk.into());
        }

        Sctp {
            sport: sctp.sport(),
            dport: sctp.dport(),
            verify_tag: sctp.verify_tag(),
            chksum: sctp.chksum(),
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
    /// Returns a reference to the first payload chunk in the [`Sctp`] packet, if such a chunk exists.
    #[inline]
    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        self.payload_chunks.first().map(|c| c.payload.as_ref())
    }

    /// Returns a mutable reference to the first payload chunk in the [`Sctp`] packet, if such a chunk exists.
    #[inline]
    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        self.payload_chunks.first_mut().map(|c| c.payload.as_mut())
    }

    /// Replaces the first payload chunk in the [`Sctp`] packet with the given payload, or adds a new payload
    /// chunk with all associated fields set to 0 if there were none.
    #[inline]
    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        if let Some(payload_chunk) = self.payload_chunks.first_mut() {
            payload_chunk.payload = payload
        } else {
            self.payload_chunks.push(DataChunk {
                flags: DataChunkFlags { data: 0 },
                tsn: 0,
                stream_id: 0,
                stream_seq: 0,
                proto_id: 0,
                payload,
            })
        }
    }

    /// Determines whether one or more payload chunks exist in the [`struct@Sctp`] packet.
    #[inline]
    fn has_payload(&self) -> bool {
        !self.payload_chunks.is_empty()
    }

    /// Removes and returns the first payload chunk from the [`struct@Sctp`] packet.
    #[inline]
    fn remove_payload(&mut self) -> Box<dyn LayerObject> {
        self.payload_chunks
            .pop()
            .map(|c| c.payload)
            .expect("attempted to remove payload where none existed in SCTP packet")
    }
}

impl ToBytes for Sctp {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.sport.to_be_bytes());
        bytes.extend(self.dport.to_be_bytes());
        bytes.extend(self.verify_tag.to_be_bytes());
        bytes.extend(self.chksum.to_be_bytes());
        for chunk in &self.control_chunks {
            chunk.to_bytes_extended(bytes);
        }

        for chunk in &self.payload_chunks {
            chunk.to_bytes_extended(bytes);
        }
    }
}

///
///
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
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in SctpRef to retrieve Source Port field"),
        )
    }

    /// The SCTP port number to which the packet is destined (i.e. Destination Port).
    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SctpRef to retrieve Destination Port field"),
        )
    }

    /// The Verification Tag assigned to the packet.
    ///
    /// The recipient of an SCTP packet uses the Verification Tag to validate the packet's source.
    #[inline]
    pub fn verify_tag(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SctpRef to retrieve Verify Tag field"),
        )
    }

    /// The CRC32c Checksum of the SCTP packet.
    ///
    /// By default, the checksum of an [`Sctp`] packet is not recalculated when its fields are modified.
    /// To make sure that a correct checksum is sent in a packet, use the `generate_checksum()` method
    /// before converting a packet into its corresponding bytes.
    #[inline]
    pub fn chksum(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SctpRef to retrieve Verify Checksum field"),
        )
    }

    /// An iterator over the list of Control Chunks contained within the packet.
    ///
    /// These chunks can be arranged in any order. Control chunks are evaluated by the peer in the
    /// same order that they are sent. All control chunks are ordered before payload chunks. Some
    /// control chunks have restrictions on what other chunks they can be bundled in the same message with:
    ///
    /// - [`ControlChunk::Shutdown`] and [`ControlChunk::ShutdownAck`] must not be bundled with any [`PayloadChunk`].
    /// This is because the Shutdown is evaulated first, and data cannot be sent after a Shutdown message.
    ///
    /// - [`ControlChunk::Init`], [`ControlChunk::InitAck`], and [`ControlChunk::ShutdownComplete`] must not be bundled
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
    /// - [`ControlChunk::Shutdown`]
    /// - [`ControlChunk::ShutdownAck`]
    /// - [`ControlChunk::Init`]
    /// - [`ControlChunk::InitAck`]
    /// - [`ControlChunk::ShutdownComplete`]
    ///
    /// These constraints will be enforced by this library by default.
    #[inline]
    pub fn payload_chunks(&self) -> PayloadChunksIterRef<'a> {
        PayloadChunksIterRef {
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
        ChunksIterRef { bytes: &self.data[12..] }
    }
}

impl<'a> FromBytesRef<'a> for SctpRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        SctpRef { data: bytes }
    }
}

impl LayerOffset for SctpRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        None // SCTP makes no indiciation of what protocol is used for its payloads
             // If we did need to provide an index, we'll want to provide an end index too...
    }
}

impl Validate for SctpRef<'_> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let mut remaining = match curr_layer.get(12..) {
            Some(rem) => rem,
            None => {
                return Err(ValidationError {
                    layer: Sctp::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
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
                    DataChunk::validate(remaining)
                }
                _ if data_reached => {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
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
                    if let ValidationErrorType::ExcessBytes(l) = e.err_type {
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
                err_type: ValidationErrorType::InvalidValue,
                reason: "multiple chunks bundled in one SCTP message where only one was allowed (chunk types INIT, INIT_ACK and SHUTDOWN_COMPLETE cannot be bundled with other chunks)",
            });
        }

        if shutdown && data_reached {
            return Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InvalidValue,
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

impl<'a> From<&'a SctpMut<'a>> for SctpRef<'a> {
    fn from(value: &'a SctpMut<'a>) -> Self {
        SctpRef {
            data: &value.data[..value.len],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ControlChunksIterRef<'a> {
    chunk_iter: ChunksIterRef<'a>,
}

impl<'a> Iterator for ControlChunksIterRef<'a> {
    type Item = ControlChunkRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(chunk) = self.chunk_iter.next() {
            match chunk {
                ChunkRef::Control(c) => return Some(c),
                _ => ()
            }
        }
        return None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PayloadChunksIterRef<'a> {
    chunk_iter: ChunksIterRef<'a>,
}

impl<'a> Iterator for PayloadChunksIterRef<'a> {
    type Item = DataChunkRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(chunk) = self.chunk_iter.next() {
            match chunk {
                ChunkRef::Payload(c) => return Some(c),
                _ => ()
            }
        }
        return None
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ChunkRef<'a> {
    Control(ControlChunkRef<'a>),
    Payload(DataChunkRef<'a>),
}

#[derive(Clone, Copy, Debug)]
pub struct ChunksIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for ChunksIterRef<'a> {
    type Item = ChunkRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (chunk_type, unpadded_len) = match (
            self.bytes.first(),
            utils::get_array::<2>(self.bytes, 2),
        ) {
            (Some(&t), Some(&l)) => (t, u16::from_be_bytes(l)),
            _ => return None,
        };

        /*
        let min_len = match chunk_type {
            CHUNK_TYPE_INIT | CHUNK_TYPE_INIT_ACK => 20,
            CHUNK_TYPE_SACK | CHUNK_TYPE_DATA => 16,
            CHUNK_TYPE_HEARTBEAT
            | CHUNK_TYPE_HEARTBEAT_ACK
            | CHUNK_TYPE_ABORT
            | CHUNK_TYPE_SHUTDOWN
            | CHUNK_TYPE_SHUTDOWN_ACK
            | CHUNK_TYPE_ERROR
            | CHUNK_TYPE_COOKIE_ECHO
            | CHUNK_TYPE_COOKIE_ACK
            | CHUNK_TYPE_SHUTDOWN_COMPLETE => 4,
            _ => 4,
        };
        

        if self.bytes.len() < min_len {
            self.bytes = &[]; // Not needed, but this helps further calls to the iterator to short-circuit
            return None;
        }

        let len = cmp::max(min_len, utils::padded_length::<4>(unpadded_len as usize));
        */

        let len = utils::padded_length::<4>(unpadded_len as usize);
        match (self.bytes.get(..len), self.bytes.get(len..)) {
            (Some(chunk_bytes), Some(rem)) => {
                self.bytes = rem;
                if chunk_type == CHUNK_TYPE_DATA {
                    Some(ChunkRef::Payload(DataChunkRef::from_bytes_unchecked(
                        chunk_bytes,
                    )))
                } else {
                    Some(ChunkRef::Control(ControlChunkRef::from_bytes_unchecked(
                        chunk_bytes,
                    )))
                }
            }
            _ => {
                panic!("insufficient bytes for ChunkRef in iterator.");
                /*
                // Just take whatever remaining bytes we can for the payload
                let chunk_bytes = self.bytes;
                self.bytes = &[];
                if chunk_type == CHUNK_TYPE_DATA {
                    Some(ChunkRef::Payload(DataChunkRef::from_bytes_unchecked(
                        chunk_bytes,
                    )))
                } else {
                    Some(ChunkRef::Control(ControlChunkRef::from_bytes_unchecked(
                        chunk_bytes,
                    )))
                }
                */
            }
        }
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[ref_type(SctpRef)]
#[owned_type(Sctp)]
#[metadata_type(SctpMetadata)]
pub struct SctpMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
}

impl<'a> SctpMut<'a> {
    // TODO: implement
}

impl<'a> FromBytesMut<'a> for SctpMut<'a> {
    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self {
        SctpMut {
            data: bytes,
            len: length,
        }
    }
}

// =============================================================================
//                             Non-Layer Components
// =============================================================================

#[derive(Clone, Debug)]
pub enum ControlChunk {
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

impl ControlChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(ControlChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        ControlChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        match self {
            ControlChunk::Init(c) => c.chunk_type(),
            ControlChunk::InitAck(c) => c.chunk_type(),
            ControlChunk::Sack(c) => c.chunk_type(),
            ControlChunk::Heartbeat(c) => c.chunk_type(),
            ControlChunk::HeartbeatAck(c) => c.chunk_type(),
            ControlChunk::Abort(c) => c.chunk_type(),
            ControlChunk::Shutdown(c) => c.chunk_type(),
            ControlChunk::ShutdownAck(c) => c.chunk_type(),
            ControlChunk::Error(c) => c.chunk_type(),
            ControlChunk::CookieEcho(c) => c.chunk_type(),
            ControlChunk::CookieAck(c) => c.chunk_type(),
            ControlChunk::ShutdownComplete(c) => c.chunk_type(),
            ControlChunk::Unknown(c) => c.chunk_type(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            ControlChunk::Init(c) => c.len(),
            ControlChunk::InitAck(c) => c.len(),
            ControlChunk::Sack(c) => c.len(),
            ControlChunk::Heartbeat(c) => c.len(),
            ControlChunk::HeartbeatAck(c) => c.len(),
            ControlChunk::Abort(c) => c.len(),
            ControlChunk::Shutdown(c) => c.len(),
            ControlChunk::ShutdownAck(c) => c.len(),
            ControlChunk::Error(c) => c.len(),
            ControlChunk::CookieEcho(c) => c.len(),
            ControlChunk::CookieAck(c) => c.len(),
            ControlChunk::ShutdownComplete(c) => c.len(),
            ControlChunk::Unknown(c) => c.len(),
        }
    }
}

impl ToBytes for ControlChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        match self {
            ControlChunk::Init(c) => c.to_bytes_extended(bytes),
            ControlChunk::InitAck(c) => c.to_bytes_extended(bytes),
            ControlChunk::Sack(c) => c.to_bytes_extended(bytes),
            ControlChunk::Heartbeat(c) => c.to_bytes_extended(bytes),
            ControlChunk::HeartbeatAck(c) => c.to_bytes_extended(bytes),
            ControlChunk::Abort(c) => c.to_bytes_extended(bytes),
            ControlChunk::Shutdown(c) => c.to_bytes_extended(bytes),
            ControlChunk::ShutdownAck(c) => c.to_bytes_extended(bytes),
            ControlChunk::Error(c) => c.to_bytes_extended(bytes),
            ControlChunk::CookieEcho(c) => c.to_bytes_extended(bytes),
            ControlChunk::CookieAck(c) => c.to_bytes_extended(bytes),
            ControlChunk::ShutdownComplete(c) => c.to_bytes_extended(bytes),
            ControlChunk::Unknown(c) => c.to_bytes_extended(bytes),
        }
    }
}

impl From<ControlChunkRef<'_>> for ControlChunk {
    #[inline]
    fn from(value: ControlChunkRef<'_>) -> Self {
        ControlChunk::from(&value)
    }
}

impl From<&ControlChunkRef<'_>> for ControlChunk {
    #[inline]
    fn from(value: &ControlChunkRef<'_>) -> Self {
        match value {
            ControlChunkRef::Init(c) => ControlChunk::Init(c.into()),
            ControlChunkRef::InitAck(c) => ControlChunk::InitAck(c.into()),
            ControlChunkRef::Sack(c) => ControlChunk::Sack(c.into()),
            ControlChunkRef::Heartbeat(c) => ControlChunk::Heartbeat(c.into()),
            ControlChunkRef::HeartbeatAck(c) => ControlChunk::HeartbeatAck(c.into()),
            ControlChunkRef::Abort(c) => ControlChunk::Abort(c.into()),
            ControlChunkRef::Shutdown(c) => ControlChunk::Shutdown(c.into()),
            ControlChunkRef::ShutdownAck(c) => ControlChunk::ShutdownAck(c.into()),
            ControlChunkRef::Error(c) => ControlChunk::Error(c.into()),
            ControlChunkRef::CookieEcho(c) => ControlChunk::CookieEcho(c.into()),
            ControlChunkRef::CookieAck(c) => ControlChunk::CookieAck(c.into()),
            ControlChunkRef::ShutdownComplete(c) => ControlChunk::ShutdownComplete(c.into()),
            ControlChunkRef::Unknown(c) => ControlChunk::Unknown(c.into()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ControlChunkRef<'a> {
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

impl<'a> ControlChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        let chunk_type = *bytes.first().expect(
            "insufficient bytes to create SCTP Control chunk from bytes (Chunk Type field missing)",
        );
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let chunk_type = *bytes
            .first()
            .expect("insufficient bytes in SCTP Control Chunk to extract Chunk Type field");
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

///
///
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
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(InitChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        InitChunkRef::validate(bytes)
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        CHUNK_TYPE_INIT
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(20 + self.options.iter().map(|o| o.len()).sum::<usize>())
            .expect("too many bytes in SCTP INIT chunk to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        20 + self.options.iter().map(|o| o.len()).sum::<usize>()
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
    pub fn options(&self) -> &Vec<InitOption> {
        &self.options
    }

    #[inline]
    pub fn options_mut(&mut self) -> &mut Vec<InitOption> {
        &mut self.options
    }
}

impl ToBytes for InitChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_INIT);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(self.init_tag.to_be_bytes());
        bytes.extend(self.a_rwnd.to_be_bytes());
        bytes.extend(self.ostreams.to_be_bytes());
        bytes.extend(self.istreams.to_be_bytes());
        bytes.extend(self.init_tsn.to_be_bytes());
        for option in &self.options {
            option.to_bytes_extended(bytes);
        }
        // No padding needed--options are guaranteed to be padded to 4 bytes.
    }
}

impl From<InitChunkRef<'_>> for InitChunk {
    #[inline]
    fn from(value: InitChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitChunkRef<'_>> for InitChunk {
    #[inline]
    fn from(value: &InitChunkRef<'_>) -> Self {
        let mut options = Vec::new();
        let mut iter = value.options_iter();
        while let Some(option) = iter.next() {
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

///
///
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

    #[inline]
    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if bytes.len() < cmp::max(len, 20) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP INIT chunk for header and optional parameters",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP INIT chunk length was not a multiple of 4",
                    });
                }

                if len < 20 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "length field of SCTP INIT chunk was too short to cover entire header",
                    });
                }

                let mut options = &bytes[20..];
                while !options.is_empty() {
                    match InitOption::validate(options) {
                        Err(e) => {
                            if let ValidationErrorType::ExcessBytes(extra) = e.err_type {
                                options = &options[options.len() - extra..];
                            } else {
                                return Err(ValidationError {
                                    layer: Sctp::name(),
                                    err_type: ValidationErrorType::InvalidValue,
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
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP INIT chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP INIT chunk for header Length field",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP INIT chunk to retrieve Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP INIT chunk to retrieve Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP INIT chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn init_tag(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in SCTP INIT chunk to extract Init Tag field"),
        )
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 8)
                .expect("insufficient bytes in SCTP INIT chunk to extract a_rwnd field"),
        )
    }

    #[inline]
    pub fn ostreams(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 12)
                .expect("insufficient bytes in SCTP INIT chunk to extract Outbound Streams field"),
        )
    }

    #[inline]
    pub fn istreams(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 14)
                .expect("insufficient bytes in SCTP INIT chunk to extract Inbound Streams field"),
        )
    }

    #[inline]
    pub fn init_tsn(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in SCTP INIT chunk to extract Initial TSN field"),
        )
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

    #[inline]
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

    #[inline]
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

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        match self {
            Self::Ipv4Address(_) => 8,
            Self::Ipv6Address(_) => 20,
            Self::CookiePreservative(_) => 8,
            Self::HostnameAddress(h) => (4 + h.len()).try_into().expect("too many bytes in SCTP INIT chunk Hostname Address option to represent in a 16-bit Length field"),
            Self::SupportedAddressTypes(addr_types) => (4 + addr_types.len()).try_into().expect("too many bytes in SCTP INIT chunk Supported Address Types option to represent in a 16-bit Length field"),
            Self::Unknown(_,d) => (4 + d.len()).try_into().expect("too many bytes in SCTP INIT chunk <unknown> option to represent in a 16-bit Length field"),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }
}

impl ToBytes for InitOption {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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
                let unpadded_len = u16::try_from(4 + addr.len()).expect("too many bytes in SCTP INIT chunk Host Name Address option to represent in a 16-bit Length field");
                bytes.extend(INIT_OPT_HOSTNAME_ADDR.to_be_bytes());
                bytes.extend(unpadded_len.to_be_bytes());
                bytes.extend(addr);
                bytes.extend(iter::repeat(0).take(
                    utils::padded_length::<4>(unpadded_len as usize) - unpadded_len as usize,
                ));
            }
            Self::SupportedAddressTypes(addr_types) => {
                let unpadded_len = u16::try_from(4 + (2 * addr_types.len())).expect("too many bytes in SCTP INIT chunk Supported Address Types option to represent in a 16-bit length field");
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
                let unpadded_len = u16::try_from(4 + data.len()).expect("too many bytes in SCTP INIT chunk <unknown> option to represent in a 16-bit length field");
                bytes.extend(opt_type.to_be_bytes());
                bytes.extend(unpadded_len.to_be_bytes());
                bytes.extend(data);
                bytes.extend(iter::repeat(0).take(
                    utils::padded_length::<4>(unpadded_len as usize) - unpadded_len as usize,
                ));
            }
        }
    }
}

impl From<InitOptionRef<'_>> for InitOption {
    #[inline]
    fn from(value: InitOptionRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitOptionRef<'_>> for InitOption {
    #[inline]
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

    #[inline]
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
                        err_type: ValidationErrorType::InsufficientBytes,
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
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "SCTP INIT option Length field didn't match expected length based on Option Type",
                        });
                    }
                }

                if opt_type == INIT_OPT_SUPP_ADDR_TYPES && unpadded_len % 2 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP INIT option payload had missing or trailing byte for Supported Address Types option",
                    });
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP INIT option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP INIT option for header",
            }),
        }
    }

    #[inline]
    pub fn opt_type(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in SCTP option to extract Option Type field"),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP option to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn payload(&self) -> InitOptionPayloadRef<'a> {
        match self.opt_type() {
            INIT_OPT_IPV4_ADDRESS => InitOptionPayloadRef::Ipv4Address(u32::from_be_bytes(utils::to_array(self.data, 4).expect("insufficent bytes in SCTP INIT Option to extract IPv4 Address payload"))),
            INIT_OPT_IPV6_ADDRESS => InitOptionPayloadRef::Ipv6Address(u128::from_be_bytes(utils::to_array::<16>(self.data, 4).expect("insufficent bytes in SCTP INIT Option to extract IPv6 Address payload"))),
            INIT_OPT_COOKIE_PRESERVATIVE => InitOptionPayloadRef::CookiePreservative(u32::from_be_bytes(utils::to_array(self.data, 4).expect("insufficent bytes in SCTP INIT Option to extract Cookie Preservative payload"))),
            INIT_OPT_HOSTNAME_ADDR => InitOptionPayloadRef::HostnameAddress(self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid length field in SCTP INIT Option (Hostname Address)") as usize).expect("insufficent bytes in SCTP INIT Option to extract Hostname Address payload")),
            INIT_OPT_SUPP_ADDR_TYPES => InitOptionPayloadRef::SupportedAddressTypes(self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid length field in SCTP INIT Option (Supported Address Types)") as usize).expect("insufficent bytes in SCTP INIT Option to extract Supported Address Types payload")),
            _ => InitOptionPayloadRef::Unknown(self.opt_type(), self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid length field in SCTP INIT Option (unknown option type)") as usize).expect("insufficent bytes in SCTP INIT Option to extract <unknown type> payload"))
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(20 + self.options.iter().map(|o| o.len()).sum::<usize>()).expect("too many bytes in SCTP INIT ACK chunk Options field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
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
}

impl ToBytes for InitAckChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_INIT_ACK);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(self.init_tag.to_be_bytes());
        bytes.extend(self.a_rwnd.to_be_bytes());
        bytes.extend(self.ostreams.to_be_bytes());
        bytes.extend(self.istreams.to_be_bytes());
        bytes.extend(self.init_tsn.to_be_bytes());
        for option in &self.options {
            option.to_bytes_extended(bytes);
        }
    }
}

impl From<InitAckChunkRef<'_>> for InitAckChunk {
    #[inline]
    fn from(value: InitAckChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitAckChunkRef<'_>> for InitAckChunk {
    #[inline]
    fn from(value: &InitAckChunkRef<'_>) -> Self {
        let mut options = Vec::new();
        let mut iter = value.options_iter();
        while let Some(option) = iter.next() {
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

    #[inline]
    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if bytes.len() < cmp::max(len, 20) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP INIT ACK chunk for header and optional parameters",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP INIT ACK chunk length was not a multiple of 4",
                    });
                }

                if len < 20 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "length field of SCTP INIT ACK chunk was too short for header",
                    });
                }

                let mut options = &bytes[20..];
                while !options.is_empty() {
                    match InitAckOption::validate(options) {
                        Err(e) => {
                            if let ValidationErrorType::ExcessBytes(extra) = e.err_type {
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
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP INIT ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP INIT ACK chunk for header Length field",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP INIT ACK chunk to retrieve Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP INIT ACK chunk to retrieve Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP INIT ACK chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn init_tag(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in SCTP INIT ACK chunk to extract Init Tag field"),
        )
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 8)
                .expect("insufficient bytes in SCTP INIT ACK chunk to extract a_rwnd field"),
        )
    }

    #[inline]
    pub fn ostreams(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 12).expect(
                "insufficient bytes in SCTP INIT ACK chunk to extract Outbound Streams field",
            ),
        )
    }

    #[inline]
    pub fn istreams(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 14).expect(
                "insufficient bytes in SCTP INIT ACK chunk to extract Inbound Streams field",
            ),
        )
    }

    #[inline]
    pub fn init_tsn(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in SCTP INIT ACK chunk to extract Initial TSN field"),
        )
    }

    #[inline]
    pub fn options_iter(&self) -> InitAckOptionsIterRef<'a> {
        InitAckOptionsIterRef {
            bytes: self
                .data
                .get(20..)
                .expect("insufficient bytes in SCTP INIT ACK chunk for header and options"),
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

    #[inline]
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

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        match self {
            Self::StateCookie(s) => (4 + s.len()).try_into().expect("too many bytes in SCTP INIT ACK State Cookie option to represent in a 16-bit Length field"),
            Self::Ipv4Address(_) => 8,
            Self::Ipv6Address(_) => 20,
            Self::UnrecognizedParameter(p) => p.len().checked_add(4).and_then(|r| r.try_into().ok()).expect("too many bytes in SCTP INIT ACK Unrecognized Parameter option to represent in a 16-bit Length field"),
            // TODO: ^^ what if the parameter in question is between 65532-65535 bytes long? Unlikely, but could affect other implementations
            Self::HostnameAddress(h) => (4 + h.len()).try_into().expect("too many bytes in SCTP INIT ACK Hostname Address option to represent in a 16-bit Length field"),
            Self::Unknown(_, v) => (4 + v.len()).try_into().expect("too many bytes in SCTP INIT ACK <unknown> option to represent in a 16-bit Length field"),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }
}

impl ToBytes for InitAckOption {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        match self {
            InitAckOption::StateCookie(c) => {
                bytes.extend(INIT_ACK_OPT_STATE_COOKIE.to_be_bytes());
                bytes.extend(self.unpadded_len().to_be_bytes());
                bytes.extend(c);
                bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
            }
            InitAckOption::Ipv4Address(ipv4) => {
                bytes.extend(INIT_ACK_OPT_IPV4_ADDRESS.to_be_bytes());
                bytes.extend(self.unpadded_len().to_be_bytes());
                bytes.extend(ipv4.to_be_bytes());
            }
            InitAckOption::Ipv6Address(ipv6) => {
                bytes.extend(INIT_ACK_OPT_IPV6_ADDRESS.to_be_bytes());
                bytes.extend(self.unpadded_len().to_be_bytes());
                bytes.extend(ipv6.to_be_bytes());
            }
            InitAckOption::UnrecognizedParameter(param) => {
                bytes.extend(INIT_ACK_OPT_UNRECOGNIZED_PARAM.to_be_bytes());
                bytes.extend(self.unpadded_len().to_be_bytes());
                param.to_bytes_extended(bytes);
                // No need for padding--parameter is type-checked and guaranteed to be padded
            }
            InitAckOption::HostnameAddress(host) => {
                bytes.extend(INIT_ACK_OPT_HOSTNAME_ADDR.to_be_bytes());
                bytes.extend(self.unpadded_len().to_be_bytes());
                bytes.extend(host);
                bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
            }
            InitAckOption::Unknown(t, v) => {
                bytes.extend(t.to_be_bytes());
                bytes.extend(self.unpadded_len().to_be_bytes());
                bytes.extend(v);
                bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
            }
        }
    }
}

impl From<InitAckOptionRef<'_>> for InitAckOption {
    #[inline]
    fn from(value: InitAckOptionRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&InitAckOptionRef<'_>> for InitAckOption {
    #[inline]
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

    #[inline]
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
                        err_type: ValidationErrorType::InsufficientBytes,
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
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "SCTP INIT ACK option Length field didn't match expected length based on Option Type",
                        });
                    }
                } else if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP INIT ACK option Length field too short to cover header",
                    });
                }

                if opt_type == INIT_ACK_OPT_UNRECOGNIZED_PARAM {
                    // Verify that payload is actually a well-formed INIT Option
                    match InitOptionRef::validate(&bytes[4..len]) {
                        Ok(_) => (),
                        Err(_) => return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "SCTP INIT ACK Unrecognized Parameter Option had malformed INIT parameter in its payload",
                        })
                    };
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP INIT ACK Option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP INIT ACK Option for header",
            }),
        }
    }

    #[inline]
    pub fn opt_type(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in SCTP INIT ACK option to extract Option Type field"),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP INIT ACK option to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn payload(&self) -> InitAckOptionPayloadRef<'a> {
        match self.opt_type() {
            INIT_ACK_OPT_IPV4_ADDRESS => InitAckOptionPayloadRef::Ipv4Address(u32::from_be_bytes(utils::to_array(self.data, 4).expect("insufficent bytes in SCTP INIT ACK option to extract IPv4 Address payload"))),
            INIT_ACK_OPT_IPV6_ADDRESS => InitAckOptionPayloadRef::Ipv6Address(u128::from_be_bytes(utils::to_array::<16>(self.data, 4).expect("insufficent bytes in SCTP INIT ACK option to extract IPv6 Address payload"))),
            INIT_ACK_OPT_HOSTNAME_ADDR => InitAckOptionPayloadRef::HostnameAddress(self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid length field in SCTP INIT ACK option (Hostname Address)") as usize).expect("insufficent bytes in SCTP INIT ACK opion to extract Hostname Address payload")),
            INIT_ACK_OPT_STATE_COOKIE => InitAckOptionPayloadRef::StateCookie(self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid length field in SCTP INIT ACK option (State Cookie)") as usize).expect("insufficent bytes in SCTP INIT ACK option to extract State Cookie payload")),
            INIT_ACK_OPT_UNRECOGNIZED_PARAM => InitAckOptionPayloadRef::UnrecognizedParameter(InitOptionRef::from_bytes_unchecked(self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid Length field in SCTP INIT ACK option (Unrecognized Parameter)") as usize).expect("insufficent bytes in SCTP INIT ACK option to extract Unrecognized Parameter payload"))),
            _ => InitAckOptionPayloadRef::Unknown(self.opt_type(), self.data.get(4..4 + self.unpadded_len().checked_sub(4).expect("invalid length field in SCTP INIT ACK option (<unknown> Option Type)") as usize).expect("insufficent bytes in SCTP INIT ACK option to extract <unknown> option payload"))
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(16 + (self.gap_ack_blocks.len() * 4) + (self.duplicate_tsns.len() * 4))
            .expect("too many bytes in SCTP SACK chunk to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
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
}

impl ToBytes for SackChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_SACK);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(self.cum_tsn_ack.to_be_bytes());
        bytes.extend(self.a_rwnd.to_be_bytes());
        bytes.extend(u16::try_from(self.gap_ack_blocks.len()).expect("too many Gap Ack Blocks in SCTP SACK chunk to represent in a 16-bit Length field").to_be_bytes());
        bytes.extend(u16::try_from(self.duplicate_tsns.len()).expect("too many Duplicate TSNs in SCTP SACK chunk to represent in a 16-bit Length field").to_be_bytes());
        for (gap_ack_start, gap_ack_end) in &self.gap_ack_blocks {
            bytes.extend(gap_ack_start.to_be_bytes());
            bytes.extend(gap_ack_end.to_be_bytes());
        }

        for dup_tsn in &self.duplicate_tsns {
            bytes.extend(dup_tsn.to_be_bytes());
        }
        // All parameters are multiples of 4, so no padding at end
    }
}

impl From<SackChunkRef<'_>> for SackChunk {
    #[inline]
    fn from(value: SackChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&SackChunkRef<'_>> for SackChunk {
    #[inline]
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

    #[inline]
    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if bytes.len() < cmp::max(len, 16) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP SACK chunk for header and optional parameters",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP SACK chunk length must be a multiple of 4",
                    });
                }

                if len < 16 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "length field of SCTP SACK chunk was too short for header",
                    });
                }

                let (gap_ack_cnt, dup_tsn_cnt) = match (utils::to_array(bytes, 12), utils::to_array(bytes, 14)) {
                    (Some(gap_ack_cnt_arr), Some(dup_tsn_cnt_arr)) => (u16::from_be_bytes(gap_ack_cnt_arr) as usize, u16::from_be_bytes(dup_tsn_cnt_arr) as usize),
                    _ => return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP SACK chunk for Number of Duplicate TSNs field"
                    })
                };

                if 16 + (gap_ack_cnt * 4) + (dup_tsn_cnt * 4) != len {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP SACK chunk Length field did not match the total length of header + Gap Ack Blocks + Duplicate TSNs"
                    });
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP SACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP SACK chunk for header Length field",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP SACK chunk to retrieve Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP SACK chunk to retrieve Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP SACK chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4).expect(
                "insufficient bytes in SCTP SACK chunk to extract Cumulative TSN Ack field",
            ),
        )
    }

    #[inline]
    pub fn a_rwnd(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).expect("insufficient bytes in SCTP SACK chunk to extract Advertised Receiver Window Credit (a_rwnd) field"))
    }

    #[inline]
    pub fn gap_ack_block_cnt(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 12).expect(
                "insufficient bytes in SCTP SACK chunk to extract Gap Ack Blocks Count field",
            ),
        )
    }

    #[inline]
    pub fn dup_tsn_cnt(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 14).expect(
                "insufficient bytes in SCTP SACK chunk to extract Duplicate TSN Count field",
            ),
        )
    }

    #[inline]
    pub fn gap_ack_blocks_iter(&self) -> GapAckBlockIterRef<'a> {
        GapAckBlockIterRef {
            bytes: self
                .data
                .get(16..)
                .expect("insufficient bytes in SCTP SACK chunk to extract header values"),
            block_idx: 0,
            block_total: self.gap_ack_block_cnt() as usize,
        }
    }

    #[inline]
    pub fn duplicate_tsn_iter(&self) -> DuplicateTsnIterRef {
        DuplicateTsnIterRef {
            bytes: self
                .data
                .get(16 + (4 * self.gap_ack_block_cnt() as usize)..)
                .expect("insufficient bytes in SCTP SACK chunk to extract Gap Ack Block fields"),
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

        let start = u16::from_be_bytes(utils::to_array(self.bytes, 0).expect(
            "insufficient bytes in SCTP SACK chunk to extract all Gap Ack Block Start fields",
        ));
        let end = u16::from_be_bytes(utils::to_array(self.bytes, 2).expect(
            "insufficient bytes in SCTP SACK chunk to extract all Gap Ack Block End fields",
        ));
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

        let dup_tsn =
            u32::from_be_bytes(utils::to_array(self.bytes, 0).expect(
                "insufficient bytes in SCTP SACK chunk to extract all Duplicate TSN fields",
            ));
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(8 + utils::padded_length::<4>(self.heartbeat.len()))
            .expect("too many bytes in SCTP HEARTBEAT chunk to represent in 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        8 + utils::padded_length::<4>(self.heartbeat.len())
    }

    #[inline]
    pub fn heartbeat(&self) -> &Vec<u8> {
        &self.heartbeat
    }

    #[inline]
    pub fn heartbeat_mut(&mut self) -> &mut Vec<u8> {
        &mut self.heartbeat
    }
}

impl ToBytes for HeartbeatChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_HEARTBEAT);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(1u16.to_be_bytes()); // HEARTBEAT_OPT_HEARTBEAT_INFO (the only option available for HEARTBEAT chunks)
        bytes.extend(u16::try_from(self.heartbeat.len()).expect("too many bytes in SCTP HEARTBEAT chunk Heartbeat Info option to represent in a 16-bit Length field").to_be_bytes());
        bytes.extend(&self.heartbeat);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize))
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

    #[inline]
    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let unpadded_len = u16::from_be_bytes(unpadded_len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(len, 8) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP HEARTBEAT chunk for header + Heartbeat Info option",
                    });
                }

                if let Err(e) = HeartbeatInfoRef::validate(&bytes[4..len]) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: e.reason,
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid nonzero padding values at end of SCTP HEARTBEAT chunk",
                        });
                    }
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP HEARTBEAT chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP HEARTBEAT chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP HEARTBEAT chunk to retreive Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP HEARTBEAT chunk to retreive Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP HEARTBEAT chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn heartbeat_info(&self) -> HeartbeatInfoRef<'a> {
        HeartbeatInfoRef { data: self.data.get(4..).expect("insufficient bytes in SCTP HEARTBEAT chunk to retreive Heartbeat Information field") }
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

    #[inline]
    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let unpadded_len = u16::from_be_bytes(unpadded_len_arr);
                let len = utils::padded_length::<4>(unpadded_len as usize);

                if len > bytes.len() {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP HEARTBEAT chunk Heartbeat Info option for Heartbeat field + padding bytes",
                    });
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP HEARTBEAT chunk Heartbeat Info option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason:
                    "insufficient bytes in SCTP HEARTBEAT chunk Heartbeat Info option for header",
            }),
        }
    }

    #[inline]
    pub fn opt_type(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0).expect(
                "insufficient bytes in SCTP HEARTBEAT chunk Heartbeat Info option to extract Option Type field",
            ),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP HEARTBEAT chunk Heartbeat Info option to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    pub fn heartbeat(&self) -> &'a [u8] {
        self.data
            .get(
                4..4 + self
                    .unpadded_len()
                    .checked_sub(4)
                    .expect("invalid length field in SCTP HEARTBEAT chunk Heartbeat Info option")
                    as usize,
            )
            .expect("insufficent bytes in SCTP HEARTBEAT chunk Heartbeat Info option to extract payload")
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(8 + utils::padded_length::<4>(self.heartbeat.len())).expect(
            "too many bytes in SCTP HEARTBEAT ACK chunk to represent in a 16-bit Length field",
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        8 + utils::padded_length::<4>(self.heartbeat.len())
    }

    #[inline]
    pub fn heartbeat(&self) -> &Vec<u8> {
        &self.heartbeat
    }

    #[inline]
    pub fn heartbeat_mut(&mut self) -> &mut Vec<u8> {
        &mut self.heartbeat
    }
}

impl ToBytes for HeartbeatAckChunk {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_HEARTBEAT_ACK);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(1u16.to_be_bytes()); // HEARTBEAT_ACK_OPT_HEARTBEAT_INFO - the only option available, so we don't define it
        bytes.extend(u16::try_from(self.heartbeat.len()).expect("too many bytes in SCTP HEARTBEAT ACK chunk Heartbeat Info option to represent in a 16-bit Length field").to_be_bytes());
        bytes.extend(&self.heartbeat);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize))
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

    #[inline]
    pub fn validate(bytes: &'a [u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(unpadded_len_arr) => {
                let len = u16::from_be_bytes(unpadded_len_arr) as usize;

                if len > bytes.len() {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP HEARTBEAT ACK chunk for header + Heartbeat field",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "SCTP HEARTBEAT ACK chunk length was not a multiple of 4",
                    });
                }

                HeartbeatInfoRef::validate(&bytes[4..len])?;

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP HEARTBEAT ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP HEARTBEAT ACK chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP HEARTBEAT ACK chunk to retreive Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP HEARTBEAT ACK chunk to retreive Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP HEARTBEAT ACK chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn heartbeat_info(&self) -> HeartbeatInfoRef<'a> {
        HeartbeatInfoRef::from_bytes_unchecked(self.data.get(4..).expect("insufficient bytes in SCTP HEARTBEAT ACK chunk to retreive Heartbeat Information field"))
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.causes.iter().map(|c| c.len()).sum::<usize>())
            .expect("too many bytes in SCTP ABORT chunk to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn causes(&self) -> &Vec<ErrorCause> {
        &self.causes
    }

    #[inline]
    pub fn set_causes(&mut self) -> &mut Vec<ErrorCause> {
        &mut self.causes
    }
}

impl ToBytes for AbortChunk {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_ABORT);
        bytes.push(self.flags.raw());
        bytes.extend(self.unpadded_len().to_be_bytes());
        for cause in &self.causes {
            cause.to_bytes_extended(bytes);
        }
    }
}

impl From<AbortChunkRef<'_>> for AbortChunk {
    #[inline]
    fn from(value: AbortChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&AbortChunkRef<'_>> for AbortChunk {
    #[inline]
    fn from(value: &AbortChunkRef<'_>) -> Self {
        let mut causes = Vec::new();
        let mut iter = value.error_iter();
        while let Some(error) = iter.next() {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason:
                            "insufficient bytes in SCTP ABORT chunk for header + Error Cause fields",
                    });
                }

                if chunk_type != CHUNK_TYPE_ABORT {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid Chunk Type field in SCTP ABORT chunk (must be equal to 6)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP ABORT chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP ABORT chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP ABORT chunk to retreive Chunk Type field")
    }

    #[inline]
    pub fn flags(&self) -> AbortFlags {
        AbortFlags {
            data: self.flags_raw(),
        }
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP ABORT chunk to retreive Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP ABORT chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn error_iter(&self) -> ErrorCauseIterRef {
        ErrorCauseIterRef {
            bytes: self
                .data
                .get(4..self.len())
                .expect("insufficient bytes in SCTP ABORT chunk to retrieve Error Cause fields"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ErrorCauseIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for ErrorCauseIterRef<'a> {
    type Item = ErrorCauseRef<'a>;

    #[inline]
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

    #[inline]
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
}

impl From<ErrorCauseRef<'_>> for ErrorCause {
    #[inline]
    fn from(value: ErrorCauseRef<'_>) -> Self {
        ErrorCause::from(&value)
    }
}

impl From<&ErrorCauseRef<'_>> for ErrorCause {
    #[inline]
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
            ErrorCauseRef::Unknown(e) => ErrorCause::Unknown(
                e.into(), /*
                          u16::from_be_bytes(*utils::get_array(b, 0).expect(
                              "insufficient bytes in SCTP <unknown> Error Cause to retrieve Error Type field",
                          )),
                          b.get(4..)
                              .expect(
                                  "insufficient bytes in SCTP <unknown> Error Cause to retrieve Data field",
                              )
                              .to_vec(),
                          */
            ),
        }
    }
}

impl ToBytes for ErrorCause {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        match self {
            ErrorCause::InvalidStreamIdentifier(e) => e.to_bytes_extended(bytes),
            ErrorCause::MissingMandatoryParameter(e) => e.to_bytes_extended(bytes),
            ErrorCause::StaleCookie(e) => e.to_bytes_extended(bytes),
            ErrorCause::OutOfResource => {
                bytes.extend(ERR_CODE_OUT_OF_RESOURCE.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
            }
            ErrorCause::UnresolvableAddress(e) => e.to_bytes_extended(bytes),
            ErrorCause::UnrecognizedChunkType(e) => e.to_bytes_extended(bytes),
            ErrorCause::InvalidMandatoryParameter => {
                bytes.extend(ERR_CODE_INVALID_MAND_PARAM.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
            }
            ErrorCause::UnrecognizedParameters(e) => e.to_bytes_extended(bytes),
            ErrorCause::NoUserData(e) => e.to_bytes_extended(bytes),
            ErrorCause::CookieDuringShutdown => {
                bytes.extend(ERR_CODE_COOKIE_RCVD_SHUTTING_DOWN.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
            }
            ErrorCause::AssociationNewAddress(e) => e.to_bytes_extended(bytes),
            ErrorCause::UserInitiatedAbort(e) => e.to_bytes_extended(bytes),
            ErrorCause::ProtocolViolation(e) => e.to_bytes_extended(bytes),
            ErrorCause::Unknown(e) => e.to_bytes_extended(bytes),
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

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        let cause_code = u16::from_be_bytes(
            utils::to_array(bytes, 0)
                .expect("insufficient bytes in SCTP Error Cause to extract Cause Code field"),
        );
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let cause_code = u16::from_be_bytes(
            utils::to_array(bytes, 0)
                .expect("insufficient bytes in SCTP Error Cause to extract Cause Code field"),
        );
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
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid length in SCTP Error Cause (must be equal to 4)",
                        });
                    }

                    if bytes.len() > 4 {
                        Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::ExcessBytes(bytes.len() - 4),
                            reason: "extra bytes remain at end of SCTP 4-byte Error Cause",
                        })
                    } else {
                        Ok(())
                    }
                }
                _ => Err(ValidationError {
                    layer: Sctp::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
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
                            err_type: ValidationErrorType::InsufficientBytes,
                            reason: "insufficient bytes in SCTP <unknown> Error Cause for header and data field",
                        });
                    }

                    if unpadded_len < 8 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid length in SCTP <unknown> Error Cause (must be at least 8 bytes)",
                        });
                    }

                    if bytes.len() > len {
                        Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                            reason: "extra bytes remain at end of SCTP <unknown> Error Cause",
                        })
                    } else {
                        Ok(())
                    }
                }
                _ => Err(ValidationError {
                    layer: Sctp::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
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
}

impl ToBytes for StreamIdentifierError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Invalid Stream Identifier option for header + Explanation field",
                    });
                }

                if cause_code != ERR_CODE_INVALID_STREAM_ID {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Invalid Stream Identifier Option (must be equal to 1)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP Invalid Stream Identifier Option (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 8),
                        reason:
                            "extra bytes remain at end of SCTP Invalid Stream Identifier option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Invalid Stream Identifier option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0).expect(
                "insufficient bytes in SCTP Invalid Stream Identifier option to extract Cause Code field",
            ),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).expect(
            "insufficient bytes in SCTP Invalid Stream Identifier option to extract Length field",
        ))
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn stream_id(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 4).expect(
            "insufficient bytes in SCTP Invalid Stream Identifier option to extract Stream Identifier field",
        ))
    }

    #[inline]
    pub fn reserved(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 4).expect(
            "insufficient bytes in SCTP Invalid Stream Identifier option to extract Reserved field",
        ))
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

    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(8 + (2 * self.missing_params.len())).expect(
            "too many bytes in SCTP Missing Parameter option to encode in a 16-bit Length field",
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn missing_params(&self) -> &Vec<u16> {
        &self.missing_params
    }

    #[inline]
    pub fn missing_params_mut(&mut self) -> &mut Vec<u16> {
        &mut self.missing_params
    }
}

impl ToBytes for MissingParameterError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_MISSING_MAND_PARAM.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend((u32::try_from(self.missing_params.len()).expect("too many Missing Params in SCTP Missing Parameter Error option to represent in a 32-bit Length field")).to_be_bytes());
        for param in &self.missing_params {
            bytes.extend(param.to_be_bytes());
        }
        if self.missing_params.len() % 4 != 0 {
            bytes.push(0);
            bytes.push(0);
        }
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(8, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Missing Mandatory Parameter option for header + Missing Parameter fields",
                    });
                }

                if cause_code != ERR_CODE_MISSING_MAND_PARAM {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Missing Mandatory Parameter option (must be equal to 2)",
                    });
                }

                if unpadded_len < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP Missing Mandatory Parameter option (must be at least 8 bytes long)",
                    });
                }

                if unpadded_len % 2 != 0 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP Missing Mandatory Parameter option (must be a multiple of 2)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid nonzero padding values at end of SCTP Missing Mandatory Parameter Option",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of Missing Mandatory Parameter option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Missing Mandatory Parameter option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP Missing Mandatory Parameter option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).expect(
            "insufficient bytes in SCTP Missing Mandatory Parameter option to extract Length field",
        ))
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn missing_params_cnt(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 2).expect("insufficient bytes in SCTP Missing Mandatory Parameter option to extract Missing Parameters Count field"))
    }

    #[inline]
    pub fn missing_params_iter(&self) -> MissingParameterIterRef<'a> {
        MissingParameterIterRef { data: self.data.get(4..cmp::min(4 + (2 * self.missing_params_cnt() as usize), self.data.len())).expect("insufficient bytes in SCTP Missing Mandatory Parameter option for header + Missing Parameter values") }
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
}

impl ToBytes for StaleCookieError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Stale Cookie option for header + Measure of Staleness field",
                    });
                }

                if cause_code != ERR_CODE_STALE_COOKIE {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "invalid cause code in SCTP Stale Cookie option (must be equal to 3)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP Stale Cookie option (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 8),
                        reason: "extra bytes remain at end of SCTP Stale Cookie option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Stale Cookie option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0).expect(
                "insufficient bytes in SCTP Stale Cookie option to extract Cause Code field",
            ),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP Stale Cookie option to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn staleness(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4).expect(
                "insufficient bytes in SCTP Stale Cookie option to extract Staleness field",
            ),
        )
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

    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.addr.len()).expect("too many bytes in SCTP Unresolvable Address Error option Address field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn addr(&self) -> &Vec<u8> {
        &self.addr
    }

    #[inline]
    pub fn addr_mut(&mut self) -> &mut Vec<u8> {
        &mut self.addr
    }
}

impl ToBytes for UnresolvableAddrError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_UNRESOLVABLE_ADDRESS.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(&self.addr);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize))
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Unresolvable Address option for header + Unresolvable Address field",
                    });
                }

                if cause_code != ERR_CODE_UNRESOLVABLE_ADDRESS {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Unresolvable Address option (must be equal to 5)",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP Unresolvable Address option (must be at least 4 bytes long)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid nonzero padding values at end of SCTP Unresolvable Address 4ption",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP Unresolvable Address option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Unresolvable Address option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP Unresolvable Address option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).expect(
            "insufficient bytes in SCTP Unresolvable Address option to extract Length field",
        ))
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn addr(&self) -> &[u8] {
        self.data.get(4..).expect("insufficient bytes in SCTP Unresolvable Address option to extract Unresolvable Address field")
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.chunk.len()).expect("too many bytes in SCTP Unrecognized Chunk option Chunk field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        4 + self.chunk.len()
    }

    #[inline]
    pub fn chunk(&self) -> &Vec<u8> {
        &self.chunk
    }

    #[inline]
    pub fn chunk_mut(&mut self) -> &mut Vec<u8> {
        &mut self.chunk
    }
}

impl ToBytes for UnrecognizedChunkError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(8, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Unrecognized Chunk option for header + Unrecognized Chunk field",
                    });
                }

                if cause_code != ERR_CODE_UNRECOGNIZED_CHUNK {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Unrecognized Chunk option (must be equal to 6)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP Unrecognized Chunk option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Unrecognized Chunk option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP Unrecognized Chunk option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2).expect(
                "insufficient bytes in SCTP Unrecognized Chunk option to extract Length field",
            ),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn chunk(&self) -> &[u8] {
        self.data.get(8..).expect("insufficient bytes in SCTP Unrecognized Chunk option to extract header and Unrecognized Chunk field")
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.params.iter().map(|p| p.len()).sum::<usize>()).expect("too many bytes in SCTP Unrecognized Parameters option to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn params(&self) -> &Vec<GenericParam> {
        &self.params
    }

    #[inline]
    pub fn params_mut(&mut self) -> &mut Vec<GenericParam> {
        &mut self.params
    }
}

impl ToBytes for UnrecognizedParamError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_UNRECOGNIZED_PARAMS.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        for param in self.params.iter() {
            param.to_bytes_extended(bytes);
        }
    }
}

impl From<UnrecognizedParamErrorRef<'_>> for UnrecognizedParamError {
    #[inline]
    fn from(value: UnrecognizedParamErrorRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&UnrecognizedParamErrorRef<'_>> for UnrecognizedParamError {
    #[inline]
    fn from(value: &UnrecognizedParamErrorRef<'_>) -> Self {
        let mut params = Vec::new();
        let mut iter = value.params_iter();
        while let Some(param) = iter.next() {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Unrecognized Parameters Option for header and Unrecognized Chunk field",
                    });
                }

                if cause_code != ERR_CODE_UNRECOGNIZED_PARAMS {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Unrecognized Parameters option (must be equal to 8)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP Unrecognized Parameters option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Unrecognized Parameters option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP Unrecognized Parameters option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2).expect(
                "insufficient bytes in SCTP Unrecognized Parameters to extract Length field",
            ),
        )
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

    #[inline]
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
}

impl ToBytes for NoUserDataError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP No User Data option for header and explanation field",
                    });
                }

                if cause_code != ERR_CODE_NO_USER_DATA {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "invalid cause code in SCTP No User Data option (must be equal to 9)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP No User Data option (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 8),
                        reason: "extra bytes remain at end of SCTP No User Data option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP No User Data option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0).expect(
                "insufficient bytes in SCTP No User Data option to extract Cause Code field",
            ),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP No User Data option to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn tsn(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in SCTP No User Data option to extract TSN field"),
        )
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.tlvs.iter().map(|p| p.len()).sum::<usize>()).expect("too many bytes in SCTP Restart of Association with New Address option New Address TLVs field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn params(&self) -> &Vec<GenericParam> {
        &self.tlvs
    }

    #[inline]
    pub fn params_mut(&mut self) -> &mut Vec<GenericParam> {
        &mut self.tlvs
    }
}

impl ToBytes for AssociationNewAddrError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_RESTART_ASSOC_NEW_ADDR.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        for tlv in self.tlvs.iter() {
            tlv.to_bytes_extended(bytes);
        }
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
        let mut iter = value.params_iter();
        while let Some(param) = iter.next() {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Restart of Association with New Address option for header + New Address TLVs field",
                    })
                }

                if cause_code != ERR_CODE_RESTART_ASSOC_NEW_ADDR {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Restart of Association with New Address option (must be equal to 11)",
                    })
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP Restart of Association with New Address option",
                    })
                } else {
                    Ok(())
                }
            },
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Restart of Association with New Address option for header"
            })
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP Restart of Association with New Address option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2).expect(
                "insufficient bytes in SCTP Restart of Association with New Address option to extract Length field",
            ),
        )
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.reason.len()).expect("too many bytes in SCTP User-Initiated Abort option to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn reason(&self) -> &Vec<u8> {
        &self.reason
    }

    #[inline]
    pub fn reason_mut(&mut self) -> &mut Vec<u8> {
        &mut self.reason
    }
}

impl ToBytes for UserInitiatedAbortError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_USER_INITIATED_ABORT.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(&self.reason);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP User-Initiated Abort option for header + Reason field",
                    });
                }

                if cause_code != ERR_CODE_USER_INITIATED_ABORT {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP User-Initiated Abort option (must be equal to 12)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP User-Initiated Abort option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP User-Initiated Abort option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP User-Initiated Abort option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).expect(
            "insufficient bytes in SCTP User-Initiated Abort option to extract Length field",
        ))
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn reason(&self) -> &[u8] {
        self.data.get(8..).expect("insufficient bytes in SCTP User-Initiated Abort option to extract header + Reason field")
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.information.len()).expect("too many bytes in SCTP Protocol Violation option Information field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn information(&self) -> &Vec<u8> {
        &self.information
    }

    #[inline]
    pub fn information_mut(&mut self) -> &mut Vec<u8> {
        &mut self.information
    }
}

impl ToBytes for ProtocolViolationError {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(ERR_CODE_PROTOCOL_VIOLATION.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(&self.information);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (utils::to_array(bytes, 0), utils::to_array(bytes, 2)) {
            (Some(cause_code_arr), Some(len_arr)) => {
                let cause_code = u16::from_be_bytes(cause_code_arr);
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < cmp::max(8, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Protocol Violation option for header + Additional Information field",
                    });
                }

                if cause_code != ERR_CODE_PROTOCOL_VIOLATION {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid cause code in SCTP Protocol Violation option (must be equal to 13)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP Protocol Violation option",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Protocol Violation option for header",
            }),
        }
    }

    #[inline]
    pub fn cause_code(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 0).expect(
            "insufficient bytes in SCTP Protocol Violation option to extract Cause Code field",
        ))
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2).expect(
                "insufficient bytes in SCTP Protocol Violation option to extract Length field",
            ),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn information(&self) -> &[u8] {
        self.data.get(8..).expect("insufficient bytes in SCTP Protocol Violation option to extract header + Additional Information field")
    }
}

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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.value.len()).expect(
            "too many bytes in SCTP Parameter Value field to represent in a 16-bit Length field",
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    #[inline]
    pub fn value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.value
    }
}

impl ToBytes for GenericParam {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.param_type.to_be_bytes());
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(self.value.iter());
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(len_arr) => {
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP Parameter for header + Value field",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP Parameter (must be at least 4 bytes long)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid nonzero padding values at end of SCTP Parameter",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP Parameter",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP Parameter for header",
            }),
        }
    }

    #[inline]
    pub fn param_type(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in SCTP Parameter to extract Parameter Type field"),
        )
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP Parameter to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        self.data
            .get(4..)
            .expect("insufficient bytes in SCTP Parameter to extract Value field")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AbortFlags {
    data: u8,
}

impl AbortFlags {
    #[inline]
    pub fn t(&self) -> bool {
        self.data & ABORT_FLAGS_T_BIT > 0
    }

    #[inline]
    pub fn set_t(&mut self, t: bool) {
        if t {
            self.data |= ABORT_FLAGS_T_BIT;
        } else {
            self.data &= !ABORT_FLAGS_T_BIT;
        }
    }

    #[inline]
    pub fn raw(&self) -> u8 {
        self.data
    }

    #[inline]
    pub fn raw_mut(&mut self) -> &mut u8 {
        &mut self.data
    }
}

impl From<u8> for AbortFlags {
    #[inline]
    fn from(value: u8) -> Self {
        AbortFlags { data: value }
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
}

impl ToBytes for ShutdownChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;

                if bytes.len() < 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP SHUTDOWN chunk for header + Cumulative TSN Ack field",
                    });
                }

                if chunk_type != CHUNK_TYPE_SHUTDOWN {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "invalid Chunk Type field in SCTP SHUTDOWN chunk (must be equal to 7)",
                    });
                }

                if len != 8 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP SHUTDOWN chunk (must be equal to 8)",
                    });
                }

                if bytes.len() > 8 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 8),
                        reason: "extra bytes remain at end of SCTP SHUTDOWN chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP SHUTDOWN chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP SHUTDOWN chunk to extract Chunk Type field")
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP SHUTDOWN chunk to extract Chunk Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP SHUTDOWN chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn cum_tsn_ack(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).expect(
            "insufficient bytes in SCTP SHUTDOWN chunk to extract Cumulative TSN Ack field",
        ))
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
}

impl ToBytes for ShutdownAckChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if chunk_type != CHUNK_TYPE_SHUTDOWN_ACK {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid Chunk Type field in SCTP SHUTDOWN ACK chunk (must be equal to 8)",
                    });
                }

                if len != 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP SHUTDOWN ACK chunk (must be equal to 4)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 4),
                        reason: "extra bytes remain at end of SCTP SHUTDOWN ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP SHUTDOWN ACK chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP SHUTDOWN ACK chunk to extract Chunk Type field")
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP SHUTDOWN ACK chunk to extract Chunk Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP SHUTDOWN ACK chunk to extract Length field"),
        )
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.causes.iter().map(|c| c.len()).sum::<usize>())
            .expect("too many bytes in SCTP ERROR chunk to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.unpadded_len() as usize
    }

    #[inline]
    pub fn causes(&self) -> &Vec<ErrorCause> {
        &self.causes
    }

    #[inline]
    pub fn set_causes(&mut self) -> &mut Vec<ErrorCause> {
        &mut self.causes
    }
}

impl ToBytes for ErrorChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_ERROR);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        for cause in &self.causes {
            cause.to_bytes_extended(bytes)
        }
    }
}

impl From<ErrorChunkRef<'_>> for ErrorChunk {
    #[inline]
    fn from(value: ErrorChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&ErrorChunkRef<'_>> for ErrorChunk {
    #[inline]
    fn from(value: &ErrorChunkRef<'_>) -> Self {
        let mut causes = Vec::new();
        let mut iter = value.error_iter();
        while let Some(error) = iter.next() {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason:
                            "insufficient bytes in SCTP ERROR chunk for header + Error Causes field",
                    });
                }

                if chunk_type != CHUNK_TYPE_ERROR {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid Chunk Type field in SCTP ERROR chunk (must be equal to 9)",
                    });
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP ERROR chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP ERROR chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP ERROR chunk to retrieve Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP ERROR chunk to retrieve Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP ERROR chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn error_iter(&self) -> ErrorCauseIterRef {
        ErrorCauseIterRef {
            bytes: self
                .data
                .get(4..self.len())
                .expect("insufficient bytes in SCTP ERROR chunk to retrieve Error Cause fields"),
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(4 + self.cookie.len()).expect("too many bytes in SCTP COOKIE ECHO chunk Cookie field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn cookie(&self) -> &Vec<u8> {
        &self.cookie
    }

    #[inline]
    pub fn cookie_mut(&mut self) -> &mut Vec<u8> {
        &mut self.cookie
    }
}

impl ToBytes for CookieEchoChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_COOKIE_ECHO);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(&self.cookie);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason:
                            "insufficient bytes in SCTP COOKIE ECHO chunk for header + Cookie field",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP COOKIE ECHO chunk (must be at least 4 octets long)",
                    });
                }

                if chunk_type != CHUNK_TYPE_COOKIE_ECHO {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid Chunk Type field in SCTP COOKIE ECHO chunk (must be equal to 10)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason:
                                "invalid nonzero padding values at end of SCTP COOKIE ECHO chunk",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP COOKIE ECHO hunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP COOKIE ECHO chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP COOKIE ECHO chunk to retreive Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP COOKIE ECHO chunk to retreive Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP COOKIE ECHO chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn cookie(&self) -> &[u8] {
        self.data
            .get(4..)
            .expect("insufficient bytes in SCTP COOKIE ECHO chunk to extract Cookie field")
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
}

impl ToBytes for CookieAckChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if chunk_type != CHUNK_TYPE_COOKIE_ACK {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "invalid Chunk Type field in SCTP COOKIE ACK chunk (must be equal to 11)",
                    });
                }

                if len != 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length in SCTP COOKIE_ACK chunk (must be equal to 4)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 4),
                        reason: "extra bytes remain at end of SCTP COOKIE ACK chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP COOKIE ACK chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP COOKIE ACK chunk to extract Chunk Type field")
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP COOKIE ACK chunk to extract Chunk Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP COOKIE ACK chunk to extract Length field"),
        )
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
}

impl ToBytes for ShutdownCompleteChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(CHUNK_TYPE_SHUTDOWN_COMPLETE);
        bytes.push(self.flags.data);
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match (bytes.first(), utils::to_array(bytes, 2)) {
            (Some(&chunk_type), Some(len_arr)) => {
                let len = u16::from_be_bytes(len_arr) as usize;
                if chunk_type != CHUNK_TYPE_SHUTDOWN_COMPLETE {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid Chunk Type field in SCTP SHUTDOWN COMPLETE chunk (must be equal to 14)",
                    });
                }

                if len != 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "invalid length in SCTP SHUTDOWN COMPLETE chunk (must be equal to 4)",
                    });
                }

                if bytes.len() > 4 {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - 4),
                        reason: "extra bytes remain at end of SCTP SHUTDOWN COMPLETE chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP SHUTDOWN COMPLETE chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self.data.first().expect(
            "insufficient bytes in SCTP SHUTDOWN COMPLETE chunk to extract Chunk Type field",
        )
    }

    #[inline]
    pub fn flags(&self) -> ShutdownCompleteFlags {
        ShutdownCompleteFlags {
            data: *self.data.get(1).expect(
                "insufficient bytes in SCTP SHUTDOWN COMPLETE chunk to extract Chunk Flags field",
            ),
        }
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2).expect(
                "insufficient bytes in SCTP SHUTDOWN COMPLETE chunk to extract Length field",
            ),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShutdownCompleteFlags {
    data: u8,
}

impl ShutdownCompleteFlags {
    pub fn raw(&self) -> u8 {
        self.data
    }

    pub fn raw_mut(&mut self) -> &mut u8 {
        &mut self.data
    }

    #[inline]
    pub fn t(&self) -> bool {
        self.data & SHUTDOWN_COMPLETE_FLAGS_T_BIT > 0
    }

    #[inline]
    pub fn set_t(&mut self, t: bool) {
        if t {
            self.data |= SHUTDOWN_COMPLETE_FLAGS_T_BIT;
        } else {
            self.data &= !SHUTDOWN_COMPLETE_FLAGS_T_BIT;
        }
    }
}

/// A chunk containing a Chunk Type value that does not match any
/// chunk type defined in RFC 4960.
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
    pub fn unpadded_len(&self) -> u16 {
        u16::try_from(self.value.len() + 4).expect("too many bytes in SCTP <unknown> chunk Value field to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    #[inline]
    pub fn value_mut(&mut self) -> &mut Vec<u8> {
        &mut self.value
    }
}

impl ToBytes for UnknownChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.chunk_type);
        bytes.push(self.flags);
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(&self.value);
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
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

/// A chunk containing a Chunk Type value that does not match any
/// chunk type defined in RFC 4960.
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

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 2) {
            Some(len_arr) => {
                let unpadded_len = u16::from_be_bytes(len_arr) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                if bytes.len() < cmp::max(4, len) {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes in SCTP <unknown> chunk for header/Value field",
                    });
                }

                if unpadded_len < 4 {
                    return Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason:
                            "invalid length in SCTP <unknown> chunk (must be at least 4 bytes long)",
                    });
                }

                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Sctp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "invalid nonzero padding values at end of SCTP <unknown> chunk",
                        });
                    }
                }

                if bytes.len() > len {
                    Err(ValidationError {
                        layer: Sctp::name(),
                        err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                        reason: "extra bytes remain at end of SCTP <unknown> chunk",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in SCTP <unknown> chunk for header",
            }),
        }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP <unknown> chunk to retreive Chunk Type field")
    }

    #[inline]
    pub fn flags_raw(&self) -> u8 {
        *self
            .data
            .get(1)
            .expect("insufficient bytes in SCTP <unknown> chunk to retreive Flags field")
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP <unknown> chunk to extract Length field"),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        self.data
            .get(4..)
            .expect("insufficient bytes in SCTP <unknown> chunk to extract Value field")
    }
}

#[derive(Clone, Debug)]
pub struct DataChunk {
    flags: DataChunkFlags,
    tsn: u32,
    stream_id: u16,
    stream_seq: u16,
    proto_id: u32,
    payload: Box<dyn LayerObject>,
}

impl DataChunk {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        DataChunkRef::validate(bytes)
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(DataChunkRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        0 // Payload Data (DATA)
    }

    #[inline]
    pub fn flags(&self) -> DataChunkFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: DataChunkFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> u16 {
        (20 + self.payload.len())
            .try_into()
            .expect("too many bytes in SCTP DATA Chunk to represent in a 16-bit Length field")
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn tsn(&self) -> u32 {
        self.tsn
    }

    #[inline]
    pub fn set_tsn(&mut self, tsn: u32) {
        self.tsn = tsn;
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
    pub fn stream_seq(&self) -> u16 {
        self.stream_seq
    }

    #[inline]
    pub fn set_stream_seq(&mut self, stream_seq: u16) {
        self.stream_seq = stream_seq;
    }

    #[inline]
    pub fn proto_id(&self) -> u32 {
        self.proto_id
    }

    #[inline]
    pub fn set_proto_id(&mut self, proto_id: u32) {
        self.proto_id = proto_id;
    }

    #[inline]
    pub fn payload(&self) -> &dyn LayerObject {
        self.payload.as_ref()
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut Box<dyn LayerObject> {
        &mut self.payload
    }
}

impl ToBytes for DataChunk {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(0); // DATA Type = 0
        bytes.push(self.flags.as_raw());
        bytes.extend(self.unpadded_len().to_be_bytes());
        bytes.extend(self.tsn.to_be_bytes());
        bytes.extend(self.stream_id.to_be_bytes());
        bytes.extend(self.stream_seq.to_be_bytes());
        bytes.extend(self.proto_id.to_be_bytes());
        self.payload.to_bytes_extended(bytes);
        bytes.extend(core::iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
    }
}

impl From<&DataChunkRef<'_>> for DataChunk {
    #[inline]
    fn from(value: &DataChunkRef<'_>) -> Self {
        DataChunk {
            flags: value.flags(),
            tsn: value.tsn(),
            stream_id: value.stream_id(),
            stream_seq: value.stream_seq(),
            proto_id: value.proto_id(),
            payload: Box::new(Raw::from_bytes_unchecked(value.user_data())),
        }
    }
}

impl From<DataChunkRef<'_>> for DataChunk {
    #[inline]
    fn from(value: DataChunkRef<'_>) -> Self {
        Self::from(&value)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DataChunkRef<'a> {
    data: &'a [u8],
}

impl<'a> DataChunkRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let len = match utils::to_array(bytes, 2) {
            None => {
                return Err(ValidationError {
                    layer: Sctp::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
                    reason: "SCTP DATA chunk must have a minimum of 16 bytes for its header",
                })
            }
            Some(arr) => u16::from_be_bytes(arr) as usize,
        };

        let padded_len = utils::padded_length::<4>(len);
        if padded_len > bytes.len() {
            return Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes for User Data portion of SCTP DATA chunk",
            });
        }

        let payload_type = bytes[0]; // This won't panic because we've already retrieved bytes at index 2
        if payload_type != 0 {
            return Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "invalid Chunk Type field in SCTP DATA chunk (must be equal to 0)",
            });
        }

        if len < 20 {
            return Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "packet length field had invalid value (insufficient length to cover packet header, at least one byte of data and padding) for SCTP DATA chunk",
            });
        }

        // The payload is considered valid by default, since we count it as a [`Raw`] packet type.

        for b in bytes.iter().take(padded_len).skip(len) {
            if *b != 0 {
                return Err(ValidationError {
                    layer: Sctp::name(),
                    err_type: ValidationErrorType::InvalidValue,
                    reason: "padding at end of SCTP DATA chunk had a non-zero value",
                });
            }
        }

        if padded_len < bytes.len() {
            Err(ValidationError {
                layer: Sctp::name(),
                err_type: ValidationErrorType::ExcessBytes(bytes.len() - len),
                reason: "SCTP DATA chunk had additional trailing bytes at the end of its data",
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        DataChunkRef { data: bytes }
    }

    #[inline]
    pub fn chunk_type(&self) -> u8 {
        *self
            .data
            .first()
            .expect("insufficient bytes in SCTP DATA chunk to extrack Chunk Type field")
    }

    #[inline]
    pub fn flags(&self) -> DataChunkFlags {
        DataChunkFlags {
            data: *self
                .data
                .get(1)
                .expect("insufficient bytes in SCTP DATA chunk to extrack Chunk Flags field"),
        }
    }

    #[inline]
    pub fn chunk_len(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in SCTP DATA chunk to retrieve Chunk Length field"),
        )
    }

    #[inline]
    pub fn chunk_len_padded(&self) -> usize {
        utils::padded_length::<4>(self.chunk_len() as usize)
    }

    #[inline]
    pub fn tsn(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in SCTP DATA chunk to retrieve TSN field"),
        )
    }

    #[inline]
    pub fn stream_id(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 8).expect(
                "insufficient bytes in SCTP DATA chunk to retrieve Stream Identifier field",
            ),
        )
    }

    #[inline]
    pub fn stream_seq(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 10).expect(
            "insufficient bytes in SCTP DATA chunk to retrieve Stream Sequence Number field",
        ))
    }

    #[inline]
    pub fn proto_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 12).expect(
            "insufficient bytes in SCTP DATA chunk to retrieve Payload Protocol Identifier field",
        ))
    }

    #[inline]
    pub fn user_data(&self) -> &[u8] {
        self.data
            .get(16..self.chunk_len() as usize)
            .expect("insufficient bytes in SCTP DATA chunk to retrieve User Data field")
    }

    #[inline]
    pub fn padding(&self) -> &[u8] {
        self.data
            .get(self.chunk_len() as usize..self.chunk_len_padded())
            .expect("insufficient bytes in SCTP DATA chunk to retrieve padding bytes")
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DataChunkFlags {
    data: u8,
}

impl DataChunkFlags {
    #[inline]
    pub fn new() -> Self {
        DataChunkFlags::default()
    }

    #[inline]
    pub fn as_raw(&self) -> u8 {
        self.data
    }

    #[inline]
    pub fn immediate(&self) -> bool {
        self.data & DATA_CHUNK_FLAGS_IMMEDIATE_BIT > 0
    }

    #[inline]
    pub fn set_immediate(&mut self, immediate: bool) {
        if immediate {
            self.data |= DATA_CHUNK_FLAGS_IMMEDIATE_BIT;
        } else {
            self.data &= !DATA_CHUNK_FLAGS_IMMEDIATE_BIT;
        }
    }

    #[inline]
    pub fn unordered(&self) -> bool {
        self.data & DATA_CHUNK_FLAGS_UNORDERED_BIT > 0
    }

    #[inline]
    pub fn set_unordered(&mut self, unordered: bool) {
        if unordered {
            self.data |= DATA_CHUNK_FLAGS_UNORDERED_BIT;
        } else {
            self.data &= !DATA_CHUNK_FLAGS_UNORDERED_BIT;
        }
    }

    #[inline]
    pub fn beginning_fragment(&self) -> bool {
        self.data & DATA_CHUNK_FLAGS_BEGINNING_BIT > 0
    }

    #[inline]
    pub fn set_beginning_fragment(&mut self, beginning: bool) {
        if beginning {
            self.data |= DATA_CHUNK_FLAGS_BEGINNING_BIT;
        } else {
            self.data &= !DATA_CHUNK_FLAGS_BEGINNING_BIT;
        }
    }

    #[inline]
    pub fn ending_fragment(&self) -> bool {
        self.data & DATA_CHUNK_FLAGS_ENDING_BIT > 0
    }

    #[inline]
    pub fn set_ending_fragment(&mut self, ending: bool) {
        if ending {
            self.data |= DATA_CHUNK_FLAGS_ENDING_BIT;
        } else {
            self.data &= !DATA_CHUNK_FLAGS_ENDING_BIT;
        }
    }

    #[inline]
    pub fn reserved(&self) -> u8 {
        self.data & 0xF0
    }

    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        self.data &= 0x0F;
        self.data |= reserved << 4;
    }
}

impl From<u8> for DataChunkFlags {
    fn from(value: u8) -> Self {
        DataChunkFlags { data: value }
    }
}
