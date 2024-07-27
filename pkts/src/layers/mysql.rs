// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Protocol layers used for communication between MySQL clients and databases.
//!

use core::cmp::Ordering;
use core::slice;

use super::Raw;
use crate::error::*;
use crate::layers::dev_traits::*;
use crate::layers::traits::*;

use pkts_macros::{Layer, LayerRef, StatelessLayer};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

// SIDE NOTE: postgres will be able to be a stateless protocol
// This is because all other packets besides StartupMessage and
// its related packets(SSLRequest, etc.) start with a 4-byte length
// field. This length field can safely be assumed to be less than
// 1 gigabyte (there just aren't enough options to warrant that),
// so we can assume that the first byte will be less than the ascii
// '1'. This in turn allows us to infer protocol state from the
// first byte of a given packet!
//
// Mysql, unfortunately, is not so simple. It's gonna require some state.

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(MysqlPacketMetadata)]
#[ref_type(MysqlPacketRef)]
pub struct MysqlPacket {
    sequence_id: u8,
    payload: Option<Box<dyn LayerObject>>,
}

impl MysqlPacket {
    #[inline]
    pub fn sequence_id(&self) -> u8 {
        self.sequence_id
    }

    #[inline]
    pub fn set_sequence_id(&mut self, seq_id: u8) {
        self.sequence_id = seq_id
    }

    #[inline]
    pub fn payload_length(&self) -> usize {
        4 + self.payload.as_ref().map_or(0, |p| p.len())
    }
}

#[doc(hidden)]
impl FromBytesCurrent for MysqlPacket {
    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        self.payload = Some(Box::new(Raw::from_bytes_unchecked(bytes)));
    }

    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let mysql = MysqlPacketRef::from_bytes_unchecked(bytes);

        MysqlPacket {
            sequence_id: mysql.sequence_id(),
            payload: None,
        }
    }
}

impl LayerLength for MysqlPacket {
    #[inline]
    fn len(&self) -> usize {
        self.payload_length() as usize
    }
}

impl LayerObject for MysqlPacket {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        // payload.as_any().downcast_ref::<&MysqlClient>().is_some()
        todo!()
    }

    #[inline]
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload = Some(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        match &self.payload {
            Some(payload) => slice::from_ref(payload),
            None => &[],
        }
    }

    #[inline]
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        match &mut self.payload {
            Some(payload) => slice::from_mut(payload),
            None => &mut [],
        }
    }

    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>> {
        if index != 0 {
            return None;
        }

        let mut ret = None;
        core::mem::swap(&mut ret, &mut self.payload);
        ret
    }
}

impl ToBytes for MysqlPacket {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        let start = bytes.len();
        bytes.push(self.sequence_id);
        bytes.extend_from_slice(&self.payload_length().to_be_bytes()[1..]);
        match &self.payload {
            Some(p) => p.to_bytes_checksummed(bytes, Some((Self::layer_id(), start))),
            None => Ok(()),
        }
    }
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(MysqlPacket)]
#[metadata_type(MysqlPacketMetadata)]
pub struct MysqlPacketRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> MysqlPacketRef<'a> {
    #[inline]
    pub fn payload_length(&self) -> u32 {
        let mut len_arr = [0u8; 4];
        len_arr[1..].copy_from_slice(&self.data[..3]);

        u32::from_be_bytes(len_arr)
    }

    #[inline]
    pub fn sequence_id(&self) -> u8 {
        self
            .data[3]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[4..]
    }
}

impl<'a> FromBytesRef<'a> for MysqlPacketRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        MysqlPacketRef { data: bytes }
    }
}

impl<'a> LayerOffset for MysqlPacketRef<'a> {
    #[inline]
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        let mysql = MysqlPacketRef::from_bytes_unchecked(bytes);
        if mysql.payload_length() == 0 {
            return None;
        }

        if layer_type == Raw::layer_id() {
            Some(4)
        } else {
            None
        }
    }
}

impl<'a> Validate for MysqlPacketRef<'a> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() < 4 {
            return Err(ValidationError {
                layer: MysqlPacket::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes for MySQL Packet header (4 bytes required)",
            });
        }

        let payload_len = ((curr_layer[0] as usize) << 16)
            + ((curr_layer[1] as usize) << 8)
            + curr_layer[2] as usize;

        match curr_layer[4..].len().cmp(&payload_len) {
            Ordering::Less => Err(ValidationError {
                layer: MysqlPacket::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes for packet length advertised by MySQL header",
            }),
            Ordering::Greater => Err(ValidationError {
                layer: MysqlPacket::name(),
                class: ValidationErrorClass::ExcessBytes(curr_layer[4..].len() - payload_len),
                #[cfg(feature = "error_string")]
                reason:
                    "more bytes in packet than advertised by the MySQL Packet header Length field",
            }),
            Ordering::Equal => Ok(()),
        }
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // Payload always defaults to `Raw`
    }
}

#[derive(Clone, Debug, Layer)]
#[metadata_type(MysqlClientMetadata)]
#[ref_type(MysqlClientRef)]
pub struct MysqlClient {
    pub sequence_id: u8,
    pub payload: Option<Box<dyn LayerObject>>,
}

impl LayerLength for MysqlClient {
    fn len(&self) -> usize {
        todo!()
    }
}

impl LayerObject for MysqlClient {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        false
    }

    #[inline]
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload = Some(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        match &self.payload {
            Some(payload) => slice::from_ref(payload),
            None => &[],
        }
    }

    #[inline]
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        match &mut self.payload {
            Some(payload) => slice::from_mut(payload),
            None => &mut [],
        }
    }

    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>> {
        if index != 0 {
            return None;
        }

        let mut ret = None;
        core::mem::swap(&mut ret, &mut self.payload);
        ret
    }
}

impl ToBytes for MysqlClient {
    fn to_bytes_checksummed(
        &self,
        _bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<'a> From<&MysqlClientRef<'a>> for MysqlClient {
    fn from(_value: &MysqlClientRef<'a>) -> Self {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, LayerRef)]
#[owned_type(MysqlClient)]
#[metadata_type(MysqlClientMetadata)]
pub struct MysqlClientRef<'a> {
    #[data_field]
    data: &'a [u8],
    message_type: MessageType,
}

impl<'a> LayerOffset for MysqlClientRef<'a> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        None // Mysql does not encapsulate any inner layer
    }
}

impl<'a> MysqlClientRef<'a> {
    pub fn from_bytes_unchecked(bytes: &'a [u8], packet_type: MessageType) -> MysqlClientRef<'a> {
        MysqlClientRef {
            data: bytes,
            message_type: packet_type,
        }
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn message(&self) -> MessageTypeRef {
        todo!()
    }

    pub fn message_mut(&mut self) -> MessageTypeRef {
        todo!()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageTypeOwned {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageTypeRef {
    // <'a>
}

// A few notes:
// 1. Encapsulation of `MysqlPacket` type should be explicit--we can't abstract that out without ridiculousness like `sstr`.
// 2. sequence_id may be an issue.
