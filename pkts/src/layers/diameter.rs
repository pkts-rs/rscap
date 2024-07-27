// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The base Diameter protocol and its derived protocols (i.e. _Diameter Applications_).
//!
//!

use crate::layers::dev_traits::*;
use crate::layers::traits::*;
use crate::layers::*;
use crate::utils;

use core::iter::Iterator;
use core::{cmp, iter, slice};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;


use bitflags::bitflags;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(DiameterMetadata)]
#[ref_type(DiameterRef)]
pub struct Diameter {
    version: u8,
    flags: CommandFlags,
    comm_code: u32,
    app_id: u32,
    hop_id: u32,
    end_id: u32,
    avps: Vec<GenericAvp>,
    payload: Option<Box<dyn LayerObject>>, // Kept for compatibility purposes // TODO: remove?
}

impl Diameter {
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    #[inline]
    pub fn flags(&self) -> CommandFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: CommandFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn comm_code(&self) -> u32 {
        self.comm_code
    }

    #[inline]
    pub fn set_comm_code(&mut self, command_code: u32) {
        assert!(
            command_code <= 0x00FFFFFF,
            "Diameter Command Code must be between 0 and 2^24 - 1"
        );
        self.comm_code = command_code;
    }

    #[inline]
    pub fn app_id(&self) -> u32 {
        self.app_id
    }

    #[inline]
    pub fn set_app_id(&mut self, application_id: u32) {
        self.app_id = application_id;
    }

    #[inline]
    pub fn hop_id(&self) -> u32 {
        self.hop_id
    }

    #[inline]
    pub fn set_hop_id(&mut self, hop_id: u32) {
        self.hop_id = hop_id;
    }

    #[inline]
    pub fn end_id(&self) -> u32 {
        self.end_id
    }

    #[inline]
    pub fn set_end_id(&mut self, end_id: u32) {
        self.end_id = end_id;
    }

    #[inline]
    pub fn avps(&self) -> &Vec<GenericAvp> {
        &self.avps
    }

    #[inline]
    pub fn avps_mut(&mut self) -> &mut Vec<GenericAvp> {
        &mut self.avps
    }
}

#[doc(hidden)]
impl FromBytesCurrent for Diameter {
    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, _bytes: &[u8]) {}

    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let diam = DiameterRef::from_bytes_unchecked(bytes);
        Diameter {
            version: diam.version(),
            flags: diam.flags(),
            comm_code: diam.comm_code(),
            app_id: diam.app_id(),
            hop_id: diam.hop_id(),
            end_id: diam.end_id(),
            avps: {
                let mut v = Vec::new();
                let i = diam.avp_iter();
                for avp in i {
                    v.push(avp.into());
                }
                v
            },
            payload: None,
        }
    }
}

impl LayerLength for Diameter {
    #[inline]
    fn len(&self) -> usize {
        20 + match self.payload.as_ref() {
            Some(p) => p.len(),
            None => 0,
        }
    }
}

impl LayerObject for Diameter {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        false // The base Diameter protocol specifies no payload
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

impl ToBytes for Diameter {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        // Version
        bytes.push(1);
        let len: u32 = self.len().try_into().unwrap();
        assert!(
            len < 0x_00FF_FFFF,
            "Diameter packet length exceeded maximum size for Message Length field"
        );
        // Message Length
        bytes.extend(&len.to_be_bytes()[1..]);
        // Command Flags
        bytes.push(self.flags.bits());
        // Command Code
        bytes.extend(&self.comm_code.to_be_bytes()[1..]);
        // Application Identifier
        bytes.extend(self.app_id.to_be_bytes());
        // Hop-by-Hop Identifier
        bytes.extend(self.hop_id.to_be_bytes());
        // End-to-End Identifier
        bytes.extend(self.end_id.to_be_bytes());
        // AVPs
        for avp in self.avps() {
            avp.to_bytes_extended(bytes);
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(Diameter)]
#[metadata_type(DiameterMetadata)]
pub struct DiameterRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> DiameterRef<'a> {
    #[inline]
    pub fn version(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> CommandFlags {
        CommandFlags::from_bits_truncate(self.data[4])
    }

    #[inline]
    pub fn unpadded_len(&self) -> u32 {
        0x_00FF_FFFF
            & u32::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn comm_code(&self) -> u32 {
        0x_00FF_FFFF
            & u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn app_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    #[inline]
    pub fn hop_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    #[inline]
    pub fn end_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 16).unwrap())
    }

    #[inline]
    pub fn avp_iter(&self) -> AvpIterRef<'a> {
        AvpIterRef {
            bytes: &self.data[20..]
        }
    }
}

impl<'a> FromBytesRef<'a> for DiameterRef<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        DiameterRef { data: packet }
    }
}

#[doc(hidden)]
impl LayerOffset for DiameterRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        None // The base Diameter protocol specifies no payload
    }
}

impl Validate for DiameterRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(curr_layer, 0) {
            Some(mut unpadded_len_arr) => {
                unpadded_len_arr[0] = 0;
                let len = u32::from_be_bytes(unpadded_len_arr) as usize;

                // Validate length field (too big) and header bytes
                if cmp::max(20, len) > curr_layer.len() {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "insufficient bytes in Diameter packet for header/Data payload",
                    });
                }

                // Validate length field (too small)
                if len < 20 {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "Diameter packet Length field was too small for header",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "Diameter packet Length field was not a multiple of 4",
                    });
                }

                // Validate AVPs
                let mut remainder = &curr_layer[20..];
                while !remainder.is_empty() {
                    match GenericAvpRef::validate(remainder) {
                        Ok(_) => break,
                        Err(e) => {
                            if let ValidationErrorClass::ExcessBytes(l) = e.class {
                                remainder = &remainder[remainder.len() - l..];
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }

                // Check for trailing bytes
                if len < curr_layer.len() {
                    Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::ExcessBytes(curr_layer.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of Diameter packet",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Diameter::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in DiameterRef for Message Length field",
            }),
        }
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // The base Diameter protocol specifies no payload
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AvpIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for AvpIterRef<'a> {
    type Item = GenericAvpRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }

        let unpadded_len = 0x_00FF_FFFF & u32::from_be_bytes(utils::to_array(self.bytes, 4).unwrap());
        let len = cmp::max(utils::padded_length::<4>(unpadded_len as usize), 12);
        let opt = GenericAvpRef::from_bytes_unchecked(&self.bytes[..len]);
        self.bytes = &self.bytes[len..];
        Some(opt)
    }
}

// Implementation of specific diameter messages (Base Diameter protocol)

pub const DIAM_BASE_COMM_ABORT_SESSION: u32 = 274;
pub const DIAM_BASE_COMM_ACCOUNTING: u32 = 271;
pub const DIAM_BASE_COMM_CAP_EXCHANGE: u32 = 257;
pub const DIAM_BASE_COMM_DEV_WATCHDOG: u32 = 280;
pub const DIAM_BASE_COMM_DISCONNECT_PEER: u32 = 282;
pub const DIAM_BASE_COMM_RE_AUTH: u32 = 258;
pub const DIAM_BASE_COMM_SESSION_TERM: u32 = 275;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(DiamBaseMetadata)]
#[ref_type(DiamBaseRef)]
pub struct DiamBase {
    // version: u8, // version must be equal to 1
    flags: CommandFlags,
    app_id: u32,
    hop_id: u32,
    end_id: u32,
    command: BaseCommand,
    payload: Option<Box<dyn LayerObject>>, // Kept for compatibility purposes // TODO: remove?
}

impl DiamBase {
    #[inline]
    pub fn version(&self) -> u8 {
        1
    }

    #[inline]
    pub fn flags(&self) -> CommandFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: CommandFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn comm_code(&self) -> u32 {
        self.command.comm_code()
    }

    #[inline]
    pub fn app_id(&self) -> u32 {
        self.app_id
    }

    #[inline]
    pub fn set_app_id(&mut self, application_id: u32) {
        self.app_id = application_id;
    }

    #[inline]
    pub fn hop_id(&self) -> u32 {
        self.hop_id
    }

    #[inline]
    pub fn set_hop_id(&mut self, hop_id: u32) {
        self.hop_id = hop_id;
    }

    #[inline]
    pub fn end_id(&self) -> u32 {
        self.end_id
    }

    #[inline]
    pub fn set_end_id(&mut self, end_id: u32) {
        self.end_id = end_id;
    }

    #[inline]
    pub fn command(&self) -> &BaseCommand {
        &self.command
    }

    #[inline]
    pub fn command_mut(&mut self) -> &mut BaseCommand {
        &mut self.command
    }
}

#[doc(hidden)]
impl FromBytesCurrent for DiamBase {
    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, _bytes: &[u8]) {}

    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let diam = DiamBaseRef::from_bytes_unchecked(bytes);
        let mut avps = Vec::new();
        let iter = diam.avp_iter();
        for avp in iter {
            avps.push(avp.into());
        }

        DiamBase {
            flags: diam.flags(),
            app_id: diam.app_id(),
            hop_id: diam.hop_id(),
            end_id: diam.end_id(),
            command: match (
                diam.comm_code(),
                diam.flags().contains(CommandFlags::REQUEST),
            ) {
                (DIAM_BASE_COMM_ABORT_SESSION, true) => {
                    BaseCommand::AbortSessionReq(AbortSessionReq { avps })
                }
                _ => todo!(),
            },
            payload: None,
        }
    }
}

impl LayerLength for DiamBase {
    #[inline]
    fn len(&self) -> usize {
        20 + match self.payload.as_ref() {
            Some(p) => p.len(),
            None => 0,
        }
    }
}

impl LayerObject for DiamBase {
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

impl ToBytes for DiamBase {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        // Version
        bytes.push(1);
        let len: u32 = self.len().try_into().unwrap();
        assert!(
            len < 0x_00FF_FFFF,
            "Diameter packet length exceeded maximum size for Message Length field"
        );
        // Message Length
        bytes.extend(&len.to_be_bytes()[1..]);
        // Command Flags
        bytes.push(self.flags.bits());
        // Command Code

        // TODO: add

        // Application Identifier
        bytes.extend(self.app_id.to_be_bytes());
        // Hop-by-Hop Identifier
        bytes.extend(self.hop_id.to_be_bytes());
        // End-to-End Identifier
        bytes.extend(self.end_id.to_be_bytes());
        // AVPs
        todo!()
    }
}

#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(DiamBase)]
#[metadata_type(DiamBaseMetadata)]
pub struct DiamBaseRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> DiamBaseRef<'a> {
    #[inline]
    pub fn version(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn flags(&self) -> CommandFlags {
        CommandFlags::from_bits_truncate(self.data[4])
    }

    #[inline]
    pub fn unpadded_len(&self) -> u32 {
        0x_00FF_FFFF & u32::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    #[inline]
    pub fn comm_code(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn app_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    #[inline]
    pub fn hop_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    #[inline]
    pub fn end_id(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 16).unwrap())
    }

    #[inline]
    pub fn avp_iter(&self) -> BaseAvpIterRef<'a> {
        BaseAvpIterRef {
            bytes: &self.data[20..],
        }
    }
}

impl<'a> FromBytesRef<'a> for DiamBaseRef<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        DiamBaseRef { data: packet }
    }
}

#[doc(hidden)]
impl LayerOffset for DiamBaseRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _ayer_type: LayerId) -> Option<usize> {
        None // Diameter has no payload
    }
}

impl Validate for DiamBaseRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(curr_layer, 0) {
            Some(unpadded_len_arr) => {
                let len = (0x_00FF_FFFF & u32::from_be_bytes(unpadded_len_arr)) as usize;

                // Validate length field (too big) and header bytes
                if cmp::max(20, len) > curr_layer.len() {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "insufficient bytes in Diameter packet for header/Data payload",
                    });
                }

                // Validate length field (too small)
                if len < 20 {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "Diameter packet Length field was too small for header",
                    });
                }

                if len % 4 != 0 {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InvalidValue,
                        #[cfg(feature = "error_string")]
                        reason: "Diameter packet Length field was not a multiple of 4",
                    });
                }

                // Validate AVPs
                let mut remainder = &curr_layer[20..];
                while !remainder.is_empty() {
                    match GenericAvpRef::validate(remainder) {
                        Ok(_) => break,
                        Err(e) => {
                            if let ValidationErrorClass::ExcessBytes(l) = e.class {
                                remainder = &remainder[remainder.len() - l..];
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }

                // Check for trailing bytes
                if len < curr_layer.len() {
                    Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::ExcessBytes(curr_layer.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of Diameter packet",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Diameter::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in DiameterRef for Message Length field",
            }),
        }
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // Diameter has no payload
    }
}

/*
#[derive(Clone, Copy, Debug)]
pub struct BaseAvpIterRef<'a> {
    bytes: &'a [u8],
}

impl<'b> Iterator for BaseAvpIterRef<'b> {
    type Item<'a> = BaseAvpRef<'a> where Self: 'a;

    fn next<'a>(&'a mut self) -> Option<Self::Item<'a>> {
        if self.bytes.is_empty() {
            return None;
        }

        let unpadded_len = 0x_00FF_FFFF
            & u32::from_be_bytes(
                utils::to_array(self.bytes, 4)
                    .expect("insufficient bytes in Diameter AVP for header values"),
            );
        let len = cmp::max(utils::padded_length::<4>(unpadded_len as usize), 12);
        let opt = BaseAvpRef::from_bytes_unchecked(
            self.bytes
                .get(..len)
                .expect("insufficient bytes in Diameter AVP for header and/or Data field"),
        );
        self.bytes = &self.bytes[len..];
        Some(opt)
    }
}
*/

/*
// Implementation of 3GPP S6a Diamemter messages


#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(S6aMetadata)]
#[ref_type(S6aRef)]
pub struct S6a {
    avps: Vec<u8>,
}

#[doc(hidden)]
impl FromBytesCurrent for S6a {
    fn from_bytes_payload_unchecked_default(&mut self, bytes: &[u8]) {
        todo!()
    }

    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerLength for S6a {
    fn len(&self) -> usize {
        todo!()
    }
}

impl LayerObject for S6a {
    #[inline]
    fn can_add_payload_default(&self, payload: &dyn LayerObject) -> bool {
        false // No generic payloads are relayed over the S6a protocol
    }

    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        todo!()
    }

    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        todo!()
    }

    fn has_payload(&self) -> bool {
        todo!()
    }

    fn remove_payload(&mut self) -> Box<dyn LayerObject> {
        todo!()
    }

    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        todo!()
    }
}

impl ToBytes for S6a {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(S6a)]
#[metadata_type(S6aMetadata)]
pub struct S6aRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> FromBytesRef<'a> for S6aRef<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        S6aRef { data: packet }
    }
}

#[doc(hidden)]
impl LayerOffset for S6aRef<'_> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        todo!()
    }
}

impl Validate for S6aRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}
*/

// =============================================================================
//                             Internal Structures
// =============================================================================

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct GenericCommandFlags: u8 {
        const REQUEST = 0b_1000_0000;
        const PROXIABLE = 0b_0100_0000;
        const ERROR = 0b_0010_0000;
        const RETRANSMITTED = 0b_0001_0000;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct CommandFlags: u8 {
        const REQUEST = 0b_1000_0000;
        const PROXIABLE = 0b_0100_0000;
        const ERROR = 0b_0010_0000;
        const RETRANSMITTED = 0b_0001_0000;
    }
}

#[derive(Clone, Debug)]
pub enum BaseCommand {
    AbortSessionReq(AbortSessionReq),
    AbortSessionAns(AbortSessionAns),
    AccountingReq(AccountingReq),
    AccountingAns(AccountingAns),
    CapExchangeReq(CapExchangeReq),
    CapExchangeAns(CapExchangeAns),
    DevWatchdogReq(DevWatchdogReq),
    DevWatchdogAns(DevWatchdogAns),
    DisconnectPeerReq(DisconnectPeerReq),
    DisconnectPeerAns(DisconnectPeerAns),
    ReAuthReq(ReAuthReq),
    ReAuthAns(ReAuthAns),
    SessionTermReq(SessionTermReq),
    SessionTermAns(SessionTermAns),
    /* TODO: Uncomprehensive list annotation */
}

impl BaseCommand {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    pub fn from_bytes_unchecked(_bytes: &[u8]) -> Self {
        todo!()
    }

    pub fn validate(_bytes: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[inline]
    pub fn comm_code(&self) -> u32 {
        match self {
            Self::AbortSessionReq(_) | Self::AbortSessionAns(_) => 274,
            Self::AccountingReq(_) | Self::AccountingAns(_) => 271,
            Self::CapExchangeReq(_) | Self::CapExchangeAns(_) => 257,
            Self::DevWatchdogReq(_) | Self::DevWatchdogAns(_) => 280,
            Self::DisconnectPeerReq(_) | Self::DisconnectPeerAns(_) => 282,
            Self::ReAuthReq(_) | Self::ReAuthAns(_) => 258,
            Self::SessionTermReq(_) | Self::SessionTermAns(_) => 275,
            // _ => panic!("Internal Error--unexpected Command Code enum variant for comm_code()"),
        }
    }

    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.to_bytes_extended(&mut v);
        v
    }

    #[inline]
    pub fn to_bytes_extended(&self, _bytes: &mut Vec<u8>) {
        _bytes.push(0); // TODO: remove
        todo!()
    }
}

pub enum BaseCommandRef<'a> {
    AbortSessionReq(AbortSessionReqRef<'a>),
    AbortSessionAns(AbortSessionAns),
    AccountingReq(AccountingReq),
    AccountingAns(AccountingAns),
    CapExchangeReq(CapExchangeReq),
    CapExchangeAns(CapExchangeAns),
    DevWatchdogReq(DevWatchdogReq),
    DevWatchdogAns(DevWatchdogAns),
    DisconnectPeerReq(DisconnectPeerReq),
    DisconnectPeerAns(DisconnectPeerAns),
    ReAuthReq(ReAuthReq),
    ReAuthAns(ReAuthAns),
    SessionTermReq(SessionTermReq),
    SessionTermAns(SessionTermAns),
    /* TODO: Uncomprehensive list annotation */
}

#[derive(Clone, Debug)]
pub struct AbortSessionReq {
    avps: Vec<BaseAvp>,
}

impl AbortSessionReq {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(_bytes: &[u8]) -> Self {
        todo!()
    }

    #[inline]
    pub fn validate(_bytes: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[inline]
    pub fn avps(&self) -> &Vec<BaseAvp> {
        &self.avps
    }

    #[inline]
    pub fn avps_mut(&mut self) -> &mut Vec<BaseAvp> {
        &mut self.avps
    }
}

pub struct AbortSessionReqRef<'a> {
    data: &'a [u8],
}

impl<'a> AbortSessionReqRef<'a> {}

#[derive(Clone, Debug)]
pub struct AbortSessionAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct AccountingReq {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct AccountingAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct CapExchangeReq {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct CapExchangeAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct DevWatchdogReq {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct DevWatchdogAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct DisconnectPeerReq {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct DisconnectPeerAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct ReAuthReq {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct ReAuthAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct SessionTermReq {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub struct SessionTermAns {
    avps: Vec<BaseAvp>,
}

#[derive(Clone, Debug)]
pub enum BaseAvp {
    Other(GenericAvp),
}

impl From<BaseAvpRef<'_>> for BaseAvp {
    #[inline]
    fn from(value: BaseAvpRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&BaseAvpRef<'_>> for BaseAvp {
    fn from(value: &BaseAvpRef<'_>) -> Self {
        match value {
            BaseAvpRef::Other(avp) => BaseAvp::Other(avp.into()),
            //            _ => todo!(),
        }
    }
}

pub enum BaseAvpRef<'a> {
    Other(GenericAvpRef<'a>),
}

impl<'a> BaseAvpRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(_bytes: &[u8]) -> Self {
        todo!()
    }

    #[inline]
    pub fn validate(_bytes: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BaseAvpIterRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for BaseAvpIterRef<'a> {
    type Item = BaseAvpRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }

        let unpadded_len = 0x_00FF_FFFF & u32::from_be_bytes(utils::to_array(self.bytes, 4).unwrap());
        let len = cmp::max(utils::padded_length::<4>(unpadded_len as usize), 12);
        let opt = BaseAvpRef::from_bytes_unchecked(&self.bytes[..len]);
        self.bytes = &self.bytes[len..];
        Some(opt)
    }
}

// TODO: write a macro to generalize work for AVPs
pub mod avp {
    use super::{BaseAvp, GenericAvp};

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::string::String;
    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::vec::Vec;

    pub struct AcctInterimInterval {
        interval: u32,
    }

    #[repr(i32)]
    pub enum AcctRealtimeRequired {
        DeliverAndGrant, // = 1
        GrantAndStore,   // = 2
        GrantAndLose,    // = 3
        Unknown(i32),
    }

    pub struct AcctMultiSessionId {
        session_id: String,
    }

    pub struct AcctRecordNumber {
        record_number: u32,
    }

    pub enum AcctRecordType {
        EventRecord,   // = 1
        StartRecord,   // = 2
        InterimRecord, // = 3
        StopRecord,    // = 4
        Unknown(i32),
    }

    pub struct AcctSessionId {
        session_id: Vec<u8>,
    }

    pub struct AcctSubSessionId {
        sub_session_id: u64,
    }

    pub struct AcctApplicationId {
        application_id: u32,
    }

    pub struct AuthApplicationId {
        application_id: u32,
    }

    pub enum AuthRequestType {
        AuthenticateOnly,      // = 1
        AuthorizeOnly,         // = 2
        AuthorizeAuthenticate, // = 3
        Unknown(i32),
    }

    pub struct AuthLifetime {
        lifetime: u32,
    }

    pub struct AuthGracePeriod {
        grace_period: u32,
    }

    pub enum AuthSessionState {
        StateMaintained,   // = 0
        NoStateMaintained, // = 1
        Unknown(i32),
    }

    pub enum ReauthRequestType {
        AuthorizeOnly,         // = 0
        AuthorizeAuthenticate, // = 1
        Unknown(i32),
    }

    pub struct Class {
        class: Vec<u8>,
    }

    pub struct DestinationHost {
        host_id: String, // Diameter Identity
    }

    pub struct DestinationRealm {
        realm_id: String, // Diameter Identity
    }

    pub enum DisconnectCause {
        Rebooting,       // = 0
        Busy,            // = 1
        DoNotWantToTalk, // = 2
        Unknown(i32),
    }

    pub struct ErrorMessage {
        message: String,
    }

    pub struct ErrorReportingHost {
        id: String, // Diameter Identity
    }

    pub struct EventTimestamp {
        time: u32,
    }

    pub struct ExperimentalResult {
        avps: Vec<BaseAvp>, // 1x Vendor-Id, 1x Experimental-Result-Code (any order)
    }

    pub struct ExperimentalResultCode {
        res_code: u32,
    }

    pub struct FailedAvp {
        failed_avps: Vec<GenericAvp>,
    }

    pub struct FirmwareRevision {
        rev: u32,
    }

    pub struct HostIpAddress {
        // Address type:
        addr_type: u16,
        addr_value: Vec<u8>,
    }

    pub struct InbandSecurityId {
        security_id: u32,
    }

    pub struct MultiRoundTimeout {
        timeout: u32,
    }

    pub struct OriginHost {
        id: String, // Diameter Identity
    }

    pub struct OriginRealm {
        id: String, // Diameter Identity
    }

    pub struct OriginStateId {
        state_id: u32,
    }

    pub struct ProductName {
        name: String,
    }

    pub struct ProxyHost {
        id: String, // Diameter Identity
    }

    pub struct ProxyInfo {
        apvs: Vec<BaseAvp>, // { Proxy-Host } { Proxy-State } *[ AVP ]
    }

    pub struct ProxyState {
        state: Vec<u8>,
    }

    pub struct RedirectHost {
        uri: String, // Diameter URI
    }

    pub enum RedirectHostUsage {
        DontCache,           // = 0
        AllSession,          // = 1
        AllRealm,            // = 2
        RealmAndApplication, // = 3
        AllApplication,      // = 4
        AllHost,             // = 5
        AllUser,             // = 6
        Unknown(i32),
    }

    pub struct RedirectMaxCacheTime {
        cache_time: u32,
    }

    pub struct ResultCode {
        code: u32,
    }

    pub struct RouteRecord {
        id: String, // Diameter Identity
    }

    pub struct SessionId {
        id: String,
    }

    pub struct SessionTimeout {
        timeout: u32,
    }

    pub struct SessionBinding {
        binding: u32,
    }

    pub enum SessionServerFailover {
        RefuseService,        // = 0
        TryAgain,             // = 1
        AllowService,         // = 2
        TryAgainAllowService, // = 3
    }

    pub struct SupportedVendorId {
        id: u32,
    }

    pub enum TerminationCause {
        Reserved,                     // = 0
        DiameterLogout,               // = 1
        DiameterServiceNotProvided,   // = 2
        DiameterBadAnswer,            // = 3
        DiameterAdministrative,       // = 4
        DiameterLinkBroken,           // = 5
        DiameterAuthExpired,          // = 6
        DiameterUserMoved,            // = 7
        DiameterSessionTimeout,       // = 8
        UserRequest,                  // = 11
        LostCarrier,                  // = 12
        LostService,                  // = 13
        IdleTimeout,                  // = 14
        SessionTimeout,               // = 15
        AdminReset,                   // = 16
        AdminReboot,                  // = 17
        PortError,                    // = 18
        NasError,                     // = 19
        NasRequest,                   // = 20
        NasReboot,                    // = 21
        PortUnneeded,                 // = 22
        PortPreempted,                // = 23
        PortSuspended,                // = 24
        ServiceUnavailable,           // = 25
        Callback,                     // = 26
        UserError,                    // = 27
        HostRequest,                  // = 28
        SupplicantRestart,            // = 29
        ReauthenticationFailure,      // = 30
        PortReinitialized,            // = 31
        PortAdministrativelyDisabled, // = 32
        Unassigned(i32),              // < 0, 9, 10, > 32
    }

    pub struct UserName {
        username: String,
    }

    pub struct VendorId {
        id: u32,
    }

    pub struct VendorSpecificApplicationId {
        avps: Vec<BaseAvp>, // 1 Vendor-Id required, 1 Auth-Application-Id and 1 Acct-Application-Id both optional
    }
}

// Data types

/*
pub struct DiameterIdentity {
    realm: Vec<u8>,
}

pub struct DiameterIdentityRef<'a> {
    realm: &'a [u8],
}

*/

// End Data Types

/*
pub enum S6aCommand {
    UpdateLocationReq,
    UpdateLocationAns,
    CancelLocationReq,
    CancelLocationAns,
    AuthInfoReq,
    AuthInfoAns,
    InsertSubDataReq,
    InsertSubDataAns,
    DeleteSubDataReq,
    DeleteSubDataAns,
    PurgeUeReq,
    PurgeUeAns,
    ResetReq,
    ResetAns,
    NotifyReq,
    NotifyAns,
}
*/

///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           AVP Code                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V M P r r r r r|                  AVP Length                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Vendor-ID (opt)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Data ...
/// +-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug)]
pub struct GenericAvp {
    code: u32,
    flags: AvpFlags,
    vendor_id: Option<u32>,
    data: Vec<u8>,
}

impl GenericAvp {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        GenericAvpRef::from_bytes_unchecked(bytes).into()
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        GenericAvpRef::validate(bytes)
    }

    #[inline]
    pub fn code(&self) -> u32 {
        self.code
    }

    #[inline]
    pub fn set_code(&mut self, code: u32) {
        self.code = code;
    }

    #[inline]
    pub fn flags(&self) -> AvpFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: AvpFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn unpadded_len(&self) -> u32 {
        assert!(
            self.data.len() < 0x_00FF_FFFF,
            "AVP Data payload exceeded maximum size for AVP Length field"
        );
        let len = (12 + self.data.len()).try_into().unwrap();
        len
    }

    #[inline]
    pub fn len(&self) -> usize {
        12 + utils::padded_length::<4>(self.data.len())
    }

    #[inline]
    pub fn vendor_id(&self) -> Option<u32> {
        self.vendor_id
    }

    #[inline]
    pub fn set_vendor_id(&mut self, vendor_id: Option<u32>) {
        self.flags
            .set(AvpFlags::VENDOR_SPECIFIC, self.vendor_id.is_some());
        self.vendor_id = vendor_id;
    }

    #[inline]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.to_bytes_extended(&mut v);
        v
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        // AVP Code
        bytes.extend(self.code.to_be_bytes());
        // Flags
        bytes.push(self.flags.bits());
        // AVP Length
        bytes.extend(&self.unpadded_len().to_be_bytes()[1..]);
        // Vendor ID
        if let Some(id) = self.vendor_id {
            bytes.extend(id.to_be_bytes());
        }
        // Data
        bytes.extend(&self.data);
        // Padding
        bytes.extend(iter::repeat(0).take(self.len() - self.unpadded_len() as usize));
    }
}

impl From<GenericAvpRef<'_>> for GenericAvp {
    #[inline]
    fn from(value: GenericAvpRef<'_>) -> Self {
        Self::from(&value)
    }
}

impl From<&GenericAvpRef<'_>> for GenericAvp {
    fn from(value: &GenericAvpRef<'_>) -> Self {
        GenericAvp {
            code: value.code(),
            flags: value.flags(),
            vendor_id: value.vendor_id(),
            data: Vec::from(value.data()),
        }
    }
}

pub struct GenericAvpRef<'a> {
    data: &'a [u8],
}

impl<'a> GenericAvpRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        GenericAvpRef { data: bytes }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match utils::to_array(bytes, 4) {
            Some(unpadded_len_arr) => {
                let flags = AvpFlags::from_bits_truncate(unpadded_len_arr[0]);
                let unpadded_len = (0x_00FF_FFFF & u32::from_be_bytes(unpadded_len_arr)) as usize;
                let len = utils::padded_length::<4>(unpadded_len);

                let minimum_length = if flags.contains(AvpFlags::VENDOR_SPECIFIC) {
                    12
                } else {
                    8
                };

                // Validate length field (too big) and header bytes
                if cmp::max(minimum_length, len) > bytes.len() {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "insufficient bytes in Diameter AVP for Data payload",
                    });
                }

                // Validate length field (too small)
                if unpadded_len < minimum_length {
                    return Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        #[cfg(feature = "error_string")]
                        reason: "Diameter AVP Length field was too small for header",
                    });
                }

                // Validate padding
                for b in bytes.iter().take(len).skip(unpadded_len) {
                    if *b != 0 {
                        return Err(ValidationError {
                            layer: Diameter::name(),
                            class: ValidationErrorClass::UnusualPadding,
                            #[cfg(feature = "error_string")]
                            reason: "non-zero padding values found at end of Diameter AVP",
                        });
                    }
                }

                if len < bytes.len() {
                    Err(ValidationError {
                        layer: Diameter::name(),
                        class: ValidationErrorClass::ExcessBytes(bytes.len() - len),
                        #[cfg(feature = "error_string")]
                        reason: "extra bytes remain at end of Diameter AVP",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(ValidationError {
                layer: Diameter::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in Diameter AVP for header",
            }),
        }
    }

    #[inline]
    pub fn code(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn flags(&self) -> AvpFlags {
        AvpFlags::from_bits_truncate(self.data[4])
    }

    #[inline]
    pub fn unpadded_len(&self) -> u32 {
        0x_00FF_FFFF & u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        utils::padded_length::<4>(self.unpadded_len() as usize)
    }

    pub fn vendor_id(&self) -> Option<u32> {
        if self.flags().contains(AvpFlags::VENDOR_SPECIFIC) {
            Some(u32::from_be_bytes(utils::to_array(self.data, 8).unwrap()))
        } else {
            None
        }
    }

    pub fn data(&self) -> &[u8] {
        let minimum_length = if self.flags().contains(AvpFlags::VENDOR_SPECIFIC) {
            12
        } else {
            8
        };

        let end = self.unpadded_len() as usize;
        assert!(end >= minimum_length, "error retrieving AVP Data field--length field in Diameter AVP was not long enough for AVP header");
        &self.data[minimum_length..end]
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct AvpFlags: u8 {
        const VENDOR_SPECIFIC = 0b_1000_0000;
        const MANDATORY = 0b_0100_0000;
    }
}
