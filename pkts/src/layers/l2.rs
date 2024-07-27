// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Ethernet and associated link-layer protocols.
//!
//!

use core::slice;

use pkts_macros::{Layer, LayerRef, StatelessLayer};

use crate::layers::dev_traits::*;
use crate::layers::ip::{Ipv4, Ipv4Ref, Ipv6, Ipv6Ref};
use crate::layers::traits::*;
use crate::layers::{Raw, RawRef};
use crate::{error::*, utils};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

const ETH_PROTOCOL_IP: u16 = 0x0800;
const ETH_PROTOCOL_EXPERIMENTAL: u16 = 0x88B5;

/// A basic 802.3 Ethernet frame.
///
/// An 802.3 Ethernet frame consists of source and destination MAC addresses, Ether Type and
/// payload. This `Layer` matches the structure of "cooked" L2 frames in Linux, as well as that
/// of general 802.3 Ethernet packets. Note that `Ether` does not include any 802.1Q VLAN tags
/// within the header or a checksum at the end of the payload.
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(EtherMetadata)]
#[ref_type(EtherRef)]
pub struct Ether {
    src: [u8; 6],
    dst: [u8; 6],
    payload: Option<Box<dyn LayerObject>>,
}

impl Ether {
    /// The source MAC address contained within the Ethernet frame.
    #[inline]
    pub fn src_mac(&self) -> [u8; 6] {
        self.src
    }

    /// The destination MAC address contained within the Ethernet frame.
    #[inline]
    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst
    }

    /// The Ether Type contained within the Ethernet frame.
    ///
    /// This field determines the type and structure of the Ethernet's
    /// payload.
    pub fn eth_type(&self) -> u16 {
        match self.payload.as_ref() {
            None => ETH_PROTOCOL_EXPERIMENTAL, // default to experimental protocol indicator
            Some(p) => {
                let payload_metadata = p
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn EtherPayloadMetadata>()
                    .expect("unknown payload protocol found in Ether packet");
                payload_metadata.eth_type()
            }
        }
    }
}

#[doc(hidden)]
impl FromBytesCurrent for Ether {
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        let ether = EtherRef::from_bytes_unchecked(bytes);
        if ether.payload_raw().is_empty() {
            self.payload = None;
        } else {
            self.payload = match ether.eth_type() {
                ETH_PROTOCOL_IP if bytes[14] >> 4 == 4 => {
                    Some(Box::new(Ipv4::from_bytes_unchecked(ether.payload_raw())))
                }
                /* Add additional Networ layer protocols here */
                _ => Some(Box::new(Raw::from_bytes_unchecked(ether.payload_raw()))),
            };
        }
    }

    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let ether = EtherRef::from_bytes_unchecked(bytes);
        Ether {
            src: ether.src_mac(),
            dst: ether.dst_mac(),
            payload: None,
        }
    }
}

impl LayerLength for Ether {
    #[inline]
    fn len(&self) -> usize {
        14 + self.payload.as_ref().map_or(0, |p| p.len())
    }
}

impl LayerObject for Ether {
    fn can_add_payload_default(&self, payload: &dyn LayerObject) -> bool {
        payload
            .layer_metadata()
            .as_any()
            .downcast_ref::<&dyn EtherPayloadMetadata>()
            .is_some()
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

impl ToBytes for Ether {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        let start = bytes.len();
        bytes.extend(self.src);
        bytes.extend(self.dst);
        match self.payload.as_ref() {
            None => {
                bytes.extend(ETH_PROTOCOL_EXPERIMENTAL.to_be_bytes());
                Ok(())
            }
            Some(p) => {
                bytes.extend(
                    match p
                        .layer_metadata()
                        .as_any()
                        .downcast_ref::<&dyn EtherPayloadMetadata>()
                    {
                        Some(m) => m.eth_type(),
                        None => ETH_PROTOCOL_EXPERIMENTAL,
                    }
                    .to_be_bytes(),
                );
                p.to_bytes_checksummed(bytes, Some((Self::layer_id(), start)))
            }
        }
    }
}

/// A reference to a basic 802.3 Ethernet frame.
///
/// An 802.3 Ethernet frame consists of source and destination MAC addresses, Ether Type and
/// payload. This `Layer` matches the structure of "cooked" L2 frames in Linux, as well as that
/// of general 802.3 Ethernet packets. Note that `Ether` does not include any 802.1Q VLAN tags
/// within the header or a checksum at the end of the payload.
#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Ether)]
#[metadata_type(EtherMetadata)]
pub struct EtherRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> EtherRef<'a> {
    /// The source MAC address contained within the Ethernet frame.
    #[inline]
    pub fn src_mac(&self) -> [u8; 6] {
        utils::to_array(self.data, 0).unwrap()
    }

    /// The destination MAC address contained within the Ethernet frame.
    #[inline]
    pub fn dst_mac(&self) -> [u8; 6] {
        utils::to_array(self.data, 6).unwrap()
    }

    /// The Ether Type contained within the Ethernet frame.
    ///
    /// This field determines the type and structure of the Ethernet's
    /// payload.
    #[inline]
    pub fn eth_type(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 12).unwrap())
    }

    /// The payload bytes of the Ethernet frame.
    #[inline]
    pub fn payload_raw(&self) -> &[u8] {
        &self.data[14..]
    }
}

impl<'a> FromBytesRef<'a> for EtherRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        EtherRef { data: bytes }
    }
}

impl<'a> LayerOffset for EtherRef<'a> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        if bytes.len() <= 14 {
            return None;
        }

        let eth_type = u16::from_be_bytes(utils::to_array(bytes, 12).unwrap());
        match eth_type {
            ETH_PROTOCOL_IP => match bytes[14] >> 4 {
                0x04 => {
                    if layer_type == Ipv4::layer_id() {
                        Some(14)
                    } else {
                        Ipv4Ref::payload_byte_index_default(&bytes[14..], layer_type)
                            .map(|val| 14 + val)
                    }
                }
                0x06 => {
                    if layer_type == Ipv6::layer_id() {
                        Some(14)
                    } else {
                        Ipv6Ref::payload_byte_index_default(&bytes[14..], layer_type)
                    }
                }
                /* Add new Internet Protocol (IP) protocols here */
                _ => None,
            },
            /* Add new Network layer protocols here */
            _ => None,
        }
    }
}

impl<'a> Validate for EtherRef<'a> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() < 14 {
            Err(ValidationError {
                layer: Ether::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in Ether layer for header fields",
            })
        } else {
            Ok(())
        }
    }

    #[doc(hidden)]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() == 14 {
            return Ok(());
        }

        let eth_type = u16::from_be_bytes(*utils::get_array(curr_layer, 10).unwrap());
        match eth_type {
            ETH_PROTOCOL_IP => match curr_layer[14] {
                0x04 => Ipv4Ref::validate(&curr_layer[14..]),
                _ => RawRef::validate(&curr_layer[14..]), // Add new IP protocols here
            },
            _ => RawRef::validate(&curr_layer[14..]), // Add new L3 protocols here
        }
    }
}
