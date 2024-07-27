// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The collection of various protocol layers implemented by this library.
//!
//! The [`Layer`] type is a fundamental abstraction used in this library for data. In general,
//! most communication protocols are organized into multiple encapsulated layers of data, where
//! each layer performs a distinct purpose in relaying information from one peer to another. Each
//! layer can be generalized into a header and one or more payloads, where the header contains data
//! specific to the operation of that layer and the payload(s) contains the next layer(s) of data.
//!
//! Layers for all sorts of different data protocols are provided in this submodule, as well as
//! traits that make operating on multiple layers easier.
//!
//! The submodule is organized so that tightly related layers are each within their own modules. For
//! instance, [`Ipv4`], [`Ipv6`], and IPSec-related layers are all contained within the [`ip`]
//! module. In addition to this, the [`traits`] module contains traits that enable `Layer` use,
//! while [`dev_traits`] contains `Layer` traits that are only useful for developing new `Layer`
//! types.
//!
//! [`Ipv4`]: struct@crate::layers::ip::Ipv4
//! [`Ipv6`]: struct@crate::layers::ip::Ipv6

pub mod dev_traits;
pub mod diameter;
pub(crate) mod example;
pub mod icmp;
pub mod ip;
pub mod l2;
pub mod mysql;
pub mod psql;
pub mod sctp;
pub mod tcp;
pub mod traits;
pub mod udp;

use core::fmt::Debug;

use crate::error::*;
use crate::layers::dev_traits::*;
use crate::layers::traits::*;

use pkts_macros::{Layer, LayerRef, StatelessLayer};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

/*
pub enum Cardinal<T> {
    None,
    One(T),
    Many(Vec<T>)
}
*/

/// A raw [`Layer`] composed of unstructured bytes.
///
/// This type is primarily used when inner layers cannot be inferred or interpreted
/// automatically by a given method call, or when payload layer data is literally
/// meant to be interpreted as an opaque array of bytes. A [`Raw`] layer does not
/// necessarily indicate the presence of only one `Layer` in its contained
/// bytes; there may be multiple encapsulated sublayers within a `Raw` payload,
/// depending on how the user interprets its content. For instance, a [`Ipv4`]/[`Tcp`]
/// packet may contain a tunneled [`Ipv4`]/[`Udp`] packet as its payload, but decoding
/// such a packet from raw bytes would only yield [`Ipv4`]/[`Tcp`]/[`Raw`] since
/// [`pkts`](crate) can't infer every possible layer combination.
///
/// [`Raw`]: struct@Raw
/// [`Ipv4`]: struct@crate::layers::ip::Ipv4
/// [`Tcp`]: struct@crate::layers::tcp::Tcp
/// [`Udp`]: struct@crate::layers::udp::Udp
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(RawMetadata)]
#[ref_type(RawRef)]
pub struct Raw {
    data: Vec<u8>,
    // Kept for the sake of compatibility, but not normally used (unless a custom_layer_selection overrides it)
    // payload: Option<Box<dyn LayerObject>>,
}

impl LayerLength for Raw {
    #[inline]
    fn len(&self) -> usize {
        self.data.len()
        //            + match &self.payload {
        //                Some(i) => i.len(),
        //                None => 0,
        //            }
    }
}

impl LayerObject for Raw {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        false
    }

    #[inline]
    fn add_payload_unchecked(&mut self, _payload: Box<dyn LayerObject>) {
        panic!("`Raw` layer cannot have a payload")
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        &[]
    }

    #[inline]
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        &mut []
    }

    #[inline]
    fn remove_payload_at(&mut self, _index: usize) -> Option<Box<dyn LayerObject>> {
        None
    }
}

impl ToBytes for Raw {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        bytes.extend(&self.data);
        Ok(())
    }
}

impl FromBytesCurrent for Raw {
    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, _bytes: &[u8]) {
        // pass
    }

    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        Raw {
            data: Vec::from(bytes),
        }
    }
}

impl Raw {
    /// A slice of the entire contents of the `Raw` layer.
    #[inline]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// A mutable slice of the entire contents of the `Raw` layer.
    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

/// A reference to a raw [`Layer`] composed of unstructured bytes.
///
/// This type is primarily used when inner layers cannot be inferred or interpreted
/// automatically by a given method call, or when payload layer data is literally
/// meant to be interpreted as an opaque array of bytes. A [`Raw`] layer does not
/// necessarily indicate the presence of only one `Layer` in its contained
/// bytes; there may be multiple encapsulated sublayers within a `Raw` payload,
/// depending on how the user interprets its content. For instance, a [`Ipv4`]/[`Tcp`]
/// packet may contain a tunneled [`Ipv4`]/[`Udp`] packet as its payload, but decoding
/// such a packet from raw bytes would only yield [`Ipv4`]/[`Tcp`]/[`Raw`] since
/// [`pkts`](crate) can't infer every possible layer combination.
///
/// [`Ipv4`]: struct@crate::layers::ip::Ipv4
/// [`Tcp`]: struct@crate::layers::tcp::Tcp
/// [`Udp`]: struct@crate::layers::udp::Udp
/// [`Raw`]: struct@Raw
#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(Raw)]
#[metadata_type(RawMetadata)]
pub struct RawRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl RawRef<'_> {
    /// A slice of the entire contents of the `Raw` layer.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> FromBytesRef<'a> for RawRef<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        RawRef { data: packet }
    }
}

#[doc(hidden)]
impl LayerOffset for RawRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        None
    }
}

impl Validate for RawRef<'_> {
    #[inline]
    fn validate_current_layer(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(())
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(())
    }
}
