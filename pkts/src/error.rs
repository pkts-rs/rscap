// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Error types for [`pkts`](crate).
//!
//!

/// Indicates an error in validating a packet.
#[derive(Copy, Clone, Debug)]
pub struct ValidationError {
    /// The layer in which the validation error occurred
    pub layer: &'static str,
    /// The general class of error that occurred
    pub class: ValidationErrorClass,
    /// A more descriptive string describing the nature of the error
    #[cfg(feature = "error_string")]
    pub reason: &'static str,
}

/// The general class of error encountered while validating a packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ValidationErrorClass {
    /// An incompatible payload was assigned to the given layer.
    InvalidPayloadLayer,
    /// The packet was cut short and needed more bytes to be whole.
    InsufficientBytes,
    /// A size field conflicts with the actual size of the field's contents.
    ///
    /// This error also manifests when two size fields conflict.
    InvalidSize,
    /// A field was outside the range of expected values.
    InvalidValue,
    /// Indicates that padding has a non-standard length or value.
    UnusualPadding,
    /// The data had a number of unused excess bytes following the packet.
    ExcessBytes(usize),
}

/// An error in serializing a packet into its byte representation.
///
/// This error is nearly always the result
#[derive(Copy, Clone, Debug)]
pub struct SerializationError {
    class: SerializationErrorClass,
    layer: &'static str,
}

impl SerializationError {
    #[inline]
    pub(crate) fn length_encoding(layer: &'static str) -> Self {
        SerializationError {
            class: SerializationErrorClass::LengthEncoding,
            layer,
        }
    }

    #[inline]
    pub(crate) fn insufficient_buffer(layer: &'static str) -> Self {
        SerializationError {
            class: SerializationErrorClass::LengthEncoding,
            layer,
        }
    }

    #[inline]
    pub(crate) fn bad_upper_layer(layer: &'static str) -> Self {
        SerializationError {
            class: SerializationErrorClass::BadUpperLayer,
            layer,
        }
    }

    pub fn class(&self) -> SerializationErrorClass {
        self.class
    }

    pub fn layer(&self) -> &'static str {
        self.layer
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SerializationErrorClass {
    /// Packet contained too many bytes to encode within some `length` field.
    LengthEncoding,

    InsufficientBuffer,
    /// A layer expected a particular value from an upper layer (such as [`Tcp`] requiring [`Ipv4`]
    /// or [`Ipv6`] to calculate a checksum).
    ///
    /// [`Ipv4`]: struct@crate::layers::ip::Ipv4
    /// [`Ipv6`]: struct@crate::layers::ip::Ipv6
    /// [`Tcp`]: struct@crate::layers::tcp::Tcp
    BadUpperLayer,
}
