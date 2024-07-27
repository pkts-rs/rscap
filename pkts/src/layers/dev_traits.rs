// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Traits that are only needed for developing new `Layer` types.
//!
//!

use core::any;

use crate::prelude::*;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;

use pkts_macros::layer_metadata;

/// An identifier unique to a protocol layer.
pub type LayerId = any::TypeId;

/// Indicates that a given [`Layer`] can be decoded directly from bytes without requiring any
/// additional information.
///
/// Some [`Layer`] types always have the same structure to their data regardless of the state of the protocol,
/// while others have several data layout variants that may be ambiguous without accompanying information.
/// An example of stateless layers would be `Dns`, which only ever has one data layout, or [`PsqlClient`],
/// which has information encoded into the first bytes of the packet that allows a decoder to determine the
/// byte layout of the specific packet variant. On the other hand, stateful layers require knowlede of what
/// packets have been exchanged prior to the given byte packet in order to be successfully converted. An
/// example of this would be the [`MysqlClient`] and `MysqlServer` layers.
///
/// Any [`Layer`] type implementing [`StatelessLayer`] can be decoded directly from bytes using
/// `from_bytes()`/`from_bytes_unchecked()` or by using a [`Sequence`] type. Layers that do not implement
/// [`StatelessLayer`] can be decoded from bytes using a [`Session`] type (which keeps track of connection state)
/// or by using constructor methods specific to that layer that require additional state information.
///
/// [`MysqlClient`]: struct@crate::layers::mysql::MysqlClient
/// [`PsqlClient`]: struct@crate::layers::psql::PsqlClient
/// [`Sequence`]: crate::sequence::Sequence
/// [`Session`]: crate::sessions::Session
pub trait StatelessLayer {}

/// An object-safe base trait for protocol layers that is extended by all `Layer` trait variants.
///
/// The [`BaseLayer`] trait enables packet layers of different implementations (e.g. [`Layer`],
/// [`LayerRef`]) to be used interchangably for certain operations. For instance,
/// concatenation of packets is achieved via this type in the [`Layer`]
/// and [`core::ops::Div`] traits.
pub trait BaseLayer: ToBoxedLayer + LayerLength {
    /// The name of the layer, usually (though not guaranteed to be) the same as the name of the
    /// struct.
    ///
    /// For [`LayerRef`] types, this will return the name of the layer without 'Ref' appended to
    /// it (i.e. the same as their associated [`Layer`] type).
    fn layer_name(&self) -> &'static str;

    /// Static metadata associated with the given layer. This method is normally only used
    /// internally or when defining a custom `Layer` type.
    fn layer_metadata(&self) -> &dyn LayerMetadata;
}

/// Allows the name of a protocol layer to be retrieved as a string.
///
/// This trait's single associated function is effectively an object-unsafe variant of the
/// [`BaseLayer::layer_metadata()`] method.
pub trait LayerName {
    /// The name of the layer, usually (though not guaranteed to be) the same as the name of the
    /// struct.
    ///
    /// For [`LayerRef`] types, this will return the name of the layer without 'Ref' appended to
    /// it (i.e. the same as their associated [`Layer`] type).
    fn name() -> &'static str;
}

/// An extension to [`any::Any`]; adds methods for retrieving a `dyn Any` reference
/// or mutable reference.
pub trait AsAny: any::Any {
    /// Return a `dyn Any` reference to `self`.
    fn as_any(&self) -> &dyn any::Any;

    /// Return a mutable `dyn Any` reference to `self`.
    fn as_any_mut(&mut self) -> &mut dyn any::Any;
}

/// Blanket implementation of [`AsAny`] for all types capable of returning a `dyn Any` reference.
impl<T: any::Any> AsAny for T {
    #[inline]
    fn as_any(&self) -> &dyn any::Any {
        self
    }

    #[inline]
    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

/// Utility method to convert a given type into a [`Box`]ed instance of [`Layer`].
///
/// This is primarily used internally to facilitate appending one layer to another
/// in a type-agnostic way.
pub trait ToBoxedLayer {
    /// Clone the given instance in a [`Box`] and return it as a `dyn Layer` type.
    fn to_boxed_layer(&self) -> Box<dyn LayerObject>;
}

// If we wanted to, we could pull out the `layer_metadata(&self)` function from BaseLayer and put it in an internal trait like so:
/*
pub trait ObjectMetadata {
    fn layer_metadata(&self) -> &dyn LayerMetadata;
}
*/

/// Methods relating to [`BaseLayer`] types that would violate the object-safety of `BaseLayer`
/// if added to it.
pub trait BaseLayerMetadata: BaseLayer {
    fn metadata() -> &'static dyn LayerMetadata;
}

impl Clone for Box<dyn LayerObject> {
    #[inline]
    fn clone(&self) -> Self {
        self.to_boxed_layer()
    }
}

/// A trait for converting a byte slice into a layer type without setting a payload, even if one exists.
pub trait FromBytesCurrent: Sized + Validate + StatelessLayer {
    /// Attempts to create a new layer from the given bytes without setting a payload for the
    /// layer, even if one exists.
    fn from_bytes_current_layer(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate_current_layer(bytes)?;
        Ok(Self::from_bytes_current_layer_unchecked(bytes))
    }

    /// Sets the given layer's payload to the appropriate layer type, if such a payload exists.
    /// In this context, `bytes` should be the serialized representation of not only the payload,
    /// but of the current layer as well.
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]);

    /// Creates a new layer from the given bytes without setting a payload for the layer, even
    /// if one exists.
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self;
}

/// Assigns a unique identifier to the layer.
///
/// Each protocol layer must have the same LayerId returned by this trait across [`Layer`]
/// and [`LayerRef`] types of that protocol. So, there were a protocol layer called `Example`,
/// then `Example::layer_id()` == `ExampleRef::layer_id()`, and likewise
/// `Example::layer_id()` == `ExampleMut::layer_id()`.
pub trait LayerIdentifier: Sized {
    /// A unique identifier for the layer type.
    ///
    /// This identifier is guaranteed to be the same across instances of [`Layer`] and
    /// [`LayerRef`] types of the same protocol layer.
    fn layer_id() -> LayerId;
}

/// The default layer offset method to be used for a layer when no [`CustomLayerSelection`] is
/// specified for the layer.
pub trait LayerOffset {
    /// Gets the index of the first byte of the layer specified by `layer_type`, if such a layer exists.
    /// This will not check the current layer against `layer_type`.
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize>;
}

/// A singleton associated with a [`Layer`] that enables indexing by that layer's type name.
pub trait LayerIndexSingleton: crate::private::Sealed {
    type LayerType: LayerObject;
}

// ==========================================================
//               Traits for Layer Metadata Types
// ==========================================================

pub trait LayerMetadata: AsAny {}

pub trait ConstSingleton {
    fn instance() -> &'static Self;
}

pub trait Ipv4PayloadMetadata: LayerMetadata {
    /// The protocol number that uniquely identifies the type of the payload.
    fn ip_data_protocol(&self) -> u8;

    /*
    /// If you're implementing this trait and you don't know what this is, just set it to `None`.
    fn diff_serv_number() -> Option<u8>;
    */
}

pub trait Ipv6PayloadMetadata: LayerMetadata {
    /// The protocol number that uniquely identifies the type of the payload.
    fn ip_data_protocol(&self) -> u8;
}

pub trait EtherPayloadMetadata: LayerMetadata {
    fn eth_type(&self) -> u16;
}

//    pub trait MysqlMetadata: LayerMetadata {}

// ==========================================================
//               Concrete Layer Metadata Types
// ==========================================================

// These are left public so that the user can implement further Metadata functions as desired

layer_metadata!(DiameterMetadata);

layer_metadata!(DiamBaseMetadata);

layer_metadata!(EtherMetadata);

layer_metadata!(ExampleMetadata);

layer_metadata!(S6aMetadata);

layer_metadata!(Ipv4Metadata);

impl EtherPayloadMetadata for Ipv4Metadata {
    fn eth_type(&self) -> u16 {
        0x0800
    }
}

layer_metadata!(Ipv6Metadata);

impl EtherPayloadMetadata for Ipv6Metadata {
    fn eth_type(&self) -> u16 {
        0x0800
    }
}

layer_metadata!(SctpMetadata);

impl Ipv4PayloadMetadata for SctpMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_SCTP
    }
}

impl Ipv6PayloadMetadata for SctpMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_SCTP
    }
}

layer_metadata!(SctpDataChunkMetadata);

layer_metadata!(TcpMetadata);

impl Ipv4PayloadMetadata for TcpMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_TCP
    }
}

impl Ipv6PayloadMetadata for TcpMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_TCP
    }
}

layer_metadata!(UdpMetadata);

impl Ipv4PayloadMetadata for UdpMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_UDP
    }
}

impl Ipv6PayloadMetadata for UdpMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_UDP
    }
}

layer_metadata!(RawMetadata);

impl Ipv4PayloadMetadata for RawMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_EXP1
    }
}

impl Ipv6PayloadMetadata for RawMetadata {
    #[inline]
    fn ip_data_protocol(&self) -> u8 {
        crate::layers::ip::DATA_PROTO_EXP1
    }
}

//    impl MysqlMetadata for RawMetadata {}

layer_metadata!(MysqlPacketMetadata);

layer_metadata!(MysqlClientMetadata);

//    impl MysqlMetadata for MysqlClientMetadata {}

layer_metadata!(MysqlServerMetadata);

//    impl MysqlMetadata for MysqlServerMetadata {}

layer_metadata!(PsqlClientMetadata);

layer_metadata!(PsqlServerMetadata);

// ===========================================
//           Custom Layer Selection
// ===========================================

#[cfg(feature = "custom_layer_selection")]
pub trait BaseLayerSelection: AsAny {}

#[cfg(feature = "custom_layer_selection")]
pub trait CustomLayerSelection: BaseLayerSelection {
    fn validate_payload(&self, curr_layer: &[u8]) -> Result<(), ValidationError>;

    fn can_add_payload(&self, payload: &dyn LayerObject) -> bool;

    fn payload_byte_index(&self, curr_layer: &[u8], desired_type: &LayerId) -> Option<usize>;

    fn payload_to_boxed(&self, curr_layer: &[u8]) -> Option<Box<dyn LayerObject>>;
}
