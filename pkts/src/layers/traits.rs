// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Traits used to provide [`Layer`] functionality.
//!
//!

use core::fmt;

use super::dev_traits::*;
use crate::error::*;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

// =============================================================================
//                       User-Facing Traits (for `Layer`)
// =============================================================================

/// A trait for retrieving the current length (in bytes) of a protocol layer and its payload.
pub trait LayerLength {
    /// The length (in bytes) of the layer.
    ///
    /// This length includes the length of any sublayers (i.e. the length is equal to the layer's
    /// header plus its entire payload).
    ///
    /// The length of a [`Layer`] may change when certain operations are performed, such as when a
    /// new layer is appended to an existing one or when a variable-length field is modified. The
    /// length of a [`LayerRef`] always remains constant.
    fn len(&self) -> usize;
}

/// A trait for serializing a [`Layer`] type into its binary representation.
pub trait ToBytes {
    /// Appends the layer's byte representation to the given byte vector and
    /// calculates the checksum of the given layer if needed.
    ///
    /// NOTE: this API is unstable, and should not be relied upon. It may be
    /// modified or removed at any point.
    #[doc(hidden)]
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError>;

    /*
    /// Appends the layer's byte representation to the given byte vector.
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        self.to_bytes_chksummed(bytes, None);
    }
    */

    /// Serializes the given layer into bytes stored in a vector.
    #[inline]
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        self.to_bytes_checksummed(&mut bytes, None)?;
        Ok(bytes)
    }
}

/// An object-safe subtrait of [`Layer`], suitable for internal operations involving
/// generic layer payloads.
pub trait LayerObject: AsAny + BaseLayer + fmt::Debug + ToBytes {
    /// Determines whether `payload` can be used as a payload for the layer.
    #[inline]
    fn can_add_payload(&self, payload: &dyn LayerObject) -> bool {
        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = self
            .layer_metadata()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection.can_add_payload(payload);
        }

        self.can_add_payload_default(payload)
    }

    /// Determines whether the given new payload can be used as a payload for the layer.
    ///
    /// This method is unaffected by custom layer selection (see [`CustomLayerSelection`]),
    /// and should only be used in cases where custom layer validation is enabled but
    /// the developer still wants to run the built-in default layer validation. If you're
    /// uncertain what all this means, just use `can_add_payload()`.
    #[doc(hidden)]
    fn can_add_payload_default(&self, payload: &dyn LayerObject) -> bool;

    /// Returns the current layer's payload, or `None` if the layer has no payload.
    #[inline]
    fn payload(&self) -> Option<&dyn LayerObject> {
        self.payloads().first().map(|p| p.as_ref())
    }

    /// Returns a slice over all of the layers payloads.
    fn payloads(&self) -> &[Box<dyn LayerObject>];

    /// Returns a mutable reference to the current layer's payload, or `None` if the layer has no
    /// payload.
    #[inline]
    fn payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        self.payloads_mut().get_mut(0).map(|p| p.as_mut())
    }

    /// Returns a mutable slice over all of the layers payloads.
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>];

    /// Sets the payload of the current layer, returning an error if the payload type is
    /// incompatible with the current layer.
    ///
    /// If the layer allows multiple payloads, this appends the payload as the last payload of the
    /// layer.
    fn add_payload(&mut self, payload: Box<dyn LayerObject>) -> Result<(), ValidationError> {
        if !self.can_add_payload(payload.as_ref()) {
            Err(ValidationError {
                layer: self.layer_name(),
                class: ValidationErrorClass::InvalidPayloadLayer,
                #[cfg(feature = "error_string")]
                reason: "requested payload layer type incompatible with the current layer",
            })
        } else {
            self.add_payload_unchecked(payload);
            Ok(())
        }
    }

    /// Sets the payload of the current layer without checking the payload type's compatibility.
    ///
    /// If the layer allows multiple payloads, this appends the payload as the last payload of the
    /// layer.
    ///
    /// # Panics
    ///
    /// Future invocations of `to_bytes()` and other layer methods may panic if an incompatible
    /// payload is passed in this method.
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>);

    /// Indicates whether the current `Layer` has any payload(s).
    #[inline]
    fn has_payload(&self) -> bool {
        !self.payloads().is_empty()
    }

    /// Removes the layer's payload, returning `None` if the layer has no stored payload.
    ///
    /// If the layer allows multiple payloads, this method will return the last payload added to the
    /// packet.
    #[inline]
    fn remove_payload(&mut self) -> Option<Box<dyn LayerObject>> {
        self.remove_payload_at(0)
    }

    /// Removes the specified payload from a layer by index.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range.
    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>>;

    /// Removes any payload(s) from the layer.
    #[inline]
    fn clear_payload(&mut self) {
        while self.has_payload() {
            self.remove_payload();
        }
    }
}

// =================================================================================================
//                                       Here be dragons
// =================================================================================================

// The following is a gross amalgamation of recursive functions. I'm not proud of it.
//
// Well, that's not exactly correct. I _am_ proud that it manages to crawl past the borrow checker
// without resorting to any `unsafe`. But its janky and inefficient and way less readable then it
// ought to be. Looking forward to tearing this out and replace it with a nice single `for`
// loop + recursive function once polonius is released.

/// Recursively searches through tree branches for a certain `Layer` type up to a given depth.
#[doc(hidden)]
fn get_layer_tree<L: LayerObject>(
    layer: &dyn LayerObject,
    mut n: usize,
    depth: usize,
) -> Result<&L, bool> {
    if layer.as_any().downcast_ref::<L>().is_some() {
        match n.checked_sub(1) {
            None | Some(0) => return layer.as_any().downcast_ref::<L>().ok_or(false), // Invariant: must be `Some()`
            Some(new_n) => n = new_n,
        }
    }

    match depth.checked_sub(1) {
        None => Err(layer.has_payload()),
        Some(new_depth) => {
            let mut more_layers = false;
            for payload in layer.payloads() {
                match get_layer_tree(payload.as_ref(), n, new_depth) {
                    Ok(t) => return Ok(t),
                    Err(m) => more_layers |= m,
                }
            }
            Err(more_layers)
        }
    }
}

/// Recursively searches through tree branch depths starting from the root of the tree,
/// using `get_layer_tree` with incrementally increasing depths.
fn get_layer_bfs<L: LayerObject>(layer: &dyn LayerObject, n: usize, depth: usize) -> Option<&L> {
    // This first `get_layer_bfs()` call is only necessary because the borrow checker
    // rejects any attempt at a `match` :(. Remove once Polonius is integrated into Rust...

    match get_layer_tree(layer, n, depth) {
        // <- Unneccesary once Polonius is done
        Ok(t) => Some(t),
        Err(false) => None,
        Err(true) => get_layer_bfs(layer, n, depth + 1), // Inductive step: try one deeper
    }
}

/// Recursively walks through the chain of `Layer`s until it becomes a tree, then calls
/// `get_layer_bfs`
fn get_layer_chain<L: LayerObject>(layer: &dyn LayerObject, mut n: usize) -> Option<&L> {
    if layer.as_any().downcast_ref::<L>().is_some() {
        match n.checked_sub(1) {
            None | Some(0) => return layer.as_any().downcast_ref::<L>(), // Invariant: must be `Some()`
            Some(n_decremented) => n = n_decremented,
        }
    }

    if layer.payloads().len() > 1 {
        get_layer_bfs(layer, n, 1)
    } else {
        get_layer_chain(layer.payload()?, n)
    }
}

/// Base function to walk through `Layer`s.
fn get_layer_base<I: IndexLayer, L: LayerObject>(layer: &I, mut n: usize) -> Option<&L> {
    if layer.as_any().downcast_ref::<L>().is_some() {
        match n.checked_sub(1) {
            None | Some(0) => return layer.as_any().downcast_ref::<L>(), // Invariant: always `Some()`
            Some(n_decremented) => n = n_decremented,
        }
    }

    if layer.payloads().len() > 1 {
        get_layer_bfs(layer, n, 1)
    } else {
        get_layer_chain(layer.payload()?, n)
    }
}

/// Recursively searches through tree branches for a certain `Layer` type up to a given depth.
#[doc(hidden)]
fn get_layer_mut_tree<L: LayerObject>(
    layer: &mut dyn LayerObject,
    mut n: usize,
    depth: usize,
) -> Result<&mut L, bool> {
    if layer.as_any_mut().downcast_mut::<L>().is_some() {
        match n.checked_sub(1) {
            None | Some(0) => return layer.as_any_mut().downcast_mut::<L>().ok_or(false), // Invariant: always `Some()`
            Some(n_decremented) => n = n_decremented,
        }
    }

    match depth.checked_sub(1) {
        None => Err(layer.has_payload()),
        Some(new_depth) => {
            let mut more_layers = false;
            for payload in layer.payloads_mut() {
                match get_layer_mut_tree(payload.as_mut(), n, new_depth) {
                    Ok(l) => return Ok(l),
                    Err(m) => more_layers |= m,
                }
            }
            Err(more_layers)
        }
    }
}

/// Recursively searches through tree branch depths starting from the root of the tree,
/// using `get_layer_mut_tree` with incrementally increasing depths.
fn get_layer_mut_bfs<L: LayerObject>(
    layer: &mut dyn LayerObject,
    n: usize,
    depth: usize,
) -> Option<&mut L> {
    // TODO:
    // This first `get_layer_mut_bfs()` call is only necessary because the borrow checker
    // rejects any attempt at a `match` :(. Remove once Polonius is finally integrated into
    // Rust...
    match get_layer_tree::<L>(layer, n, depth) {
        // <- Unneccesary once Polonius is done
        Ok(_) => Some(get_layer_mut_tree(layer, n, depth).unwrap()),
        Err(false) => None,
        Err(true) => get_layer_mut_bfs(layer, n, depth + 1), // Inductive step: try one deeper
    }
}

/// Recursively walks through the chain of `Layer`s until it becomes a tree, then calls
/// `get_layer_mut_bfs`
fn get_layer_mut_chain<L: LayerObject>(
    layer: &mut dyn LayerObject,
    mut n: usize,
) -> Option<&mut L> {
    if layer.as_any_mut().downcast_mut::<L>().is_some() {
        match n.checked_sub(1) {
            None | Some(0) => return layer.as_any_mut().downcast_mut::<L>(), // Invariant: always `Some()`
            Some(n_decremented) => n = n_decremented,
        }
    }

    if layer.payloads().len() > 1 {
        get_layer_mut_bfs(layer, n, 1)
    } else {
        get_layer_mut_chain(layer.payload_mut()?, n)
    }
}

/// Base function to walk through `Layer`s.
fn get_layer_mut_base<I: IndexLayer, L: LayerObject>(
    layer: &mut I,
    mut n: usize,
) -> Option<&mut L> {
    if layer.as_any_mut().downcast_mut::<L>().is_some() {
        match n.checked_sub(1) {
            None | Some(0) => return layer.as_any_mut().downcast_mut::<L>(), // Invariant: always `Some()`
            Some(n_decremented) => n = n_decremented,
        }
    }

    if layer.payloads().len() > 1 {
        get_layer_mut_bfs(layer, n, 1)
    } else {
        get_layer_mut_chain(layer.payload_mut()?, n)
    }
}

/// A trait for indexing into sublayers of a [`Layer`] type.
pub trait IndexLayer: LayerObject + Sized {
    /// Retrieves a reference to the first sublayer of type `T`, if such a sublayer exists.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will
    /// return a reference to the base layer. For cases where a sublayer of the same type as
    /// the base layer needs to be indexed into, refer to `get_nth_layer()`.
    ///
    /// # Search Behavior
    ///
    /// The [`get_layer()`](IndexLayer::get_layer()),
    /// [`get_layer_mut()`](IndexLayer::get_layer_mut()),
    /// [`get_nth_layer()`](IndexLayer::get_nth_layer()) and
    /// [`get_nth_layer_mut()`](IndexLayer::get_nth_layer()) methods all follow the same algorithm
    /// when searching for a particular `Layer`. The algorithm used is a recursive Breadth-First
    /// Search (BFS) with added optimization for when a packet initially has a chain of `Layer`s
    /// with only one payload each.
    ///
    /// ## Performance
    ///
    /// When a packet consists of a chain of single-payload `Layer`s, the algoritm has a complexity
    /// of `O(n)`, where `n` is the number of layers in the packet.
    ///
    /// When a packet's `Layer`s has multiple payloads, the algorithm has a worst-case complexity of
    /// `O(k * n)`, where `k` is the depth of `Layer` tree and `n` is the total number of `Layer`
    /// in the tree. Note that `k` is measured starting after the first `Layer` that has more than
    /// one payload as an optimization.
    ///
    /// For instance, a packet of the format `Eth` / `Ip` / `Udp` / `Dns` / `[Rr, Rr, Rr]` (e.g., a
    /// DNS packet with 3 resource records) would mean `k` = 1, as the `Dns` layer is the first layer
    /// with more than one payload.
    ///
    /// Using a traditional stack-based approach (which performs in `O(n)`) would be *slightly* more
    /// efficient, but it would require fundamental re-architecting of `Layer` internals, so we opt
    /// for the above approach instead.
    #[inline]
    fn get_layer<T: LayerObject>(&self) -> Option<&T> {
        self.get_nth_layer(1)
    }

    /// Retrieves a reference to the `n`th sublayer of type `T`, if such a sublayer exists.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// Note that the base layer counts towards the index if it is of type `T`.
    #[inline]
    fn get_nth_layer<T: LayerObject>(&self, n: usize) -> Option<&T> {
        get_layer_base(self, n)
    }

    /// Retrieves a mutable reference to the first sublayer of type `T`, if such a sublayer exists.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will return
    /// a mutable reference to the base layer. For cases where a sublayer of the same type as the
    /// base layer needs to be indexed into, refer to `get_nth_layer()`.
    #[inline]
    fn get_layer_mut<T: LayerObject>(&mut self) -> Option<&mut T> {
        self.get_nth_layer_mut(1)
    }

    /// Retrieves a mutable reference to the `n`th sublayer of type `T`, if such a sublayer exists.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// Note that the base layer counts towards the index if it is of type `T`.
    #[inline]
    fn get_nth_layer_mut<T: LayerObject>(&mut self, n: usize) -> Option<&mut T> {
        get_layer_mut_base(self, n)
    }

    /*
    // DO NOT DELETE this code snippet; this took me a long while to figure out its lifetimes...

    /// Retrieves a mutable reference to the `n`th sublayer of type `T`, if such a sublayer exists.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// Note that the base layer counts towards the index if it is of type `T`.
    fn get_nth_layer_mut<T: LayerObject>(&mut self, mut n: usize) -> Option<&mut T> {

        if n == 0 {
            return None;
        }

        if self.as_any_mut().downcast_mut::<T>().is_some() {
            match n.checked_sub(1) {
                None => return None,
                Some(0) => return self.as_any_mut().downcast_mut::<T>(),
                Some(n_decremented) => n = n_decremented,
            }
        }

        let mut next_layer = self.payload_mut();
        let mut layer;
        loop {
            match next_layer {
                None => return None,
                Some(l) => {
                    layer = l;
                    if layer.as_any_mut().downcast_mut::<T>().is_some() {
                        match n.checked_sub(1) {
                            None | Some(0) => break, // `None` should never occur here
                            Some(n_decremented) => n = n_decremented,
                        }
                    }
                    next_layer = layer.payload_mut();
                }
            }
        }

        layer.as_any_mut().downcast_mut::<T>()
    }
    */
}

/// Represents a distinct protocol layer that may encapsulate data and/or other layers.
///
/// This is one of two layer trait variants: [`Layer`] and [`LayerRef`].
/// This general layer type is distinct from the others in that it does not reference an external
/// byte slice--all of its internal types are owned by the layer. Individual data fields can be
/// modified or replaced in a simple and type-safe manner, and a packet comprising several distinct
/// layers can be crafted using methods related to this type.
pub trait Layer: IndexLayer + LayerName + LayerObject {
    /*
    /// Determines whether a given new layer can be appended to an existing one.
    ///
    /// Some `Layer` types have restrictions on what other layers can follow it. As an example of
    /// this, the IPv4 header has a field that explicitly denotes the Transport layer in use above
    /// it; as such, layers that have a defined value for that field are permitted to be a payload
    /// for and `Ipv4` type, while those that don't (such as Application layer protocols) are not.
    ///
    /// NOTE: This function requires a rather expensive and unavoidable conversion of `other` into
    /// a `Box<dyn LayerObject>` just to check if a `Layer` or `LayerRef` can be appended, so we
    /// currently disable it.
    #[inline]
    fn can_append<T: BaseLayer + ToLayer>(&self, other: &T) -> bool {
        if let Some(mut curr) = self.payload() {
            while let Some(payload) = curr.payload() {
                curr = payload;
            }
            curr.can_add_payload(other.to_boxed_layer().as_ref()) // TODO: expensive :(
        } else {
            self.can_add_payload(other.to_boxed_layer().as_ref())
        }
    }
    */

    /// Append the given layer to the existing packet layer, returning an error if the given layer
    /// is not permitted as a payload for the innermose sublayer.
    fn append_layer<T: BaseLayer + ToLayer>(&mut self, other: T) -> Result<(), ValidationError> {
        if let Some(mut curr) = self.payload_mut() {
            while curr.payload().is_some() {
                curr = curr.payload_mut().unwrap();
            }
            curr.add_payload(other.to_boxed_layer())?;
        } else {
            self.add_payload(other.to_boxed_layer())?;
        }

        Ok(())
    }

    /// Appends the provided new layer to the existing one without checking whether it is a
    /// permitted underlayer.
    ///
    /// # Panics
    ///
    /// Using this method can lead to a panic condition later on in the lifetime of the layer if
    /// the provided layer is not permitted as a payload for the innermost sublayer.
    fn append_layer_unchecked<T: BaseLayer>(&mut self, other: T) {
        if let Some(mut curr) = self.payload_mut() {
            while curr.payload().is_some() {
                curr = curr.payload_mut().unwrap();
            }
            curr.add_payload_unchecked(other.to_boxed_layer());
        } else {
            self.add_payload_unchecked(other.to_boxed_layer());
        }
    }
}

/// A trait for indexing into sublayers of a [`LayerRef`] type.
pub trait IndexLayerRef<'a>: LayerOffset + BaseLayer {
    /// Retrieves a reference to the first sublayer of type `T`, if such a sublayer exists.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will
    /// return a reference to the base layer. For cases where a sublayer of the same type as
    /// the base layer needs to be indexed into, refer to `get_nth_layer()`.
    fn get_layer<T: LayerRef<'a> + FromBytesRef<'a>>(&'a self) -> Option<T>;

    /// Retrieves a reference to the `n`th sublayer of type `T`, if such a sublayer exists.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// Note that the base layer counts towards the index if it is of type `T`.
    fn get_nth_layer<T: LayerRef<'a> + FromBytesRef<'a> + BaseLayerMetadata>(
        &'a self,
        n: usize,
    ) -> Option<T>;

    /// Retrieves a reference to the first sublayer of type `T`.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will
    /// return a reference to the base layer. For cases where a sublayer of the same type as
    /// the base layer needs to be indexed into, refer to `get_nth_layer()`.
    ///
    /// # Panics
    ///
    /// If no layer of the given type exists within the sublayers, this method will panic.
    #[inline]
    fn index_layer<T: LayerRef<'a> + FromBytesRef<'a> + BaseLayerMetadata>(&'a self) -> T {
        self.get_layer().unwrap_or_else(|| {
            panic!(
                "layer {} not found in instance of {} when index_layer() called",
                T::name(),
                self.layer_name()
            )
        })
    }

    /// Retrieves a reference to the `n`th sublayer of type `T`.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// # Panics
    ///
    /// If no layer of the given type exists within the sublayers, this method will panic.
    #[inline]
    fn index_nth_layer<T: LayerRef<'a> + FromBytesRef<'a> + BaseLayerMetadata>(
        &'a self,
        n: usize,
    ) -> T {
        self.get_nth_layer(n).unwrap_or_else(|| {
            panic!(
                "layer {} not found in instance of {} when index_nth_layer() called",
                T::name(),
                self.layer_name()
            )
        })
    }
}

/// Represents a distinct protocol layer that may encapsulate data and/or other layers.
///
/// This is one of two layer trait variants: [`Layer`] and [`LayerRef`].
/// This general layer type references an immutable byte slice, and is best suited for efficiently
/// retrieving individual layer fields or payload data from a given packet. This type can be easily
/// converted into its corresponding [`Layer`] type if desired.
pub trait LayerRef<'a>:
    LayerIdentifier + LayerName + IndexLayerRef<'a> + ToLayer + Copy + Into<&'a [u8]>
{
}

/// A Trait for validating a byte slice against the expected structure of a layer type.
pub trait Validate: BaseLayer + StatelessLayer {
    /// Checks that `bytes` represents a valid serialization of the layer type.
    ///
    /// Validation errors are returned in a special order, such that the library user may still
    /// inspect or otherwise use the contents of a packet despite the existence of certain errors in
    /// the fields of that packet. This is achieved by using the `from_bytes_unchecked()` method in
    /// any of the layer types.
    ///
    /// 1. [`ValidationErrorClass::InvalidSize`] errors are checked for and returned first and in
    /// order from parent layer to sublayer. An `InvalidSize` error indicates that there are
    /// insufficient bytes for some portion of the packet, such that an attempt to index into those
    /// bytes would panic. If this error is returned by a call to validate, the caller should not
    /// use `from_bytes_unchecked()`, as subsequent method invocations on that layer instance may
    /// result in a panic condition.
    ///
    /// 2. [`ValidationErrorClass::InvalidValue`] errors are returned when a field in a layer
    /// contains an invalid value (such as an Ipv4 packet containing a version code other than `4`).
    /// `InvalidValue` errors are returned in order from parent layer to sublayer. These errors
    /// will not lead to panic conditions if the bytes are converted into a layer type,
    /// and so can be safely converted using `from_bytes_unchecked()`. However, if the bytes are
    /// converted to a [`Layer`] type and then back to bytes, the library makes no guarantees about
    /// the reflexivity of the bytes. In other words, the output bytes may have subtle differences
    /// to those input, even if no modifications are made to the layer in between the conversions.
    /// For the most part, this is because the conversion to `Layer` types drops some meta
    /// information contained within the bytes (and corrects others as needed).
    ///
    /// 3. [`ValidationErrorClass::ExcessBytes`] errors are returned when the byte slice contains
    /// more bytes in it than is needed to fully construct the layer and its sublayers
    /// (i.e. there are trailing bytes at the end of the packet). Byte slices that return this
    /// error can be safely converted using `from_bytes_unchecked()` without leading to panic
    /// conditions, and conversion back to bytes from a [`Layer`] type is guaranteed to be
    /// prefix-reflexive. In other words, the output bytes are guaranteed to be a prefix of the
    /// input bytes--everything the same except the trailing bytes at the end of the packet.
    ///
    /// If no errors are returned, the byte slice can be used to construct a layer that is both
    /// panic-free and reflexive.
    ///
    /// [`ValidationErrorClass::InvalidPayloadLayer`] will not be returned by this function.
    fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let curr_valid = Self::validate_current_layer(bytes);
        match curr_valid {
            Err(e) if e.class == ValidationErrorClass::InsufficientBytes => return curr_valid,
            _ => (),
        }

        let next_valid = Self::validate_payload(bytes);
        match (curr_valid, next_valid) {
            // THIS ORDER MATTERS
            // TODO: review this order to ensure correctness
            (_, Err(e)) if e.class == ValidationErrorClass::InsufficientBytes => next_valid,
            (Err(e), _) if e.class == ValidationErrorClass::InvalidValue => curr_valid,
            (_, Err(e)) if e.class == ValidationErrorClass::InvalidValue => next_valid,
            (_, Err(e)) => Err(ValidationError {
                layer: e.layer,
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: e.reason,
            }),
            (Err(_), _) => curr_valid, // ValidationErrorClass::ExcessBytes(_)
            _ => Ok(()),
        }
    }

    /// Validates the given layer without validating any of its underlayers. Has the same
    /// error ordering properties as `validate()`.
    #[doc(hidden)]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError>;

    /// Validates the payload (underlayers) of the given layer without validating the layer itself.
    /// Has the same error ordering properties as [`validate()`](Self::validate()).
    #[doc(hidden)]
    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = TcpMetadata::instance()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection.validate_payload(curr_layer);
        }

        Self::validate_payload_default(curr_layer)
    }

    /// Default method for validating payload when custom layer selection is enabled. In general,
    /// `validate_payload()` should be used instead of this.
    #[doc(hidden)]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError>;
}

/// A trait for converting a slice of byets into a [`Layer`] type.
pub trait FromBytes: Sized + Validate + StatelessLayer + FromBytesCurrent {
    /// Converts a slice of bytes into a [`Layer`] type.
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts a slice of bytes into a [`Layer`] type, `panic`ing on failure.
    ///
    /// # Panics
    ///
    /// The following function may panic if the slice of bytes doesn't form a valid packet
    /// structure. If an invocation of `validate()` on the slice does not return
    /// [`ValidationErrorClass::InvalidSize`], this function will not panic.
    fn from_bytes_unchecked(bytes: &[u8]) -> Self;
}

/// A trait for converting a slice of byets into a [`LayerRef`] type.
pub trait FromBytesRef<'a>: Sized + Validate + StatelessLayer {
    /// Converts a slice of bytes into a [`LayerRef`] type, returning an error if the bytes would
    /// not form a valid layer.
    #[inline]
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts a slice of bytes into a [`LayerRef`] type.
    ///
    /// # Panics
    ///
    /// The following function may panic if the slice of bytes doesn't form a valid packet
    /// structure. If an invocation of `validate()` on the slice does not return
    /// [`ValidationErrorClass::InvalidSize`], this function will not panic.
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self;
}

/// A trait for creating an owned layer type [`Layer`] from an instance of a protocol layer
/// (a [`Layer`] or [`LayerRef`]).
pub trait ToLayer {
    type Owned: LayerObject;

    /// Creates a new [`Layer`] out of the given layer instance.
    fn to_layer(&self) -> Self::Owned;
}

impl<T: LayerObject + Clone> ToLayer for T {
    type Owned = Self;
    #[inline]
    fn to_layer(&self) -> Self::Owned {
        self.clone()
    }
}

// =============================================================================
//                     Macros to Parse Custom Layer Order
// =============================================================================

/// Parses bytes into a specified sequence of [`Layer`]s.
#[cfg(any(feature = "alloc", feature = "std"))]
#[macro_export]
macro_rules! parse_layers {
    ($bytes:expr, $first:ty, $($next:tt),+) => {{
        match <$first as $crate::layers::dev_traits::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(mut layer) => {
                let remaining = &$bytes[<$first as $crate::layers::traits::LayerLength>::len(&layer)..];
                $crate::parse_layers!(remaining; layer, $($next),*)
            }
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty, $($next:tt),+) => {{
        match <$curr as $crate::layers::dev_traits::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(new_layer) => {
                let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerLength>::len(&new_layer)..];
                #[cfg(feature = "std")]
                let payload = Box::new(new_layer);
                #[cfg(not(feature = "std"))]
                let payload = alloc::boxed::Box::new(new_layer);
                match $base_layer.add_payload(payload) {
                    Ok(_) => $crate::parse_layers!(remaining_bytes; $base_layer, $($next),*),
                    Err(e) => Err(e),
                }
            },
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty) => {{
        match <$curr as $crate::layers::dev_traits::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(new_layer) => {
                let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerLength>::len(&new_layer)..];
                #[cfg(feature = "std")]
                let payload = Box::new(new_layer);
                #[cfg(not(feature = "std"))]
                let payload = alloc::boxed::Box::new(new_layer);
                match $base_layer.add_payload(payload) {
                    Ok(_) if remaining_bytes.len() == 0 => Ok($base_layer),
                    Ok(_) => Err($crate::error::ValidationError {
                        layer: <$curr as $crate::layers::dev_traits::LayerName>::name(),
                        class: $crate::error::ValidationErrorClass::ExcessBytes($bytes.len()),
                        #[cfg(feature = "error_string")]
                        reason: "parsing of bytes failed--additional bytes remaining after parsing all protocol layers"
                    }),
                    Err(e) => Err(e),
                }
            },
            Err(e) => Err(e),
        }
    }};
}

/// Parses bytes into a specified sequence of [`Layer`]s, `panic()`ing on error.
///
/// # Panic
#[macro_export]
macro_rules! parse_layers_unchecked {
    ($bytes:expr, $first:ty, $($next:tt),+) => {{
        let mut layer = <$first as $crate::layers::traits::FromBytesCurrent>::from_bytes_current_layer_unchecked($bytes);
        let remaining = &$bytes[<$first as $crate::layers::traits::LayerLength>::len(&layer)..];
        $crate::parse_layers_unchecked!(remaining; layer, $($next),*)
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty, $($next:tt),+) => {{
        let new_layer = <$curr as $crate::layers::traits::FromBytesCurrent>::from_bytes_current_layer_unchecked($bytes);
        let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerLength>::len(&new_layer)..];
        $base_layer.set_payload_unchecked(Some(Box::new(new_layer)));
        $crate::parse_layers_unchecked!(remaining_bytes; $base_layer, $($next),*)
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty) => {{
        let new_layer = <$curr as $crate::layers::traits::FromBytesCurrent>::from_bytes_current_layer_unchecked($bytes);
        let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerLength>::len(&new_layer)..];
        $base_layer.set_payload_unchecked(Some(Box::new(new_layer)));
        $base_layer
    }};
    /*
    ($bytes:expr; $base_layer:ident) => {{
        $base_layer
    }};
    */
}
