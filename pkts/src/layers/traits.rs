use crate::error::*;
use core::fmt;
use extras::*;
use rscap_macros::layer_metadata;

use crate::layers::ip::Ipv4DataProtocol;

// =============================================================================
//                       User-Facing Traits (for `Layer`)
// =============================================================================

/// The most basic abstraction of a packet layer.
/// The [`BaseLayer`] trait enables packet layers of different implementations (e.g. [`Layer`],
/// [`LayerRef`] and [`LayerMut`]) to be used interchangably for certain operations. For instance,
/// concatenation of packets is achieved via this type in the [`BaseLayerAppend`]
/// and [`core::ops::Div`] traits.
pub trait BaseLayer: ToBoxedLayer + LayerLength {
    /// The name of the layer, usually (though not guaranteed to be) the same as the name of the
    /// struct.
    ///
    /// For [`LayerRef`] and [`LayerMut`] types, this will return the name of the layer without
    /// 'Ref' or 'Mut' appended to it (i.e. the same as their associated [`Layer`] type).
    fn layer_name(&self) -> &'static str;

    /// Static metadata associated with the given layer. This method is normally only used
    /// internally or when defining a custom `Layer` type.
    fn layer_metadata(&self) -> &dyn LayerMetadata;
}

/// A trait for getting the name of a given layer at runtime.
pub trait LayerName {
    /// The name of the layer, usually (though not guaranteed to be) the same as the name of the
    /// struct.
    ///
    /// For [`LayerRef`] and [`LayerMut`] types, this will return the name of the layer without
    /// 'Ref' or 'Mut' appended to it (i.e. the same as their associated [`Layer`] type).
    fn name() -> &'static str;
}

/// A trait for retrieving the current length in bytes of a given layer.
pub trait LayerLength {
    /// The length in bytes of the layer. This length includes the length of any sublayers (i.e.
    /// the length is equal to the layer's header plus its entire payload).
    ///
    /// The length of a [`Layer`] or [`LayerMut`] may change when certain operations are performed,
    /// such as when a new layer is appended to an existing one or when a variable-length field is
    /// modified. The length of a [`LayerRef`] always remains constant.
    fn len(&self) -> usize;
}

/// A trait for appending one layer to another and returning an owned instance of the parent layer.
///
/// We define _appending_ a new layer as setting the innermost empty payload of an existing layer
/// to the value of the new layer. This means that _appending_ a layer is different from setting
/// a layer's payload. While the `set_payload()` family of methods replace whatever underlayer(s)
/// existed before with the new layer, appending a layer involves traversing through each underlayer
/// until one with an empty payload is reached, and then replacing the empty payload with the new
/// layer.
///
/// For instance, if one had an `Ipv4` layer that had a structure of `Ipv4` / `Tcp` (with the `Tcp`
/// layer having no payload), then appending a `Smtp` layer to it would result in a structure of
/// `Ipv4` / `Tcp` / `Smtp`. This is different from `set_payload()`, which would attempt (and fail)
/// to change the layer structure to be `Ipv4` / `Smtp`.
pub trait BaseLayerAppend: BaseLayerAppendBoxed {
    /// Determines whether a given new layer can be appended to an existing one.
    ///
    /// Some `Layer` types have restrictions on what other layers can follow it. As an example of
    /// this, the IPv4 header has a field that explicitly denotes the Transport layer in use above
    /// it; as such, layers that have a defined value for that field are permitted to be a payload
    /// for and `Ipv4` type, while those that don't (such as Application layer protocols) are not.
    ///
    /// A note for performance: the current implementation of this function allocates `Layer`
    /// instances that are then destroyed at the end of the method invocation.
    /// Because of this, it is generally much more efficient to use the `appended_with()` method than to
    /// use `can_append_with()` and `appended_with_unchecked()` separately.
    #[inline]
    fn can_append_with<T: BaseLayer + IntoLayer>(&self, other: &T) -> bool {
        self.can_append_with_boxed(other.to_boxed_layer().as_ref())
    }

    /// Append the given layer to the existing packet layer, returning an error if the given layer
    /// is not permitted as a payload for the innermose underlayer.
    #[inline]
    fn appended_with<T: BaseLayer + IntoLayer>(
        self,
        other: T,
    ) -> Result<Self::Output, &'static str> {
        self.appended_with_boxed(other.into_boxed_layer())
    }

    /// Appends the provided new layer to the existing one without checking whether it is a
    /// permitted underlayer.
    ///
    /// # Panics
    ///
    /// Using this method can lead to a panic condition later on in the lifetime of the layer if
    /// the provided layer is not permitted as a payload for the innermost underlayer.
    #[inline]
    fn appended_with_unchecked<T: BaseLayer + IntoLayer>(self, other: T) -> Self::Output {
        self.appended_with_boxed_unchecked(other.into_boxed_layer())
    }
}

/// A trait for checking whether the payload of a layer can be set.
pub trait CanSetPayload: BaseLayer {
    /// Determines whether the given new payload can be used as a payload for the layer.
    #[inline]
    fn can_set_payload(&self, payload: &dyn LayerObject) -> bool {
        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = self
            .layer_metadata()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection.can_set_payload(payload);
        }

        self.can_set_payload_default(payload)
    }

    /// Determines whether the given new payload can be used as a payload for the layer.
    /// This method is unaffected by custom layer selection (see [`CustomLayerSelection`]),
    /// and should only be used in cases where custom layer validation is enabled but
    /// the developer still wants to run the built-in default layer validation. If you're
    /// uncertain what all this means, just use `can_set_payload()`.
    fn can_set_payload_default(&self, payload: &dyn LayerObject) -> bool;
}

pub trait ToSlice {
    fn to_slice(&self) -> &[u8];
}

/// A trait for serializing a [`Layer`] type into its binary representation.
pub trait ToBytes {
    /// Appends the layer's byte representation to the given byte vector.
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>);

    /// Serializes the given layer into bytes stored in a vector.
    #[inline]
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.to_bytes_extended(&mut bytes);
        bytes
    }
}

// TODO: I added this because I could, but do we need it? Is it useless?
impl<T: ToSlice> ToBytes for T {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.to_slice());
    }
}





/// An object-safe subtrait of [`Layer`], suitable for internal operations involving
/// generic layer payloads.
pub trait LayerObject: AsAny + BaseLayer + CanSetPayload + fmt::Debug + ToBytes {
    /// Returns an immutable reference to the current layer's payload, or `None` if the layer has no payload.
    fn get_payload_ref(&self) -> Option<&dyn LayerObject>;

    /// Returns a mutable reference to the current layer's payload, or `None` if the layer has no payload.
    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject>;

    /// Sets the payload of the current layer, returning an error if the payload type is
    /// incompatible with the current layer.
    fn set_payload(&mut self, payload: Box<dyn LayerObject>) -> Result<(), ValidationError> {
        if !self.can_set_payload(payload.as_ref()) {
            Err(ValidationError {
                layer: self.layer_name(),
                err_type: ValidationErrorType::InvalidPayloadLayer,
                reason: "", // TODO: fixme
            })
        } else {
            self.set_payload_unchecked(payload);
            Ok(())
        }
    }

    /// Returns `true` if the current layer has a payload, or `false` if not.
    fn has_payload(&self) -> bool;

    /// Removes the layer's payload, returning it.
    ///
    /// # Panics
    ///
    /// Panics if the layer has no payload.
    fn remove_payload(&mut self) -> Box<dyn LayerObject>;

    /// Removes the layer's payload if it exists.
    #[inline]
    fn discard_payload(&mut self) {
        if self.has_payload() {
            self.remove_payload();
        }
    }

    /// Sets the payload of the current layer without checking the payload type's compatibility.
    ///
    /// # Panics
    ///
    /// Future invocations of `to_bytes()` and other layer methods may panic if an incompatible
    /// payload is passed in this method.
    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>);
}

/// A trait for indexing into sublayers of a [`Layer`] type.
pub trait LayerIndex: LayerObject {
    /// Retrieves a reference to the first sublayer of type `T`, if such a sublayer exists.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will
    /// return a reference to the base layer. For cases where a sublayer of the same type as
    /// the base layer needs to be indexed into, refer to `get_nth_layer()`.
    #[inline]
    fn get_layer<T: LayerObject>(&self) -> Option<&T> {
        if let Some(t) = self.as_any().downcast_ref::<T>() {
            return Some(t);
        };

        let mut next_layer = self.get_payload_ref();
        while let Some(layer) = next_layer {
            if let Some(t) = layer.as_any().downcast_ref::<T>() {
                return Some(t);
            }
            next_layer = layer.get_payload_ref()
        }

        None
    }

    /// Retrieves a reference to the `n`th sublayer of type `T`, if such a sublayer exists.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// Note that the base layer counts towards the index if it is of type `T`.
    fn get_nth_layer<T: LayerObject>(&self, mut n: usize) -> Option<&T> {
        if n == 0 {
            return None;
        }

        if let Some(t) = self.as_any().downcast_ref::<T>() {
            n -= 1;
            if n == 0 {
                return Some(t);
            }
        };

        let mut next_layer = self.get_payload_ref();
        while let Some(layer) = next_layer {
            if let Some(t) = layer.as_any().downcast_ref::<T>() {
                n -= 1;
                if n == 0 {
                    return Some(t);
                }
            }
            next_layer = layer.get_payload_ref()
        }

        None
    }

    /// Retrieves a mutable reference to the first sublayer of type `T`, if such a sublayer exists.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will return
    /// a mutable reference to the base layer. For cases where a sublayer of the same type as the
    /// base layer needs to be indexed into, refer to `get_nth_layer()`.
    fn get_layer_mut<T: LayerObject>(&mut self) -> Option<&mut T> {
        if self.as_any_mut().downcast_mut::<T>().is_some() {
            return self.as_any_mut().downcast_mut::<T>();
        }

        let mut next_layer = self.get_payload_mut();
        let mut layer;
        loop {
            match next_layer {
                None => return None,
                Some(l) => {
                    layer = l;
                    if layer.as_any_mut().downcast_mut::<T>().is_some() {
                        break;
                    }
                    next_layer = layer.get_payload_mut();
                }
            }
        }

        layer.as_any_mut().downcast_mut::<T>()
    }

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
            n -= 1;
            if n == 0 {
                return self.as_any_mut().downcast_mut::<T>();
            }
        }

        let mut next_layer = self.get_payload_mut();
        let mut layer;
        loop {
            match next_layer {
                None => return None,
                Some(l) => {
                    layer = l;
                    if layer.as_any_mut().downcast_mut::<T>().is_some() {
                        n -= 1;
                        if n == 0 {
                            break;
                        }
                    }
                    next_layer = layer.get_payload_mut();
                }
            }
        }

        layer.as_any_mut().downcast_mut::<T>()
    }
}

/// A trait for appending a new layer to an existing one.
pub trait LayerAppend: BaseLayerAppend + LayerObject {
    /// Append the given layer to the existing packet layer, returning an error if the given layer
    /// is not permitted as a payload for the innermose underlayer.
    fn append_layer<T: BaseLayer + IntoLayer>(&mut self, other: T) -> Result<(), ValidationError> {
        if let Some(mut curr) = self.get_payload_mut() {
            while curr.get_payload_ref().is_some() {
                curr = curr.get_payload_mut().unwrap();
            }
            curr.set_payload(other.into_boxed_layer())?;
        } else {
            self.set_payload(other.into_boxed_layer())?;
        }

        Ok(())
    }

    /// Appends the provided new layer to the existing one without checking whether it is a
    /// permitted underlayer.
    ///
    /// # Panics
    ///
    /// Using this method can lead to a panic condition later on in the lifetime of the layer if
    /// the provided layer is not permitted as a payload for the innermost underlayer.
    fn append_layer_unchecked<T: BaseLayer>(&mut self, other: T) {
        if let Some(mut curr) = self.get_payload_mut() {
            while curr.get_payload_ref().is_some() {
                curr = curr.get_payload_mut().unwrap();
            }
            curr.set_payload_unchecked(other.into_boxed_layer());
        } else {
            self.set_payload_unchecked(other.into_boxed_layer());
        }
    }
}

/// Represents a distinct protocol layer that may encapsulate data and/or other layers.
///
/// This is one of three layer trait variants: [`Layer`], [`LayerRef`], and [`LayerMut`].
/// This general layer type is distinct from the others in that it does not reference an external
/// byte slice--all of its internal types are owned by the layer. Individual data fields can be
/// modified or replaced in a simple and type-safe manner, and a packet comprising several distinct
/// layers can be crafted using methods related to this type.
pub trait Layer: LayerObject + IntoLayer + LayerAppend + LayerIndex {}

/// A trait for indexing into sublayers of a [`LayerRef`] type.
pub trait LayerRefIndex<'a>: LayerOffset + BaseLayer {
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
/// This is one of three layer trait variants: [`Layer`], [`LayerRef`], and [`LayerMut`].
/// This general layer type references an immutable byte slice, and is best suited for efficiently
/// retrieving individual layer fields or payload data from a given packet. This type can be easily
/// converted into its corresponding [`Layer`] type if desired.
pub trait LayerRef<'a>:
    AnyLayerRef<'a>
    + BaseLayerAppend
    + Into<&'a [u8]>
    + Into<Vec<u8>>
    + LayerName
    + LayerRefIndex<'a>
    + ToOwnedLayer
{
}

/// A trait for mutably indexing into sublayers of a [`LayerRef`] type.
pub trait LayerMutIndex<'a>: LayerRefIndex<'a> + AnyLayerMut<'a> {
    /// Retrieves a mutable reference to the first sublayer of type `T`, if such a sublayer exists.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will
    /// return a reference to the base layer. For cases where a sublayer of the same type as
    /// the base layer needs to be indexed into, refer to `get_nth_layer()`.
    fn get_layer_mut<T: LayerMut<'a> + FromBytesMut<'a>>(&'a mut self) -> Option<T>;

    /// Retrieves a mutable reference to the `n`th sublayer of type `T`, if such a sublayer exists.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// Note that the base layer counts towards the index if it is of type `T`.
    fn get_nth_layer_mut<T: LayerMut<'a> + FromBytesMut<'a> + BaseLayerMetadata>(
        &'a mut self,
        n: usize,
    ) -> Option<T>;

    /// Retrieves a mutable reference to the first sublayer of type `T`.
    ///
    /// If the layer type `T` is the same type as the base layer (`self`), this method will
    /// return a reference to the base layer. For cases where a sublayer of the same type as
    /// the base layer needs to be indexed into, refer to `get_nth_layer()`.
    ///
    /// # Panics
    ///
    /// If no layer of the given type exists within the sublayers, this method will panic.
    #[inline]
    fn index_layer_mut<T: LayerMut<'a> + FromBytesMut<'a>>(&'a mut self) -> T {
        let layer_name = self.layer_name();
        self.get_layer_mut().unwrap_or_else(|| {
            panic!(
                "layer {} not found in instance of {} when index_layer() called",
                T::name(),
                layer_name
            )
        })
    }

    /// Retrieves a mutable reference to the `n`th sublayer of type `T`.
    ///
    /// The `n` parameter is one-indexed, so a method call of `pkt.get_nth_layer<L>(1)`
    /// is functionally equivalent to `pkt.get_layer<L>()`. Passing in an index of 0 will
    /// lead to `None` being returned.
    ///
    /// # Panics
    ///
    /// If no layer of the given type exists within the sublayers, this method will panic.
    #[inline]
    fn index_nth_layer_mut<T: LayerRef<'a> + FromBytesRef<'a> + BaseLayerMetadata>(
        &'a self,
        n: usize,
    ) -> T {
        self.get_nth_layer(n).unwrap_or_else(|| {
            panic!(
                "{} layer not found in instance of {} when index_nth_layer_mut() called",
                T::name(),
                self.layer_name()
            )
        })
    }
}

/// Represents a distinct protocol layer that may encapsulate data and/or other layers.
///
/// This is one of three layer trait variants: [`Layer`], [`LayerRef`], and [`LayerMut`].
/// This general layer type references a mutable byte slice, and is best suited for efficiently
/// accessing and modifying individual layer fields or payload data from a given packet when only
/// small changes are being made. This type can be easily converted into its corresponding
/// [`Layer`] type if desired.
pub trait LayerMut<'a>:
    AnyLayerMut<'a>
    + BaseLayerAppend
    + Into<&'a [u8]>
    + Into<Vec<u8>>
    + LayerMutIndex<'a>
    + LayerName
    + ToOwnedLayer
{
}

/// A Trait for validating a byte slice against the expected structure of a layer type.
pub trait Validate: BaseLayer + StatelessLayer {
    /// Attempts to validate that `bytes` represents a well-formed serialized version of the layer
    /// type.
    ///
    /// Validation errors are returned in a special order, such that the library user may still
    /// inspect or otherwise use the contents of a packet despite the existence of errors in the
    /// fields of that packet. This is achieved by using the `from_bytes_unchecked()` method in any
    /// of the layer types.
    ///
    /// 1. [`ValidationErrorType::InvalidSize`] errors are checked for and returned first and in
    /// order from parent layer to sublayer. An `InvalidSize` error indicates that there are
    /// insufficient bytes for some portion of the packet, such that an attempt to index into those
    /// bytes would panic. If this error is returned by a call to validate, the caller should not
    /// use `from_bytes_unchecked()`, as subsequent method invocations on that layer instance may
    /// result in a panic condition.
    ///
    /// 2. [`ValidationErrorType::InvalidValue`] errors are returned when a field in a layer
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
    /// 3. [`ValidationErrorType::ExcessBytes`] errors are returned when the byte slice contains
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
    /// [`ValidationErrorType::InvalidPayloadLayer`] will not be returned by this function.
    fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let curr_valid = Self::validate_current_layer(bytes);
        match curr_valid {
            Err(e) if e.err_type == ValidationErrorType::InsufficientBytes => return curr_valid,
            _ => (),
        }

        let next_valid = Self::validate_payload(bytes);
        match (curr_valid, next_valid) {
            // THIS ORDER MATTERS
            // TODO: review this order to ensure correctness
            (_, Err(e)) if e.err_type == ValidationErrorType::InsufficientBytes => next_valid,
            (Err(e), _) if e.err_type == ValidationErrorType::InvalidValue => curr_valid,
            (_, Err(e)) if e.err_type == ValidationErrorType::InvalidValue => next_valid,
            (_, Err(e)) => Err(ValidationError {
                layer: e.layer,
                err_type: ValidationErrorType::InvalidValue,
                reason: e.reason,
            }),
            (Err(_), _) => curr_valid, // ValidationErrorType::ExcessBytes(_)
            _ => Ok(()),
        }
    }

    /// Validates the given layer without validating any of its underlayers. Has the same
    /// error ordering properties as `validate()`.
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError>;

    /// Validates the payload (underlayers) of the given layer without validating the layer itself.
    /// Has the same error ordering properties as `validate()`.
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
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError>;
}

/// A trait for converting a slice of byets into a [`Layer`] type.
pub trait FromBytes: Sized + Validate + StatelessLayer + FromBytesCurrent {
    /// Converts a slice of bytes into a [`Layer`] type, returning an error if the bytes would
    /// not form a valid layer.
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts a slice of bytes into a [`Layer`] type.
    ///
    /// # Panics
    ///
    /// The following function may panic if the slice of bytes doesn't form a valid packet
    /// structure. If an invocation of `validate()` on the slice does not return
    /// [`ValidationErrorType::InvalidSize`], this function will not panic.
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
    /// [`ValidationErrorType::InvalidSize`], this function will not panic.
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self;
}

pub trait FromBytesMut<'a>: Sized + Validate + StatelessLayer {
    /// Converts a slice of bytes into a [`LayerMut`] type, returning an error if the bytes would
    /// not form a valid layer.
    #[inline]
    fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    /// Converts a slice of bytes into a [`LayerMut`] type, returning an error if the bytes would
    /// not form a valid layer. Validation errors of type [`ValidationErrorType::ExcessBytes`]
    /// are silently ignored.
    #[inline]
    fn from_bytes_trailing(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        match Self::validate(bytes) {
            Ok(_) => Ok(Self::from_bytes_unchecked(bytes)),
            Err(e) => match e.err_type {
                ValidationErrorType::ExcessBytes(extra) => Ok(
                    Self::from_bytes_trailing_unchecked(bytes, bytes.len() - extra),
                ),
                _ => Err(e),
            },
        }
    }

    /// Converts a slice of bytes into a [`LayerMut`] type.
    ///
    /// # Panics
    ///
    /// The following function may panic if the slice of bytes doesn't form a valid packet
    /// structure. If an invocation of `validate()` on the slice does not return
    /// [`ValidationErrorType::InvalidSize`], this function will not panic.
    #[inline]
    fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        Self::from_bytes_trailing_unchecked(bytes, bytes.len())
    }

    /// Converts a slice of bytes into a [`LayerMut`] type.
    ///
    /// # Panics
    ///
    /// The following function may panic if the slice of bytes doesn't form a valid packet
    /// structure. If an invocation of `validate()` on the slice does not return
    /// [`ValidationErrorType::InvalidSize`], this function will not panic.
    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self;
}

// =============================================================================
//                     Macros to Parse Custom Layer Order
// =============================================================================

/// Creates a [`Layer`] from the given layer types with the specified order of layering, returning
/// an error if any sublayer is an incompatible payload for a given layer.
#[macro_export]
macro_rules! parse_layers {
    ($bytes:expr, $first:ty, $($next:tt),+) => {{
        match <$first as $crate::layers::traits::extras::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(mut layer) => {
                let remaining = &$bytes[<$first as $crate::layers::traits::LayerLength>::len(&layer)..];
                $crate::parse_layers!(remaining; layer, $($next),*)
            }
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty, $($next:tt),+) => {{
        match <$curr as $crate::layers::traits::extras::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(new_layer) => {
                let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerLength>::len(&new_layer)..];
                match $base_layer.set_payload(Box::new(new_layer)) {
                    Ok(_) => $crate::parse_layers!(remaining_bytes; $base_layer, $($next),*),
                    Err(e) => Err(e),
                }
            },
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty) => {{
        match <$curr as $crate::layers::traits::extras::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(new_layer) => {
                let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerLength>::len(&new_layer)..];
                match $base_layer.set_payload(Box::new(new_layer)) {
                    Ok(_) => $crate::parse_layers!(remaining_bytes; $base_layer),
                    Err(e) => Err(e),
                }
            },
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident) => {{
        if $bytes.len() > 0 {
            Err($crate::error::ValidationError {
                layer: "parse_layers!()", // TODO: fix this
                err_type: $crate::error::ValidationErrorType::ExcessBytes($bytes.len()),
                reason: "layers could not be successfully parsed from the given buffer--additional bytes remaining after parsing"
            })
        } else {
            Ok($base_layer)
        }
    }};
}

/// Creates a [`Layer`] from the given layer types with the specified order of layering.
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
        $crate::parse_layers_unchecked!(remaining_bytes; $base_layer)
    }};
    ($bytes:expr; $base_layer:ident) => {{
        $base_layer
    }};
}

// =============================================================================
//                              Library Traits
// =============================================================================

pub mod extras {
    use super::*;
    use core::{any, mem};

    pub type LayerId = any::TypeId;

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

    /// Utility method to convert a given type into some type implementing [`Layer`].
    /// This is used for converting a type implementing [`LayerRef<'_>] or [`LayerMut<'_>`]
    /// into its corresponding owned type. For example, the [`IPv4Ref<'_>`] type implements
    /// [`IntoLayer<Output=IPv4>`]. Because of this, it can be converted into its owned
    /// variant, the [`IPv4`] type.
    pub trait IntoLayer: Into<Self::Output> {
        type Output: LayerObject;
    }

    /// A trait for creating an owned layer type [`Layer`] from an instance of a layer (a [`Layer`],
    /// [`LayerRef`] or [`LayerMut`]).
    pub trait ToOwnedLayer {
        type Owned: LayerObject;

        /// Creates a new [`Layer`] out of the given layer instance.
        fn to_owned(&self) -> Self::Owned;

        /// Creates a new [`Layer`] out of the given layer instance and moves it into `target`.
        #[inline]
        fn clone_into(&self, target: &mut Self::Owned) {
            *target = self.to_owned();
        }
    }

    impl<T: LayerObject + Clone> ToOwnedLayer for T {
        type Owned = Self;
        #[inline]
        fn to_owned(&self) -> Self::Owned {
            self.clone()
        }
    }

    /// Utility method to convert a given type into a [`Box`]ed instance of [`Layer`].
    /// This is primarily used internally to facilitate appending one layer to another
    /// in a type-agnostic way.
    pub trait ToBoxedLayer {
        /// Put the given instance in a [`Box`] and return it as a `dyn Layer` type.
        fn into_boxed_layer(self) -> Box<dyn LayerObject>;

        fn to_boxed_layer(&self) -> Box<dyn LayerObject>;
    }

    /// Blanket implementation of [`IntoBoxedLayer`] for all types implementing [`IntoLayer`].
    /// This converts the given instance into a type implementing [`Layer`] using methods from
    /// [`IntoLayer`] and returns that instance within a [`Box`].
    impl<T: IntoLayer + ToOwnedLayer> ToBoxedLayer for T {
        #[inline]
        fn into_boxed_layer(self) -> Box<dyn LayerObject> {
            Box::new(self.into())
        }

        #[inline]
        fn to_boxed_layer(&self) -> Box<dyn LayerObject> {
            Box::new(self.to_owned())
        }
    }

    // If we wanted to, we could pull out the `layer_metadata(&self)` function from BaseLayer and put it in an internal trait like so:
    /*
    pub trait ObjectMetadata {
        fn layer_metadata(&self) -> &dyn LayerMetadata;
    }
    */

    // methods relating to `BaseLayer` types that would pollute the object safety of [`BaseLayer`] if added to it.
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

    pub trait BaseLayerAppendBoxed: BaseLayer + IntoLayer + Sized + ToOwnedLayer {
        fn can_append_with_boxed(&self, other: &dyn LayerObject) -> bool {
            let base: Self::Owned = self.to_owned(); // Ouch. Heavy allocation here
            if let Some(mut curr) = base.get_payload_ref() {
                while curr.get_payload_ref().is_some() {
                    curr = curr.get_payload_ref().unwrap();
                }
                curr.can_set_payload(other)
            } else {
                base.can_set_payload(other)
            }
        }

        #[inline]
        fn appended_with_boxed(
            self,
            other: Box<dyn LayerObject>,
        ) -> Result<Self::Output, &'static str> {
            if self.can_append_with_boxed(other.as_ref()) {
                Ok(self.appended_with_boxed_unchecked(other))
            } else {
                Err("nope")
            }
        }

        /// Appends the provided new layer to the existing one without check if it is an acceptable
        /// underlayer.
        ///
        /// Note that using this method can lead to a `panic!()` later on in the lifetime of the
        /// layer if the provided new layer is not permitted as a payload for the innermost underlayer.
        #[inline]
        fn appended_with_boxed_unchecked(self, other: Box<dyn LayerObject>) -> Self::Output {
            let mut base: Self::Output = self.into();
            if let Some(mut curr) = base.get_payload_mut() {
                while curr.get_payload_ref().is_some() {
                    curr = curr.get_payload_mut().unwrap();
                }
                curr.set_payload_unchecked(other);
            } else {
                base.set_payload_unchecked(other);
            }

            base
        }
    }

    pub trait AnyLayerRef<'a>: Sized {
        fn layer_id_static() -> LayerId;

        #[inline]
        fn layer_id(&self) -> LayerId {
            Self::layer_id_static()
        }

        /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
        /// Note that this function is only meanat to work if `T` is the same type as `self`.
        #[inline]
        fn cast_layer<T: AnyLayerRef<'a>>(&self) -> Result<T, &'static str> {
            if self.is_layer::<T>() {
                unsafe { Ok(self.cast_layer_unchecked()) }
            } else {
                Err("layer was not itself TODO: better msg here")
            }
        }

        #[inline]
        unsafe fn cast_layer_unchecked<T: AnyLayerRef<'a>>(&self) -> T {
            debug_assert!(self.is_layer::<T>());
            // SAFETY: caller guarantees that T is the same type as Self
            // This is accomplished with `layer_id()`
            mem::transmute_copy(self)
        }

        #[inline]
        fn is_layer<T: AnyLayerRef<'a>>(&self) -> bool {
            self.layer_id() == T::layer_id_static()
        }
    }

    // Casting directly to an immutable variant would introduce UB. Use Into<Self::AssociatedRef> and then cast immutably to be safe.
    pub trait AnyLayerMut<'a>: Sized {
        type AssociatedRef: AnyLayerRef<'a>;

        /// The unique identifier associated with the given [`Layer`].
        /// This identifier is guaranteed to be the same for [`Layer`], [`LayerRef`]
        /// and [`LayerMut`] types implementing the same layer.
        ///
        /// As an example, `Tcp::layer_id_static()` will be equal to
        /// `TcpRef::layer_id_static()` and `TcpMut::layer_id_static()`.
        /// Additionally, any instances of these types will likewise carry
        /// the same layer ID.
        ///
        /// Layer IDs

        fn layer_id_static() -> LayerId;

        #[inline]
        fn layer_id(&self) -> LayerId {
            Self::layer_id_static()
        }

        /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
        /// Note that this function is only meant to work if `T` is the same type as `self`.
        #[inline]
        fn cast_layer<T: AnyLayerMut<'a>>(&'a mut self) -> Result<T, &'static str> {
            if self.is_layer::<T>() {
                unsafe { Ok(self.cast_layer_unchecked()) }
            } else {
                Err("TODO: add error code here (layer was not itself)")
            }
        }

        #[inline]
        unsafe fn cast_layer_unchecked<T: AnyLayerMut<'a>>(&'a mut self) -> T {
            debug_assert!(self.is_layer::<T>());
            // SAFETY: caller guarantees that T is the same type as Self
            // This is accomplished with `layer_id()`
            mem::transmute_copy(&self)
        }

        #[inline]
        fn is_layer<T: AnyLayerMut<'a>>(&self) -> bool {
            self.layer_id() == T::layer_id_static()
        }
    }

    /// The default (non-custom)
    pub trait LayerOffset {
        /// Gets the index of the first byte of the layer specified by `layer_type`, if such a layer exists.
        /// This will not check the current layer against `layer_type`.
        fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize>;
    }

    pub trait LayerIndexSingleton: crate::private::Sealed {
        type LayerType: LayerObject;
    }

    /// Indicates that a given [`Layer`] can be decoded directly from bytes without requiring any
    /// additional information.
    ///
    /// Some [`Layer`] types always have the same structure to their data regardless of the state of the protocol,
    /// while others have several data layout variants that may be ambiguous without accompanying information.
    /// An example of stateless layers would be [`Dns`], which only ever has one data layout, or [`PsqlClient`],
    /// which has information encoded into the first bytes of the packet that allows a decoder to determine the
    /// byte layout of the specific packet variant. On the other hand, stateful layers require knowlede of what
    /// packets have been exchanged prior to the given byte packet in order to be successfully converted. An
    /// example of this would be the [`MysqlClient`] and [`MysqlServer`] layers.
    ///
    /// Any [`Layer`] type implementing [`StatelessLayer`] can be decoded directly from bytes using
    /// `from_bytes()`/`from_bytes_unchecked()` or by using a [`Defragment`] type. Layers that do not implement
    /// [`StatelessLayer`] can be decoded from bytes using a [`Session`] type (which keeps track of connection state)
    /// or by using constructor methods specific to that layer that require additional state information.
    pub trait StatelessLayer {}

    // ==========================================================
    //               Traits for Layer Metadata Types
    // ==========================================================

    pub trait LayerMetadata: AsAny {}

    pub trait ConstSingleton {
        fn instance() -> &'static Self;
    }

    pub trait Ipv4PayloadMetadata: LayerMetadata {
        fn ip_data_protocol(&self) -> Ipv4DataProtocol;

        /*
        /// If you're implementing this trait and you don't know what this is, just set it to `None`.
        fn diff_serv_number() -> Option<u8>;
        */
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

    layer_metadata!(SctpMetadata);

    layer_metadata!(TcpMetadata);

    impl Ipv4PayloadMetadata for TcpMetadata {
        #[inline]
        fn ip_data_protocol(&self) -> Ipv4DataProtocol {
            Ipv4DataProtocol::Tcp
        }
    }

    layer_metadata!(UdpMetadata);

    impl Ipv4PayloadMetadata for UdpMetadata {
        #[inline]
        fn ip_data_protocol(&self) -> Ipv4DataProtocol {
            Ipv4DataProtocol::Udp
        }
    }

    layer_metadata!(RawMetadata);

    impl Ipv4PayloadMetadata for RawMetadata {
        #[inline]
        fn ip_data_protocol(&self) -> Ipv4DataProtocol {
            Ipv4DataProtocol::Exp1
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
    //           CUSTOM LAYER SELECTION
    // ===========================================

    #[cfg(feature = "custom_layer_selection")]
    pub trait BaseLayerSelection: AsAny {}

    #[cfg(feature = "custom_layer_selection")]
    pub trait CustomLayerSelection: BaseLayerSelection {
        fn validate_payload(&self, curr_layer: &[u8]) -> Result<(), ValidationError>;

        fn can_set_payload(&self, payload: &dyn LayerObject) -> bool;

        fn payload_byte_index(&self, curr_layer: &[u8], desired_type: &LayerId) -> Option<usize>;

        fn payload_to_boxed(&self, curr_layer: &[u8]) -> Option<Box<dyn LayerObject>>;
    }
}
