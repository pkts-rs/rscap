use core::{any, mem};

use rscap_macros::{layer_metadata, layer_selection};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ValidationError {
    InvalidSize,          // Fatal error--can lead to panic! if used unchecked
    InvalidValue,         // Nonfatal error--struct not reflexive if used unchecked
    TrailingBytes(usize), // Extra bytes appeared at end of payload--prefix reflexive if used unchecked
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

/// Utility method to convert a given type into some type implementing [`Layer`].
/// This is used for converting a type implementing [`LayerRef<'_>] or [`LayerMut<'_>`]
/// into its corresponding owned type. For example, the [`IPv4Ref<'_>`] type implements
/// [`IntoLayer<Output=IPv4>`]. Because of this, it can be converted into its owned
/// variant, the [`IPv4`] type.
pub trait IntoLayer {
    type Output: Layer;

    /// Convert the given instance into its [`Layer`] variant.
    fn into_layer(self) -> Self::Output;
}

/// Blanket implementation of [`IntoLayer`] for all types implementing [`Layer`].
/// A type implementing [`Layer`] can simply return itself to satisfy this trait.
impl<T: Layer> IntoLayer for T {
    type Output = Self;

    #[inline]
    fn into_layer(self) -> Self::Output {
        self
    }
}

/// Utility method to convert a given type into a [`Box`]ed instance of [`Layer`].
/// This is primarily used internally to facilitate appending one layer to another
/// in a type-agnostic way.
pub trait IntoBoxedLayer {
    /// Put the given instance in a [`Box`] and return it as a `dyn Layer` type.
    fn into_boxed_layer(self) -> Box<dyn Layer>;
}

/// Blanket implementation of [`IntoBoxedLayer`] for all types implementing [`IntoLayer`].
/// This converts the given instance into a type implementing [`Layer`] using methods from
/// [`IntoLayer`] and returns that instance within a [`Box`].
impl<T: IntoLayer> IntoBoxedLayer for T {
    #[inline]
    fn into_boxed_layer(self) -> Box<dyn Layer> {
        Box::new(self.into_layer())
    }
}

/// The most basic abstraction of a packet layer.
/// The [`BaseLayer`] trait enables packet layers of different implementations (e.g. [`Layer`],
/// [`LayerRef`] and [`LayerMut`]) to be used interchangably for certain operations. For instance,
/// concatenation of packets is achieved via this type in the [`BaseLayerAppend`]
/// and [`core::ops::Div`] traits.
pub trait BaseLayer: IntoBoxedLayer {
    /*
    /// The name of the instance's layer type (e.g. `"TCP"`, `"ARP"`, `"IPv6"`).
    fn layer_name(&self) -> &'static str;
    */

    // fn len(&self) -> usize;

    fn layer_metadata(&self) -> &dyn LayerMetadata; // put custom layer selection in layer metadata

    #[cfg(feature = "custom_layer_selection")]
    fn custom_layer_selection_instance(&self) -> &dyn BaseLayerSelection;
}

pub trait BaseLayerAppend: Sized + IntoLayer {
    fn can_append_with<T: BaseLayer>(&self, other: &T) -> bool;

    #[inline]
    fn appended_with<T: BaseLayer>(self, other: T) -> Result<Self::Output, Self> {
        if self.can_append_with(&other) {
            Ok(self.appended_with_unchecked(other))
        } else {
            Err(self)
        }
    }

    #[inline]
    fn appended_with_unchecked<T: BaseLayer>(self, other: T) -> Self::Output {
        let mut base = self.into_layer();
        if let Some(mut curr) = base.get_payload_mut() {
            while curr.get_payload_ref().is_some() {
                curr = curr.get_payload_mut().unwrap();
            }
            curr.set_payload_unchecked(Some(other.into_boxed_layer()));
        } else {
            base.set_payload_unchecked(Some(other.into_boxed_layer()));
        }

        base
    }
}

pub trait ToBoxedLayer {
    fn to_boxed(&self) -> Box<dyn Layer>;
}

impl<T: ToOwnedLayer> ToBoxedLayer for T {
    #[inline]
    fn to_boxed(&self) -> Box<dyn Layer> {
        self.to_owned().into_boxed_layer()
    }
}

pub trait Layer: AsAny + IntoBoxedLayer + BaseLayer + ToBoxedLayer {
    //fn layer_name(&self) -> &'static str;

    fn get_payload_ref(&self) -> Option<&dyn Layer>;

    fn get_payload_mut(&mut self) -> Option<&mut dyn Layer>;

    fn can_set_payload(&self, payload: Option<&dyn Layer>) -> bool;

    fn set_payload(&mut self, payload: Option<Box<dyn Layer>>) -> Result<(), &'static str> {
        if !self.can_set_payload(payload.as_ref().map(|layer| layer.as_ref())) {
            Err("payload wasn't a type that could be set")
        } else {
            self.set_payload_unchecked(payload);
            Ok(())
        }
    }

    fn set_payload_unchecked(&mut self, payload: Option<Box<dyn Layer>>);
}

impl Clone for Box<dyn Layer> {
    #[inline]
    fn clone(&self) -> Self {
        self.to_boxed()
    }
}

pub trait LayerIndex: Layer {
    fn get_layer<T: Layer>(&self) -> Option<&T> {
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

    fn get_layer_mut<T: Layer>(&mut self) -> Option<&mut T> {
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
}

pub trait LayerAppend: BaseLayerAppend + Layer {
    fn append_layer<T: BaseLayer>(&mut self, other: T) -> Result<(), &'static str> {
        if self.can_append_with(&other) {
            self.append_layer_unchecked(other);
            Ok(())
        } else {
            Err("Layers could not be appended")
        }
    }

    fn append_layer_unchecked<T: BaseLayer>(&mut self, other: T) {
        if let Some(mut curr) = self.get_payload_mut() {
            while curr.get_payload_ref().is_some() {
                curr = curr.get_payload_mut().unwrap();
            }
            curr.set_payload_unchecked(Some(other.into_boxed_layer()));
        } else {
            self.set_payload_unchecked(Some(other.into_boxed_layer()));
        }
    }
}

pub trait ToOwnedLayer {
    type Owned: Layer;

    fn to_owned(&self) -> Self::Owned;

    #[inline]
    fn clone_into(&self, target: &mut Self::Owned) {
        *target = self.to_owned();
    }
}

impl<T: Layer + Clone> ToOwnedLayer for T {
    type Owned = Self;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        self.clone()
    }
}

// ==========================================================
//                    Traits for References
// ==========================================================

pub trait AnyLayerRef<'a>: Sized {
    fn type_layer_id() -> any::TypeId;

    #[inline]
    fn layer_id(&self) -> any::TypeId {
        Self::type_layer_id()
    }

    /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
    /// Note that this function is only meanat to work if `T` is the same type as `self`.
    #[inline]
    fn cast_layer<T: AnyLayerRef<'a>>(self) -> Result<T, Self> {
        if self.is_layer::<T>() {
            unsafe { Ok(self.cast_layer_unchecked()) }
        } else {
            Err(self)
        }
    }

    #[inline]
    unsafe fn cast_layer_unchecked<T: AnyLayerRef<'a>>(self) -> T {
        debug_assert!(self.is_layer::<T>());
        // SAFETY: caller guarantees that T is the same type as Self
        // This is accomplished with `layer_id()`
        mem::transmute_copy(&self)
    }

    #[inline]
    fn is_layer<T: AnyLayerRef<'a>>(&self) -> bool {
        self.layer_id() == T::type_layer_id()
    }
}

pub trait AnyLayerMut<'a>: Sized {
    type AssociatedRef: AnyLayerRef<'a>;

    fn type_layer_id() -> any::TypeId;

    #[inline]
    fn layer_id(&self) -> any::TypeId {
        Self::type_layer_id()
    }

    /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
    /// Note that this function is only meant to work if `T` is the same type as `self`.
    #[inline]
    fn cast_layer<T: AnyLayerMut<'a>>(self) -> Result<T, Self> {
        if self.is_layer::<T>() {
            unsafe { Ok(self.cast_layer_unchecked()) }
        } else {
            Err(self)
        }
    }

    /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
    /// Note that this function is only meant to work if `T` is the same type as `self`.
    #[inline]
    fn cast_immutable_layer<T: AnyLayerRef<'a>>(self) -> Result<T, Self> {
        if Self::is_mutable_variant_of::<T>() {
            unsafe { Ok(self.cast_immutable_layer_unchecked()) }
        } else {
            Err(self)
        }
    }

    #[inline]
    unsafe fn cast_layer_unchecked<T: AnyLayerMut<'a>>(self) -> T {
        debug_assert!(self.is_layer::<T>());
        // SAFETY: caller guarantees that T is the same type as Self
        // This is accomplished with `layer_id()`
        mem::transmute_copy(&self)
    }

    /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
    /// Note that this function is only meant to work if `T` is the same type as `self`.
    #[inline]
    unsafe fn cast_immutable_layer_unchecked<T: AnyLayerRef<'a>>(self) -> T {
        mem::transmute_copy(&self)
    }

    #[inline]
    fn is_layer<T: AnyLayerMut<'a>>(&self) -> bool {
        self.layer_id() == T::type_layer_id()
    }

    #[inline]
    fn is_mutable_variant_of<T: AnyLayerRef<'a>>() -> bool {
        Self::AssociatedRef::type_layer_id() == T::type_layer_id()
    }
}

pub trait LayerRef<'a>: AnyLayerRef<'a> + BaseLayer + ValidateBytes + FromBytes<'a> {
    fn as_bytes(&self) -> &'a [u8];

    fn get_layer<T: LayerRef<'a>>(&self) -> Option<T>;
}

pub trait LayerRefIndex<'a>: LayerRef<'a> {}

pub trait LayerMut<'a>: AnyLayerMut<'a> + BaseLayer + ValidateBytes + FromBytesMut<'a> {
    fn as_bytes(&'a self) -> &'a [u8];

    fn as_bytes_mut(&'a mut self) -> &'a mut [u8];

    fn get_layer<T: LayerRef<'a>>(&'a self) -> Option<T>;

    fn get_layer_mut<T: LayerMut<'a>>(&'a mut self) -> Option<T>;

    fn get_layer_from_raw<'b, T: LayerRef<'b>>(bytes: &'b [u8]) -> Option<T>;

    fn get_layer_mut_from_raw<'b, T: LayerMut<'b>>(bytes: &'b mut [u8]) -> Option<T>;
}

pub trait LayerStruct: crate::private::Sealed {
    type LayerType: Layer;
}

pub trait ValidateBytes : BaseLayer {
    fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let curr_valid = Self::validate_current_layer(bytes);
        if curr_valid == Err(ValidationError::InvalidSize) {
            return curr_valid
        }

        let next_valid = Self::validate_payload(bytes);
        match (curr_valid, next_valid) {
            // THIS ORDER MATTERS
            // TODO: review this order to ensure correctness
            (_, Err(ValidationError::InvalidSize)) => return next_valid,
            (Err(ValidationError::InvalidValue), _) => return curr_valid,
            (_, Err(ValidationError::InvalidValue)) => return next_valid,
            (_, Err(ValidationError::TrailingBytes(_))) => return next_valid,
            (Err(ValidationError::TrailingBytes(_)), _) => return curr_valid,
            _ => return Ok(())
        }
    }

    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError>;

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError>;



//    fn validate_current(bytes: &[u8]) -> Result<(), ValidationError>;
}

pub trait FromBytes<'a>: Sized + ValidateBytes {
    #[inline]
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    // TODO: add from_bytes_trailing here?

    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self;
}

pub trait FromBytesMut<'a>: Sized + ValidateBytes {
    #[inline]
    fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    fn from_bytes_trailing(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        match Self::validate(bytes) {
            Ok(_) | Err(ValidationError::TrailingBytes(_)) => Ok(Self::from_bytes_unchecked(bytes)),
            Err(e) => Err(e),
        }
    }

    fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self;
}

// ==========================================================
//               Traits for Layer Metadata Types
// ==========================================================

pub trait LayerMetadata: AsAny {}

pub trait ConstSingleton {
    fn instance() -> &'static Self;
}

pub trait Ipv4Metadata: LayerMetadata {
    fn ip_protocol_number(&self) -> u8;

    /*
    /// If you're implementing this trait and you don't know what this is, just set it to `None`.
    fn diff_serv_number() -> Option<u8>;
    */
}

// ==========================================================
//               Concrete Layer Metadata Types
// ==========================================================

// These are left public so that the user can implement further Metadata functions as desired

layer_metadata!(Ipv4AssociatedMetadata);

/*
Note that the layer_metadata! macro is quivalent to:

```rust
#[derive(LayerMetadata)]
pub struct IPv4Metadata {
    _zst: (),
}

const IPV4_METADATA_INSTANCE: IPv4Metadata = IPv4Metadata { _zst: () };

impl ConstSingleton for IPv4Metadata {
    fn instance() -> &'static Self {
        &IPV4_METADATA_INSTANCE
    }
}
```
*/

layer_metadata!(TcpAssociatedMetadata);

impl Ipv4Metadata for TcpAssociatedMetadata {
    #[inline]
    fn ip_protocol_number(&self) -> u8 {
        0x06
    }
}

layer_metadata!(UdpAssociatedMetadata);

impl Ipv4Metadata for UdpAssociatedMetadata {
    #[inline]
    fn ip_protocol_number(&self) -> u8 {
        0x11
    }
}

layer_metadata!(RawAssociatedMetadata);

// ===========================================
//           CUSTOM LAYER SELECTION
// ===========================================

#[cfg(feature = "custom_layer_selection")]
pub trait BaseLayerSelection: AsAny {}

#[cfg(feature = "custom_layer_selection")]
pub trait CustomLayerSelection: BaseLayerSelection {
    fn validate_payload(&self, curr_layer: &[u8]) -> Result<(), ValidationError>;

    fn next_layer_to_boxed(&self, curr_layer: &[u8]) -> Box<dyn Layer>;

    fn get_layer_from_next(&self, curr_layer: &[u8], desired_type: &any::TypeId) -> Option<usize>;
}

#[cfg(feature = "custom_layer_selection")]
layer_selection!(Ipv4LayerSelection);

#[cfg(feature = "custom_layer_selection")]
layer_selection!(TcpLayerSelection);

#[cfg(feature = "custom_layer_selection")]
layer_selection!(UdpLayerSelection);

#[cfg(feature = "custom_layer_selection")]
layer_selection!(RawLayerSelection);
