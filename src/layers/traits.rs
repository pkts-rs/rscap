use core::{any, fmt, mem};

use rscap_macros::layer_metadata;


pub type LayerId = any::TypeId;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
pub trait IntoLayer: Into<Self::Output> {
    type Output: Layer;
}

/// Utility method to convert a given type into a [`Box`]ed instance of [`Layer`].
/// This is primarily used internally to facilitate appending one layer to another
/// in a type-agnostic way.
pub trait ToBoxedLayer {
    /// Put the given instance in a [`Box`] and return it as a `dyn Layer` type.
    fn into_boxed_layer(self) -> Box<dyn Layer>;

    fn to_boxed_layer(&self) -> Box<dyn Layer>;
}

/// Blanket implementation of [`IntoBoxedLayer`] for all types implementing [`IntoLayer`].
/// This converts the given instance into a type implementing [`Layer`] using methods from
/// [`IntoLayer`] and returns that instance within a [`Box`].
impl<T: IntoLayer + ToOwnedLayer> ToBoxedLayer for T {
    #[inline]
    fn into_boxed_layer(self) -> Box<dyn Layer> {
        Box::new(self.into())
    }

    #[inline]
    fn to_boxed_layer(&self) -> Box<dyn Layer> {
        Box::new(self.to_owned())
    }
}

/// The most basic abstraction of a packet layer.
/// The [`BaseLayer`] trait enables packet layers of different implementations (e.g. [`Layer`],
/// [`LayerRef`] and [`LayerMut`]) to be used interchangably for certain operations. For instance,
/// concatenation of packets is achieved via this type in the [`BaseLayerAppend`]
/// and [`core::ops::Div`] traits.
pub trait BaseLayer: ToBoxedLayer {
    // fn len(&self) -> usize;

    fn layer_metadata(&self) -> &dyn LayerMetadata; // put custom layer selection in layer metadata

    /*
    #[cfg(feature = "custom_layer_selection")]
    fn custom_layer_selection_instance(&self) -> &dyn BaseLayerSelection;
    */
}

// methods relating to `BaseLayer` types that would pollute the object safety of [`BaseLayer`] if added to it.
pub trait BaseLayerImpl: BaseLayer {
    fn layer_metadata_instance() -> &'static dyn LayerMetadata;
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
        let mut base: Self::Output = self.into();
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

pub trait LayerImpl: BaseLayer {
    #[inline]
    fn can_set_payload(&self, payload: Option<&dyn Layer>) -> bool {
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

    fn can_set_payload_default(&self, payload: Option<&dyn Layer>) -> bool;

    fn len(&self) -> usize;
}

pub trait ToByteVec {
    fn to_byte_vec_extend(&self, bytes: &mut Vec<u8>);

    #[inline]
    fn to_byte_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.to_byte_vec_extend(&mut bytes);
        bytes
    }
}

pub trait Layer: AsAny + BaseLayer + LayerImpl + fmt::Debug + ToByteVec {
    //fn layer_name(&self) -> &'static str;

    fn get_payload_ref(&self) -> Option<&dyn Layer>;

    fn get_payload_mut(&mut self) -> Option<&mut dyn Layer>;

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
        self.to_boxed_layer()
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

    /*
    /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
    /// Note that this function is only meant to work if `T` is the same type as `self`.
    #[inline]
    fn cast_immutable_layer<T: AnyLayerRef<'a>>(&'a self) -> Result<T, &'static str> {
        if Self::is_mutable_variant_of::<T>() {
            unsafe { Ok(self.cast_immutable_layer_unchecked()) }
        } else {
            Err("TODO: add error code here (layer was not itself)")
        }
    }
    */

    #[inline]
    unsafe fn cast_layer_unchecked<T: AnyLayerMut<'a>>(&'a mut self) -> T {
        debug_assert!(self.is_layer::<T>());
        // SAFETY: caller guarantees that T is the same type as Self
        // This is accomplished with `layer_id()`
        mem::transmute_copy(&self)
    }

    /*
    /// Allows for a given `AnyLayer` type to be cast to another instance of itself.
    /// Note that this function is only meant to work if `T` is the same type as `self`.
    #[inline]
    unsafe fn cast_immutable_layer_unchecked<T: AnyLayerRef<'a>>(&'a self) -> T {
        mem::transmute_copy(&self)
    }
    */

    #[inline]
    fn is_layer<T: AnyLayerMut<'a>>(&self) -> bool {
        self.layer_id() == T::layer_id_static()
    }

    /*
    #[inline]
    fn is_mutable_variant_of<T: AnyLayerRef<'a>>() -> bool {
        Self::AssociatedRef::type_layer_id() == T::type_layer_id()
    }
    */
}

pub trait LayerRef<'a>: AnyLayerRef<'a> + BaseLayer + Into<&'a [u8]> {}

/// The default (non-custom)
pub trait LayerOffset {
    /// Gets the index of the first byte of the layer specified by `layer_type`, if such a layer exists.
    /// This will not check the current layer against `layer_type`.
    fn get_layer_offset_default(bytes: &[u8], layer_type: LayerId) -> Option<usize>;
}

pub trait LayerRefIndex<'a>: LayerOffset {
    fn get_layer<T: LayerRef<'a> + FromBytesRef<'a>>(&'a self) -> Option<T>;

    #[inline]
    fn index<T: LayerRef<'a> + FromBytesRef<'a>>(&'a self) -> T {
        self.get_layer().unwrap()
    }
}

pub trait LayerMutIndex<'a>: LayerRefIndex<'a> + AnyLayerMut<'a> {
    fn get_layer_mut<T: LayerMut<'a> + FromBytesMut<'a>>(&'a mut self) -> Option<T>;

    #[inline]
    fn index_mut<T: LayerMut<'a> + FromBytesMut<'a>>(&'a mut self) -> T {
        self.get_layer_mut().unwrap()
    }
}

pub trait LayerMut<'a>: AnyLayerMut<'a> + BaseLayer + Validate {}

pub trait LayerTypeIndex: crate::private::Sealed {
    type LayerType: Layer;
}

/*
pub trait LayerTypeIndexImpl {
    type Output: Layer + ?Sized;
    fn associated_type_from_bytes_ignore_payload(
        &self,
        bytes: &[u8],
    ) -> Result<Box<Self::Output>, ValidationError>;

    fn associated_type_id(&self) -> any::TypeId;
}
*/

pub trait Validate: BaseLayer + StatelessLayer {
    fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let curr_valid = Self::validate_current_layer(bytes);
        if curr_valid == Err(ValidationError::InvalidSize) {
            return curr_valid;
        }

        let next_valid = Self::validate_payload(bytes);
        match (curr_valid, next_valid) {
            // THIS ORDER MATTERS
            // TODO: review this order to ensure correctness
            (_, Err(ValidationError::InvalidSize)) => next_valid,
            (Err(ValidationError::InvalidValue), _) => curr_valid,
            (_, Err(ValidationError::InvalidValue)) => next_valid,
            (_, Err(ValidationError::TrailingBytes(_))) => next_valid,
            (Err(ValidationError::TrailingBytes(_)), _) => curr_valid,
            _ => Ok(()),
        }
    }

    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError>;

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

    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError>;
}

pub trait FromBytes: Sized + Validate + StatelessLayer {
    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    // TODO: add from_bytes_trailing here?

    fn from_bytes_unchecked(bytes: &[u8]) -> Self;
}

pub trait FromBytesRef<'a>: Sized + Validate + StatelessLayer {
    #[inline]
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    // TODO: add from_bytes_trailing here?

    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self;
}

pub trait FromBytesCurrent: FromBytes {
    fn from_bytes_current_layer(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate_current_layer(bytes)?;
        Ok(Self::from_bytes_current_layer_unchecked(bytes))
    }

    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self;
}

pub trait FromBytesMut<'a>: Sized + Validate + StatelessLayer {
    #[inline]
    fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    fn from_bytes_trailing(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        match Self::validate(bytes) {
            Ok(_) => Ok(Self::from_bytes_unchecked(bytes)),
            Err(ValidationError::TrailingBytes(extra)) => Ok(Self::from_bytes_trailing_unchecked(
                bytes,
                bytes.len() - extra,
            )),
            Err(e) => Err(e),
        }
    }

    fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        Self::from_bytes_trailing_unchecked(bytes, bytes.len())
    }

    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self;
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

#[macro_export]
macro_rules! parse_layers {
    ($bytes:expr, $first:ty, $($next:tt),+) => {{
        match <$first as $crate::layers::traits::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(mut layer) => {
                let remaining = &$bytes[<$first as $crate::layers::traits::LayerImpl>::len(&layer)..];
                $crate::parse_layers!(remaining; layer, $($next),*)
            }
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty, $($next:tt),+) => {{
        match <$curr as $crate::layers::traits::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(new_layer) => {
                let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerImpl>::len(&new_layer)..];
                match $base_layer.set_payload(Some(Box::new(new_layer))) {
                    Ok(_) => $crate::parse_layers!(remaining_bytes; $base_layer, $($next),*),
                    Err(_) => Err($crate::layers::traits::ValidationError::InvalidValue),
                }
            },
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident, $curr:ty) => {{
        match <$curr as $crate::layers::traits::FromBytesCurrent>::from_bytes_current_layer($bytes) {
            Ok(new_layer) => {
                let remaining_bytes = &$bytes[<$curr as $crate::layers::traits::LayerImpl>::len(&new_layer)..];
                match $base_layer.set_payload(Some(Box::new(new_layer))) {
                    Ok(_) => $crate::parse_layers!(remaining_bytes; $base_layer),
                    Err(_) => Err($crate::layers::traits::ValidationError::InvalidValue),
                }
            },
            Err(e) => Err(e),
        }
    }};
    ($bytes:expr; $base_layer:ident) => {{
        if $bytes.len() > 0 {
            Err($crate::layers::traits::ValidationError::TrailingBytes($bytes.len()))
            // $base_layer.set_payload(Some(Box::new($crate::layers::Raw::from_bytes($bytes).unwrap()))).unwrap(); // TODO: impl Ok for Raw to bytes
        } else {
            Ok($base_layer)
        }
    }};
}

// ==========================================================
//               Traits for Layer Metadata Types
// ==========================================================

pub trait LayerMetadata: AsAny {}

pub trait ConstSingleton {
    fn instance() -> &'static Self;
}

pub trait Ipv4PayloadMetadata: LayerMetadata {
    fn ip_protocol_number(&self) -> u8;

    /*
    /// If you're implementing this trait and you don't know what this is, just set it to `None`.
    fn diff_serv_number() -> Option<u8>;
    */
}

pub trait MysqlMetadata: LayerMetadata {}

// ==========================================================
//               Concrete Layer Metadata Types
// ==========================================================

// These are left public so that the user can implement further Metadata functions as desired

layer_metadata!(Ipv4Metadata);

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

layer_metadata!(TcpMetadata);

impl Ipv4PayloadMetadata for TcpMetadata {
    #[inline]
    fn ip_protocol_number(&self) -> u8 {
        0x06
    }
}

layer_metadata!(UdpMetadata);

impl Ipv4PayloadMetadata for UdpMetadata {
    #[inline]
    fn ip_protocol_number(&self) -> u8 {
        0x11
    }
}

layer_metadata!(RawMetadata);

impl Ipv4PayloadMetadata for RawMetadata {
    #[inline]
    fn ip_protocol_number(&self) -> u8 {
        0xFD // Experimental protocol
    }
}

impl MysqlMetadata for RawMetadata {}

layer_metadata!(MysqlPacketMetadata);

layer_metadata!(MysqlClientMetadata);

impl MysqlMetadata for MysqlClientMetadata {}

layer_metadata!(MysqlServerMetadata);

impl MysqlMetadata for MysqlServerMetadata {}

// ===========================================
//           CUSTOM LAYER SELECTION
// ===========================================

#[cfg(feature = "custom_layer_selection")]
pub trait BaseLayerSelection: AsAny {}

#[cfg(feature = "custom_layer_selection")]
pub trait CustomLayerSelection: BaseLayerSelection {
    fn validate_payload(&self, curr_layer: &[u8]) -> Result<(), ValidationError>;

    fn can_set_payload(&self, payload: Option<&dyn Layer>) -> bool;

    fn get_payload_index(&self, curr_layer: &[u8], desired_type: &LayerId) -> Option<usize>;

    fn payload_to_boxed(&self, curr_layer: &[u8]) -> Option<Box<dyn Layer>>;
}
