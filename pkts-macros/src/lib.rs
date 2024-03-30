// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Structures used for memory-mapped packet sockets.

#![forbid(unsafe_code)]

use syn::parse_macro_input;

// ======================================================
//            Blanket Derive Implementations
// ======================================================

// Apart from `impl IndexLayer...`, all of the following is extra plumbing that enables the index (`[]`) operation
// to be used with the type's name just like Python. This is possible because Rust allows const values to have the
// same name as structs--they are considered to be in different namespaces. We define a const value for the given
// Layer with an the same name as that Layer, assign it to a unique type that implements the `LayerStruct` trait with
// the associated type being set to the Layer's type, and then implement indexing over all layer types for that one-off
// unique type such that it will return the associated type.
//
// For instance, if this were derived for `TCP`, the macro would define a `TCPStructIdentifier` struct that implements
// `LayerStruct`, instantiate a constant of that type with name `TCP`, and implement ops::Index and ops::IndexMut for the
// `TCPStructIdentifier` type over all LayerTypes. With this done, a user of the library can now index into any layer
// that also implements `IndexLayer` like so:
//
// ```
// let mut pkt: TCP = TCP::from(bytes);
// let tls = &pkt[TLS];
// let mut http = &mut pkt[HTTP];
// let tunnelled_tcp = &mut http[TCP];
// // ... and so on and so forth.
// ```
//
// Note that this approach bends the rules a bit with regards to naming--if a struct has lowercase letters in it, then
// so will the const even though consts are supposed to use SCREAMING_SNAKE_CASE. For the purposes of usability and making
// the library feel very similar to scapy's interface, we consider this a fair trade.

#[proc_macro_derive(StatelessLayer)]
pub fn derive_stateless_layer_owned(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as syn::DeriveInput);
    let mut output = proc_macro::TokenStream::new();
    let layer_type = ast.ident;
    // let layer_type_index = quote::format_ident!("{}TypeIndex", layer_type);
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    if !ast.attrs.iter().any(|a| a.path.is_ident("owned_type")) {
        let ref_type: syn::Ident = ast
            .attrs
            .iter()
            .find(|&a| a.path.is_ident("ref_type"))
            .unwrap()
            .parse_args()
            .unwrap();
        output.extend(proc_macro::TokenStream::from(quote::quote! {
            impl StatelessLayer for #layer_type { }

            impl FromBytes for #layer_type {
                #[inline]
                fn from_bytes_unchecked(bytes: &[u8]) -> Self {
                    Self::from(#ref_type::from_bytes_unchecked(bytes))
                }
            }

            impl Validate for #layer_type {
                #[inline]
                fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
                    #ref_type::validate_current_layer(curr_layer)
                }

                #[doc(hidden)]
                #[inline]
                fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
                    #ref_type::validate_payload_default(curr_layer)
                }
            }

            impl From<&#ref_type<'_>> for #layer_type {
                fn from(r: &#ref_type<'_>) -> Self {
                    let mut res = Self::from_bytes_current_layer_unchecked((*r).into());
                    match r.layer_metadata().as_any().downcast_ref::<&dyn CustomLayerSelection>() {
                        Some(&layer_selection) => match layer_selection.payload_to_boxed((*r).into()) {
                            Some(payload) => { res.add_payload_unchecked(payload); },
                            None => (),
                        }
                        None => res.payload_from_bytes_unchecked_default((*r).into()),
                    }
                    res
                }
            }
        }));
    } else if !ast.attrs.iter().any(|a| a.path.is_ident("ref_type")) {
        output.extend(proc_macro::TokenStream::from(quote::quote! {
            impl #impl_generics StatelessLayer for #layer_type #ty_generics #where_clause { }
        }));
    } else {
        let ref_type: syn::Ident = ast
            .attrs
            .iter()
            .find(|&a| a.path.is_ident("ref_type"))
            .unwrap()
            .parse_args()
            .unwrap();
        output.extend(proc_macro::TokenStream::from(quote::quote! {
            impl #impl_generics StatelessLayer for #layer_type #ty_generics #where_clause { }

            impl Validate for #layer_type<'_> {
                #[inline]
                fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
                    #ref_type::validate_current_layer(curr_layer)
                }

                #[doc(hidden)]
                #[inline]
                fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
                    #ref_type::validate_payload_default(curr_layer)
                }
            }
        }));
    }

    output
}

#[proc_macro_derive(Layer, attributes(ref_type, metadata_type))]
pub fn derive_layer_owned(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as syn::DeriveInput);
    let mut output = proc_macro::TokenStream::new();
    let layer_type = ast.ident;
    let layer_type_index = quote::format_ident!("{}TypeIndex", layer_type);
    let ref_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.is_ident("ref_type"))
        .expect("ref_type attribute required for deriving Layer")
        .parse_args()
        .expect("ref_type attribute must contain a struct name");
    let metadata_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.is_ident("metadata_type"))
        .expect("metadata_type attribute required for deriving Layer")
        .parse_args()
        .expect("metadata_type attribute must contain a struct name");

    // extern crate self as rscap;
    // TODO: use the above within the quote! to make derives stable without including layer names
    output.extend(derive_base_layer_impl(
        &ast.generics,
        &layer_type,
        layer_type.to_string().as_str(),
        &metadata_type,
    ));
    output.extend(proc_macro::TokenStream::from(quote::quote! {
        impl<T: BaseLayer + ToLayer> core::ops::Div<T> for #layer_type {
            type Output = #layer_type;

            /// Combines `rhs` as the next `Layer` of `self`.
            ///
            /// The [`appended_with()`](BaseLayerAppend::appended_with()) method performs the same
            /// operation as indexing, but returns a `Result` instead of `panic`king on failure.
            #[inline]
            fn div(mut self, rhs: T) -> Self::Output {
                self.append_layer_unchecked(rhs);
                self
            }
        }

        impl<T: BaseLayer + ToLayer> core::ops::DivAssign<T> for #layer_type {
            /// Adds `rhs` as the next `Layer` of `self`.
            ///
            /// The [`append_layer()`](Layer::append_layer()) method performs the same
            /// operation as indexing, but returns a `Result` instead of `panic`king on failure.
            #[inline]
            fn div_assign(&mut self, rhs: T) {
                self.append_layer(rhs).unwrap()
            }
        }

        impl From<#ref_type<'_>> for #layer_type {
            fn from(value: #ref_type<'_>) -> Self {
                Self::from(&value)
            }
        }

        #[doc(hidden)]
        pub struct #layer_type_index {
            _zst: (), // Allows the StructIdentifier to be public but not recreatable
        }

        impl crate::private::Sealed for #layer_type_index { }

        impl LayerIndexSingleton for #layer_type_index {
            type LayerType = #layer_type;
        }

        #[allow(non_upper_case_globals)]
        #[doc(hidden)]
        pub const #layer_type: #layer_type_index = #layer_type_index { _zst: () };

        impl<T: LayerIndexSingleton> core::ops::Index<T> for #layer_type {
            /// The `Layer` returned by the indexing operation.
            type Output = T::LayerType;

            /// Returns the first [`Layer`] of the given type in the packet.
            ///
            /// For `Layer`s with multiple payloads, this performs a breadth-first search to return
            /// the first `Layer` of the correct type. This operator is implemented with
            /// [`get_layer()`](LayerIndex::get_layer()); more information on its workings is
            /// documented there.
            #[inline]
            fn index(&self, _: T) -> &Self::Output {
                self.get_layer().unwrap()
            }
        }

        impl<T: LayerIndexSingleton> core::ops::IndexMut<T> for #layer_type {
            /// Returns the first [`Layer`] of the given type in the packet.
            ///
            /// For `Layer`s with multiple payloads, this performs a breadth-first search to return
            /// the first `Layer` of the correct type. This operator is implemented with
            /// [`get_layer_mut()`](LayerIndex::get_layer_mut()); more information on its workings
            /// is documented there.
            #[inline]
            fn index_mut(&mut self, _: T) -> &mut Self::Output {
                self.get_layer_mut().unwrap()
            }
        }

        #[doc(hidden)]
        impl LayerIdentifier for #layer_type {
            #[inline]
            fn layer_id() -> LayerId {
                 core::any::TypeId::of::<#layer_type>()
            }
        }

        impl Layer for #layer_type { }

        impl IndexLayer for #layer_type {}
    }));

    output
}

#[proc_macro_derive(LayerRef, attributes(owned_type, metadata_type, data_field))]
pub fn derive_layer_ref(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as syn::DeriveInput);
    let layer_type = ast.ident;
    let mut output = proc_macro::TokenStream::new();
    let owned_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.segments.len() == 1 && a.path.segments[0].ident == "owned_type")
        .expect("owned_type attribute required for deriving `LayerRef`")
        .parse_args()
        .expect("owned_type attribute must contain a struct name that implements `LayerRef`");
    let metadata_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.segments.len() == 1 && a.path.segments[0].ident == "metadata_type")
        .expect("metadata_type attribute required for deriving LayerRef")
        .parse_args()
        .expect("metadata_type attribute must contain a struct name");
    let data_field = match ast.data {
        syn::Data::Struct(data_struct) => match data_struct.fields {
            syn::Fields::Named(named) => named
                .named
                .iter()
                .find(|field| {
                    field
                        .attrs
                        .iter()
                        .any(|attr| attr.path.is_ident("data_field"))
                })
                .expect("data_field inner attribute required to derive `LayerRef`")
                .ident
                .as_ref()
                .unwrap()
                .clone(),
            _ => panic!("data_field associated field must be named"),
        },
        _ => panic!("Only structs are currently supported for `LayerRef` derive"),
    };

    output.extend(derive_base_layer_impl(
        &ast.generics,
        &layer_type,
        owned_type.to_string().as_str(),
        &metadata_type,
    ));
    output.extend(proc_macro::TokenStream::from(quote::quote! {
        impl LayerLength for #layer_type<'_> {
            #[inline]
            fn len(&self) -> usize {
                self.#data_field.len()
            }
        }

        impl<'a> IndexLayerRef<'a> for #layer_type<'a> {
            fn get_layer<T: LayerRef<'a> + FromBytesRef<'a>>(&'a self) -> Option<T> {
                if <Self as LayerIdentifier>::layer_id() == T::layer_id() {
                    return Some(T::from_bytes_unchecked(self.#data_field))
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    return custom_selection
                        .payload_byte_index(self.#data_field, &T::layer_id())
                        .map(|offset| T::from_bytes_unchecked(self.#data_field));
                }

                match Self::payload_byte_index_default(self.#data_field, T::layer_id()) {
                    Some(offset) => Some(T::from_bytes_unchecked(&self.#data_field[offset..])),
                    None => None
                }
            }

            fn get_nth_layer<T: LayerRef<'a> + FromBytesRef<'a> + BaseLayerMetadata>(&'a self, mut n: usize) -> Option<T> {
                match n {
                    0 => return None,
                    1 => return self.get_layer(),
                    _ => (),
                }

                if <Self as LayerIdentifier>::layer_id() == T::layer_id() {
                    n -= 1
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    if let Some(mut curr_offset) = custom_selection.payload_byte_index(self.#data_field, &T::layer_id()) {
                        n -= 1;
                        if n == 0 {
                            return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                        }

                        while let Some(new_offset) =
                            if let Some(custom_selection) = T::metadata().as_any().downcast_ref::<&dyn CustomLayerSelection>() {
                                custom_selection.payload_byte_index(&self.#data_field[curr_offset..], &T::layer_id())
                            } else {
                                T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id())
                            }
                        {
                            curr_offset = new_offset;
                            n -= 1;
                            if n == 0 {
                                return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                            }
                        }
                    }
                    return None
                }

                if let Some(mut curr_offset) = Self::payload_byte_index_default(self.#data_field, T::layer_id()) {
                    n -= 1;
                    if n == 0 {
                        return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                    }

                    while let Some(new_offset) = T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id()) {
                        curr_offset = new_offset;
                        n -= 1;
                        if n == 0 {
                            return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                        }
                    }
                }

                None
            }
        }

        impl LayerIdentifier for #layer_type<'_> {
            #[inline]
            fn layer_id() -> LayerId {
                core::any::TypeId::of::<#owned_type>()
            }
        }

        impl ToLayer for #layer_type<'_> {
            type Owned = #owned_type;

            #[inline]
            fn to_layer(&self) -> Self::Owned {
                Self::Owned::from(self)
            }
        }

        impl<'a> From<#layer_type<'a>> for &'a [u8] {
            fn from(value: #layer_type<'a>) -> Self {
                value.#data_field
            }
        }

        impl<'a> LayerRef<'a> for #layer_type<'a> { }
    }));

    output
}

fn derive_base_layer_impl(
    generics: &syn::Generics,
    layer_type: &syn::Ident,
    layer_name: &str,
    metadata_type: &syn::Ident,
) -> proc_macro::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let expanded = quote::quote! {
        #[doc(hidden)]
        impl #impl_generics BaseLayer for #layer_type #ty_generics #where_clause {
            #[inline]
            fn layer_name(&self) -> &'static str {
                #layer_name
            }

            #[inline]
            fn layer_metadata(&self) -> &dyn LayerMetadata {
                #metadata_type::instance()
            }
        }

        #[doc(hidden)]
        impl #impl_generics BaseLayerMetadata for #layer_type #ty_generics #where_clause {
            #[inline]
            fn metadata() -> &'static dyn LayerMetadata {
                #metadata_type::instance()
            }
        }

        #[doc(hidden)]
        impl #impl_generics LayerName for #layer_type #ty_generics #where_clause {
            #[inline]
            fn name() -> &'static str {
                #layer_name
            }
        }

        impl #impl_generics ToBoxedLayer for #layer_type #ty_generics #where_clause {
            #[inline]
            fn to_boxed_layer(&self) -> Box<dyn LayerObject> {
                Box::new(self.to_layer())
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

#[proc_macro]
pub fn layer_metadata(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let struct_name: syn::Ident =
        syn::parse(input).expect("Invalid struct name passed in to layer_metadata!() macro");
    let metadata_const = quote::format_ident!(
        "{}_METADATA_RSCAP_INTERNAL",
        struct_name.to_string().to_uppercase()
    );

    //#[cfg(not(feature = "custom_layer_selection"))]
    let expanded = quote::quote! {
        pub struct #struct_name {
            _zst: (),
        }

        const #metadata_const: #struct_name = #struct_name { _zst: () };

        impl LayerMetadata for #struct_name { }

        impl ConstSingleton for #struct_name {
            #[inline]
            fn instance() -> &'static Self {
                & #metadata_const
            }
        }

        #[cfg(feature = "custom_layer_selection")]
        impl BaseLayerSelection for #struct_name { }
    };

    proc_macro::TokenStream::from(expanded)
}
