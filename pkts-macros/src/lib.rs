// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>

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

    if ast
        .attrs
        .iter()
        .find(|&a| a.path.is_ident("owned_type"))
        .is_none()
    {
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

                #[inline]
                fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
                    #ref_type::validate_payload_default(curr_layer)
                }
            }

            impl From<&#ref_type<'_>> for #layer_type {
                fn from(r: &#ref_type<'_>) -> Self {
                    let mut res = Self::from_bytes_current_layer_unchecked(r.into());
                    match r.layer_metadata().as_any().downcast_ref::<&dyn CustomLayerSelection>() {
                        Some(&layer_selection) => match layer_selection.payload_to_boxed(r.into()) {
                            Some(payload) => { res.set_payload_unchecked(payload); },
                            None => (),
                        }
                        None => res.payload_from_bytes_unchecked_default(r.into()),
                    }
                    res
                }
            }
        }));
    } else if ast
        .attrs
        .iter()
        .find(|&a| a.path.is_ident("ref_type"))
        .is_none()
    {
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

                #[inline]
                fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
                    #ref_type::validate_payload_default(curr_layer)
                }
            }
        }));
    }

    output
}

#[proc_macro_derive(Layer, attributes(ref_type, metadata_type/*, payload_field*/))]
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

    /*
    let payload_field = match ast.data {
        syn::Data::Struct(data_struct) => match data_struct.fields {
            syn::Fields::Named(named) => named.named.iter().find(|field| field.attrs.iter().find(|attr| attr.path.is_ident("payload_field")).is_some())
            .expect("payload_field inner attribute required to derive `Layer`").ident.as_ref().unwrap().clone(),
            _ => panic!("payload_field associated field must be named"),
        },
        _ => panic!("Only structs are currently supported for `Layer` derive")
    };
    */

    // extern crate self as rscap;
    // TODO: use the above within the quote! to make derives stable without including layer names
    output.extend(derive_base_layer_impl(
        &ast.generics,
        &layer_type,
        &layer_type.to_string().as_str(),
        &metadata_type,
    ));
    output.extend(proc_macro::TokenStream::from(quote::quote! {
        impl<RscapInternalT: BaseLayer + IntoLayer> core::ops::Div<RscapInternalT> for #layer_type {
            type Output = #layer_type;

            #[inline]
            fn div(mut self, rhs: RscapInternalT) -> Self::Output {
                self.appended_with(rhs).unwrap() // TODO: change to expect()
            }
        }

        impl From<#ref_type<'_>> for #layer_type {
            fn from(value: #ref_type<'_>) -> Self {
                Self::from(&value)
            }
        }

        impl IntoLayer for #layer_type {
            type Output = #layer_type;
        }

        impl BaseLayerAppend for #layer_type { }

        impl BaseLayerAppendBoxed for #layer_type { }

        /*
        impl LayerObject for #layer_type {
            #[inline]
            fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
                self.#payload_field.as_ref().map(|p| p.as_ref())
            }
        
            #[inline]
            fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
                self.#payload_field.as_mut().map(|p| p.as_mut())
            }
        
            #[inline]
            fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
                self.#payload_field = Some(payload);
            }

            #[inline]
            fn has_payload(&self) -> bool {
                self.#payload_field.is_some()
            }

            #[inline]
            fn remove_payload(&mut self) -> Box<dyn LayerObject> {
                let mut ret = None;
                core::mem::swap(&mut ret, &mut self.#payload_field);
                self.#payload_field = None;
                ret.expect(format!("remove_payload() called on {} layer when layer had no payload", self.layer_name()).as_str())
            }
        }
        */

        impl LayerIndex for #layer_type { }

        pub struct #layer_type_index {
            _zst: (), // Allows the StructIdentifier to be public but not recreatable
        }

        impl crate::private::Sealed for #layer_type_index { }

        impl LayerIndexSingleton for #layer_type_index {
            type LayerType = #layer_type;
        }

        #[allow(non_upper_case_globals)]
        pub const #layer_type: #layer_type_index = #layer_type_index { _zst: () };

        impl<RscapInternalT: LayerIndexSingleton> core::ops::Index<RscapInternalT> for #layer_type {
            type Output = RscapInternalT::LayerType;

            #[inline]
            fn index(&self, _: RscapInternalT) -> &Self::Output {
                self.get_layer().unwrap()
            }
        }

        impl<RscapInternalT: LayerIndexSingleton> core::ops::IndexMut<RscapInternalT> for #layer_type {
            #[inline]
            fn index_mut(&mut self, _: RscapInternalT) -> &mut Self::Output {
                self.get_layer_mut().unwrap()
            }
        }

        impl LayerAppend for #layer_type { }

        impl<RscapInternalT: BaseLayer + IntoLayer> core::ops::DivAssign<RscapInternalT> for #layer_type {
            #[inline]
            fn div_assign(&mut self, rhs: RscapInternalT) {
                self.append_layer(rhs).unwrap()
            }
        }

        impl Layer for #layer_type { }
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
                        .find(|attr| attr.path.is_ident("data_field"))
                        .is_some()
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
        &owned_type.to_string().as_str(),
        &metadata_type,
    ));
    output.extend(proc_macro::TokenStream::from(quote::quote! {
        impl IntoLayer for #layer_type<'_> {
            type Output = #owned_type;
        }

        impl<'a> core::convert::From<&#layer_type<'a>> for &'a [u8] {
            #[inline]
            fn from(value: &#layer_type<'a>) -> Self {
                value.#data_field
            }
        }

        impl<'a> core::convert::From<#layer_type<'a>> for &'a [u8] {
            #[inline]
            fn from(value: #layer_type<'a>) -> Self {
                value.#data_field
            }
        }

        impl<'a> core::convert::From<#layer_type<'a>> for Vec<u8> {
            #[inline]
             fn from(value: #layer_type<'a>) -> Self {
                Vec::from(value.#data_field)
            }
        }

        impl LayerLength for #layer_type<'_> {
            #[inline]
            fn len(&self) -> usize {
                self.#data_field.len()
            }
        }

        impl BaseLayerAppend for #layer_type<'_> { }

        impl BaseLayerAppendBoxed for #layer_type<'_> { }

        impl<'a> LayerRefIndex<'a> for #layer_type<'a> {
            fn get_layer<T: LayerRef<'a> + FromBytesRef<'a>>(&'a self) -> Option<T> {
                if self.is_layer::<T>() {
                    return Some(T::from_bytes_unchecked(self.#data_field))
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    return custom_selection
                        .payload_byte_index(self.#data_field, &T::layer_id_static())
                        .map(|offset| T::from_bytes_unchecked(self.#data_field));
                }

                match Self::payload_byte_index_default(self.#data_field, T::layer_id_static()) {
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

                if self.is_layer::<T>() {
                    n -= 1
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    if let Some(mut curr_offset) = custom_selection.payload_byte_index(self.#data_field, &T::layer_id_static()) {
                        n -= 1;
                        if n == 0 {
                            return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                        }

                        while let Some(new_offset) =
                            if let Some(custom_selection) = T::metadata().as_any().downcast_ref::<&dyn CustomLayerSelection>() {
                                custom_selection.payload_byte_index(&self.#data_field[curr_offset..], &T::layer_id_static())
                            } else {
                                T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id_static())
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

                if let Some(mut curr_offset) = Self::payload_byte_index_default(self.#data_field, T::layer_id_static()) {
                    n -= 1;
                    if n == 0 {
                        return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                    }

                    while let Some(new_offset) = T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id_static()) {
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

        impl<RscapInternalT: BaseLayer + IntoLayer> core::ops::Div<RscapInternalT> for #layer_type<'_> {
            type Output = #owned_type;

            #[inline]
            fn div(mut self, rhs: RscapInternalT) -> Self::Output {
                self.appended_with(rhs).unwrap()
            }
        }

        impl<'a> AnyLayerRef<'a> for #layer_type<'a> {
            #[inline]
            fn layer_id_static() -> core::any::TypeId {
                core::any::TypeId::of::<#owned_type>()
            }
        }

        impl ToOwnedLayer for #layer_type<'_> {
            type Owned = #owned_type;

            #[inline]
            fn to_owned(&self) -> Self::Owned {
                Self::Owned::from(self)
            }
        }

        impl<'a> ToSlice for #layer_type<'a> {
            fn to_slice(&self) -> &[u8] {
                self.into()
            }
        }

        impl<'a> LayerRef<'a> for #layer_type<'a> { }
    }));

    output
}

#[proc_macro_derive(
    LayerMut,
    attributes(owned_type, ref_type, metadata_type, data_field, data_length_field)
)]
pub fn derive_layer_mut(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as syn::DeriveInput);
    let mut output = proc_macro::TokenStream::new();
    let layer_type = ast.ident;
    let owned_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.segments.len() == 1 && a.path.segments[0].ident == "owned_type")
        .expect("owned_type attribute required for deriving `LayerMut`")
        .parse_args()
        .expect("owned_type attribute must contain a struct name that implements `LayerMut`");
    let ref_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.segments.len() == 1 && a.path.segments[0].ident == "ref_type")
        .expect("ref_type attribute required for deriving LayerMut")
        .parse_args()
        .expect("ref_type attribute must contain a struct name");
    let metadata_type: syn::Ident = ast
        .attrs
        .iter()
        .find(|&a| a.path.segments.len() == 1 && a.path.segments[0].ident == "metadata_type")
        .expect("metadata_type attribute required for deriving LayerMut")
        .parse_args()
        .expect("metadata_type attribute must contain a struct name");

    let data_field = match &ast.data {
        syn::Data::Struct(data_struct) => match &data_struct.fields {
            syn::Fields::Named(named) => named
                .named
                .iter()
                .find(|field| {
                    field
                        .attrs
                        .iter()
                        .find(|attr| attr.path.is_ident("data_field"))
                        .is_some()
                })
                .expect("data_field inner attribute required to derive `LayerMut`")
                .ident
                .as_ref()
                .unwrap()
                .clone(),
            _ => panic!("data_field associated field must be named"),
        },
        _ => panic!("Only structs are currently supported for `LayerMut` derive"),
    };

    let data_length_field = match &ast.data {
        syn::Data::Struct(data_struct) => match &data_struct.fields {
            syn::Fields::Named(named) => named
                .named
                .iter()
                .find(|field| {
                    field
                        .attrs
                        .iter()
                        .find(|attr| attr.path.is_ident("data_length_field"))
                        .is_some()
                })
                .expect("data_length_field inner attribute required to derive `LayerMut`")
                .ident
                .as_ref()
                .unwrap()
                .clone(),
            _ => panic!("data_length_field associated field must be named"),
        },
        _ => panic!("Only structs are currently supported for `LayerMut` derive"),
    };

    output.extend(derive_base_layer_impl(
        &ast.generics,
        &layer_type,
        &owned_type.to_string().as_str(),
        &metadata_type,
    ));
    output.extend(proc_macro::TokenStream::from(quote::quote! {

        impl core::convert::From<&#layer_type<'_>> for #owned_type {
            fn from(value: &#layer_type<'_>) -> Self {
                Self::from(#ref_type::from(value))
            }
        }

        impl core::convert::From<#layer_type<'_>> for #owned_type {
            fn from(value: #layer_type<'_>) -> Self {
                Self::from(&value)
            }
        }

        impl<'a> core::convert::From<&'a #layer_type<'a>> for &'a [u8] {
            fn from(value: &'a #layer_type<'a>) -> Self {
                &value.#data_field[..value.#data_length_field]
            }
        }

        impl<'a> core::convert::From<#layer_type<'a>> for &'a [u8] {
            fn from(value: #layer_type<'a>) -> Self {
                &value.#data_field[..value.#data_length_field]
            }
        }

        impl<'a> core::convert::From<#layer_type<'a>> for Vec<u8> {
            #[inline]
             fn from(value: #layer_type<'a>) -> Self {
                Vec::from(&value.#data_field[..value.#data_length_field])
            }
        }

        impl LayerLength for #layer_type<'_> {
            #[inline]
            fn len(&self) -> usize {
                let r = #ref_type::from_bytes_unchecked(&self.#data_field[..self.#data_length_field]);
                r.len()
            }
        }

        impl BaseLayerAppend for #layer_type<'_> { }

        impl BaseLayerAppendBoxed for #layer_type<'_> { }

        /*
        impl BaseLayerAppendBoxed for #layer_type<'_> {
            fn can_append_with_boxed(&self, other: &Box<dyn LayerObject>) -> bool {
                let r = #ref_type::from_bytes_unchecked(&self.#data_field[..self.#data_length_field]);
                r.can_append_with_boxed(other)
            }
        }
        */

        impl IntoLayer for #layer_type<'_> {
            type Output = #owned_type;
        }

        impl ToOwnedLayer for #layer_type<'_> {
            type Owned = #owned_type;

            #[inline]
            fn to_owned(&self) -> Self::Owned {
                Self::Owned::from(self)
            }
        }

        impl<'a> LayerRefIndex<'a> for #layer_type<'a> {
            fn get_layer<T: LayerRef<'a> + FromBytesRef<'a>>(&'a self) -> Option<T> {
                if <Self as AnyLayerMut>::AssociatedRef::layer_id_static() == T::layer_id_static() {
                    return Some(T::from_bytes_unchecked(self.#data_field))
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    return custom_selection
                        .payload_byte_index(self.#data_field, &T::layer_id_static())
                        .map(|offset| T::from_bytes_unchecked(self.#data_field));
                }

                match Self::payload_byte_index_default(self.#data_field, T::layer_id_static()) {
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

                if <Self as AnyLayerMut>::AssociatedRef::layer_id_static() == T::layer_id_static() {
                    n -= 1
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    if let Some(mut curr_offset) = custom_selection.payload_byte_index(self.#data_field, &T::layer_id_static()) {
                        n -= 1;
                        if n == 0 {
                            return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                        }

                        while let Some(new_offset) =
                            if let Some(custom_selection) = T::metadata().as_any().downcast_ref::<&dyn CustomLayerSelection>() {
                                custom_selection.payload_byte_index(&self.#data_field[curr_offset..], &T::layer_id_static())
                            } else {
                                T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id_static())
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

                if let Some(mut curr_offset) = Self::payload_byte_index_default(self.#data_field, T::layer_id_static()) {
                    n -= 1;
                    if n == 0 {
                        return Some(T::from_bytes_unchecked(&self.#data_field[curr_offset..]))
                    }

                    while let Some(new_offset) = T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id_static()) {
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

        impl<'a> LayerMutIndex<'a> for #layer_type<'a> {
            fn get_layer_mut<T: LayerMut<'a> + FromBytesMut<'a>>(&'a mut self) -> Option<T> {
                if self.is_layer::<T>() {
                    return Some(T::from_bytes_unchecked(self.#data_field));
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    return custom_selection
                        .payload_byte_index(self.#data_field, &T::layer_id_static())
                        .map(|offset| T::from_bytes_unchecked(self.#data_field));
                }

                match Self::payload_byte_index_default(self.#data_field, T::layer_id_static()) {
                    Some(offset) => Some(T::from_bytes_unchecked(&mut self.#data_field[offset..])),
                    None => None
                }
            }

            fn get_nth_layer_mut<T: LayerMut<'a> + FromBytesMut<'a> + BaseLayerMetadata>(&'a mut self, mut n: usize) -> Option<T> {
                match n {
                    0 => return None,
                    1 => return self.get_layer_mut(),
                    _ => (),
                }

                if self.is_layer::<T>() {
                    n -= 1;
                }

                #[cfg(feature = "custom_layer_selection")]
                if let Some(&custom_selection) = self
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn CustomLayerSelection>()
                {
                    if let Some(mut curr_offset) = custom_selection.payload_byte_index(self.#data_field, &T::layer_id_static()) {
                        n -= 1;
                        if n == 0 {
                            return Some(T::from_bytes_unchecked(&mut self.#data_field[curr_offset..]))
                        }

                        while let Some(new_offset) =
                            if let Some(custom_selection) = T::metadata().as_any().downcast_ref::<&dyn CustomLayerSelection>() {
                                custom_selection.payload_byte_index(&self.#data_field[curr_offset..], &T::layer_id_static())
                            } else {
                                T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id_static())
                            }
                        {
                            curr_offset = new_offset;
                            n -= 1;
                            if n == 0 {
                                return Some(T::from_bytes_unchecked(&mut self.#data_field[curr_offset..]))
                            }
                        }
                    }
                    return None
                }

                if let Some(mut curr_offset) = Self::payload_byte_index_default(self.#data_field, T::layer_id_static()) {
                    n -= 1;
                    if n == 0 {
                        return Some(T::from_bytes_unchecked(&mut self.#data_field[curr_offset..]))
                    }

                    while let Some(new_offset) = T::payload_byte_index_default(&self.#data_field[curr_offset..], T::layer_id_static()) {
                        curr_offset = new_offset;
                        n -= 1;
                        if n == 0 {
                            return Some(T::from_bytes_unchecked(&mut self.#data_field[curr_offset..]))
                        }
                    }
                }

                None
            }
        }

        impl LayerOffset for #layer_type<'_> {
            fn payload_byte_index_default(bytes: &[u8], layer_type: core::any::TypeId) -> Option<usize> {
                #ref_type::payload_byte_index_default(bytes, layer_type)
            }
        }

        impl<'a> LayerMut<'a> for #layer_type<'a> { }

        impl<'a> AnyLayerMut<'a> for #layer_type<'a> {
            type AssociatedRef = #ref_type <'a>;
            #[inline]
            fn layer_id_static() -> core::any::TypeId {
                core::any::TypeId::of::<#owned_type>()
            }
        }

        impl<'a> ToSlice for #layer_type<'a> {
            fn to_slice(&self) -> &[u8] {
                self.into()
            }
        }
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

        impl #impl_generics BaseLayerMetadata for #layer_type #ty_generics #where_clause {
            #[inline]
            fn metadata() -> &'static dyn LayerMetadata {
                #metadata_type::instance()
            }
        }

        impl #impl_generics LayerName for #layer_type #ty_generics #where_clause {
            #[inline]
            fn name() -> &'static str {
                #layer_name
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

    /*
    #[cfg(feature = "custom_layer_selection")]
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

        impl BaseLayerSelection for #struct_name { }
    };
    */

    proc_macro::TokenStream::from(expanded)
}
