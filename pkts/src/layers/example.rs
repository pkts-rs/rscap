// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>


use pkts_macros::{Layer, LayerRef, StatelessLayer};

use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::error::*;


#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(ExampleMetadata)]
#[ref_type(ExampleRef)]
pub struct Example {

}

impl Example {

}

impl CanSetPayload for Example {
    fn can_set_payload_default(&self, payload: &dyn LayerObject) -> bool {
        todo!()
    }
}

impl FromBytesCurrent for Example {
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        todo!()
    }

    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerLength for Example {
    fn len(&self) -> usize {
        todo!()
    }
}

impl LayerObject for Example {
    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        todo!()
    }

    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        todo!()
    }

    fn has_payload(&self) -> bool {
        todo!()
    }

    fn remove_payload(&mut self) -> Box<dyn LayerObject> {
        todo!()
    }

    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        todo!()
    }
}

impl ToBytes for Example {
    fn to_bytes_chksummed(&self, bytes: &mut Vec<u8>, prev: Option<(LayerId, usize)>) {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Example)]
#[metadata_type(ExampleMetadata)]
pub struct ExampleRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> ExampleRef<'a> {

}

impl<'a> FromBytesRef<'a> for ExampleRef<'a> {
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        todo!()
    }
}

impl<'a> LayerOffset for ExampleRef<'a> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        todo!()
    }
}

impl<'a> Validate for ExampleRef<'a> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

/*

// To mutate existing packets, we have two options:
//
// 1. `LayerMut` - allows easy in-place modifications, but only for fields that are fixed-size.
//
// 2. `LayerBuilder` - a typed builder that allows passing in a 


// `LayerBuilder<'a, 'b, State>`

// new(layer: LayerMut<'a>) -> Self
//


trait State<'b>: private::Sealed {
    fn new() -> Self;
}

mod private {
    pub trait Sealed { }
}

struct Ipv4Builder<'b, S: State<'b>> {
//    layer: Ipv4Mut<'a>,
    state: S,
    _marker: PhantomData<&'b ()>,
}

impl<'a, 'b, S: State<'b>> Ipv4Builder<'b, S> {
    pub fn new(layer: Ipv4Mut<'a>) -> Self {
        Self {
//            layer,
            state: S::new(),
            _marker: PhantomData::default(),
        }
    }

    // This gets implemented for more specific impls
    // pub fn build() -> Ipv4Mut<'a>;
}

struct HeaderState {
    // It's useless to save fields that don't change size--we can just modify our bytes!
}

impl private::Sealed for HeaderState { }

impl<'b> State<'b> for HeaderState {
    fn new() -> Self {
        Self { }
    }

/*
    fn build<'a>(self, ipv4: Ipv4Mut<'a>) -> Ipv4Mut<'a> {
        ipv4
    }
*/
}

impl<'a, 'b> Ipv4Builder<'b, HeaderState> {
    fn options(self) -> Ipv4Builder<'b, HeaderOptionsState<'b, 0>> {
        Ipv4Builder {
//            layer: self.layer,
            state: HeaderOptionsState::new(),
            _marker: PhantomData::default(),
        }
    }
}

struct HeaderOptionsState<'b, const IP_OPTS: usize> {
    opts: [(u8, &'b [u8]); IP_OPTS],
}

impl<'b, const IP_OPTS: usize> private::Sealed for HeaderOptionsState<'b, IP_OPTS> { }

pub fn empty_slice() -> &'static [u8] {
    &[]
}

impl<'b, const IP_OPTS: usize> State<'b> for HeaderOptionsState<'b, IP_OPTS> {
    fn new() -> Self {
        Self {
            opts: core::array::from_fn(|_| (0u8, empty_slice())),
        }
    }
/*
    fn build<'a>(self, ipv4: Ipv4Mut<'a>) -> Ipv4Mut<'a> {
        todo!()
    }
*/
}

impl<'b, const IP_OPTS: usize> Ipv4Builder<'b, HeaderOptionsState<'b, IP_OPTS>> {
    pub fn build<'a>(self, layer: Ipv4Mut<'a>) -> Ipv4Mut<'a> {
        // If we needed to build previous states, we could do so here
        // Such as if we want to add Ipv4 variable-length fields before we build Tcp variable-length fields
        self.state.build(layer)
    }
}

impl<'b> Ipv4Builder<'b, HeaderOptionsState<'b, 0>> {
    pub fn with_options<const NUM_OPTS: usize>(self, opts: [(u8, &'b [u8]); NUM_OPTS]) -> HeaderOptionsState<'b, NUM_OPTS> {
        HeaderOptionsState {
            opts,
        }
    }
}

struct TcpHeaderState {
    // It's useless to save fields that don't change size--we can just modify our bytes!
}

impl private::Sealed for TcpHeaderState { }

impl<'b> State<'b> for TcpHeaderState {
    fn new() -> Self {
        Self { }
    }

/*
    fn build<'a>(self, ipv4: TcpMut<'a>) -> TcpMut<'a> {
        ipv4
    }
*/
}



struct TcpBuilder<'b, S: State<'b>> {
    
//    layer: Ipv4Mut<'a>,
    state: S,
    _marker: PhantomData<&'b ()>,
}

impl<'a, 'b> TcpBuilder<'b, HeaderState> {
    fn options(self) -> TcpBuilder<'b, HeaderOptionsState<'b, 0>> {
        TcpBuilder {
//            layer: self.layer,
            state: HeaderOptionsState::new(),
            _marker: PhantomData::default(),
        }
    }
}

// There's no way to stack these kinds of builders.
// This is because a State can't hold another state--the first state would need to accept another state as a generic, which gets messy
// It's also because generics grow and propogate in a cumbersome way.

// Solutions?
// - Restrict what kinds of fields can be modified easily in a stacked manner??
// - Restrict to only one layer? (not very useful...)
// - Move this functionality to LayerMut (less efficient)
*/