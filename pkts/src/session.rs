// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Stateful protocol handling/tracking via [`Session`]s.
//!
//! While stateless protocol formats are not uncommon (see `Dns` or `Http`), many protocols
//! implemented by `rscap` are stateful. These protocols require some form of state machine to be
//! maintained by an endpoint in order to guage the correctness of a received packet.
//!
//! Some of these protocols are only **semantically** stateful, meaning that the format of the
//! packet stays the same regardless of what state the protocol is in. A good example of this is
//! [`Tcp`]--a TCP packet always maintains the same strcuture of fields and payload, but different
//! flags (SYN, ACK or RST) may be required depending on what state a TCP connection is in.
//!
//! Other protocols may be **syntactically** stateful in addition to being semantically stateful.
//! This means that the protocol has defined more than one packet format, and the only way to choose
//! the right format when converting raw bytes is to have some knowledge of the connection state. A
//! good example of this is [`MysqlClient`] and `MysqlServer`, which have various different packet
//! formats for startup, authentication and data delivery.
//!
//! Protocols that are **syntactically** stateless can be validated/parsed from bytes withou
//! requiring saved state; these are designated by the [`StatelessLayer`] trait. Stateless packets
//! also generally implement the [`Validate`] trait, along with [`FromBytes`]/[`FromBytesCurrent`]
//! and [`FromBytesRef`]. Syntactically stateful protocols cannot validate or be parsed from bytes
//! using these traits; [`Session`] types are intended to resolve this gap in functionality.
//!
//! In order to accurately capture packets that are syntactically stateful, rscap employs `Session`
//! types that keep track of a protocol's current state and return the appropriate message structure
//! for that state. Transitions between states are represented by methods that can be called on a
//! `Session`, such that only valid transitions are offered in a given state.
//!
//! TODO: example(s) here
//!
//! [`Tcp`]: struct@crate::layers::tcp::Tcp
//! [`MysqlClient`]: struct@crate::layers::mysql::MysqlClient
//! [`StatelessLayer`]: crate::layers::dev_traits::StatelessLayer
//! [`Validate`]: crate::layers::traits::Validate
//! [`FromBytes`]: crate::layers::traits::FromBytes
//! [`FromBytesCurrent`]: crate::layers::dev_traits::FromBytesCurrent
//! [`FromBytesRef`]: crate::layers::traits::FromBytesRef

use crate::error::ValidationError;
use crate::layers::traits::LayerRef;

// A session takes in raw bytes and outputs the type associated with the given session

pub trait Session {
    type Out<'a>: LayerRef<'a>;

    /// Creates a packet from the given bytes, checking that they conform to
    /// a valid packet structure for the current session state.
    fn convert(bytes: &[u8]) -> Result<Self::Out<'_>, ValidationError>;

    /// Creates a packet from the given bytes without checking the syntactical
    /// validity of those bytes.
    fn convert_unchecked(bytes: &[u8]) -> Self::Out<'_>;

    /// Checks to see whether the given bytes form a syntactically valid packet
    /// within the context of the current sesson's state.
    fn validate(&self, bytes: &[u8]) -> Result<(), ValidationError>;
}

pub struct MysqlClientSession {
    // The `state` field of a session intentionally implements `Copy`.
    // This is so that we can copy out the state of a given session and
    // use methods specific to that state to update the state.
    state: MysqlClientState,
}

#[derive(Clone, Copy)]
pub enum MysqlClientState {
    Startup(MysqlStartupState),
    Error(MysqlErrorState),
}

#[derive(Clone, Copy)]
pub struct MysqlStartupState {}

impl MysqlStartupState {
    pub fn error(session: &mut MysqlClientSession) {
        session.state = MysqlClientState::Error(MysqlErrorState {});
    }
}

#[derive(Clone, Copy)]
pub struct MysqlErrorState {}

/*
pub struct MysqlClientSession<S: MysqlClientState> {
    _marker: core::marker::PhantomData<S>,
}

pub trait MysqlClientState: private::Sealed { }

pub struct MysqlStartupState { }

impl private::Sealed for MysqlStartupState { }

impl MysqlClientState for MysqlStartupState { }

impl MysqlClientSession<MysqlStartupState> {
    //pub fn transition(self, input: &Self::Out<'_>) ->
}

impl Session for MysqlClientSession<MysqlStartupState> {
    type Out<'a>;

    fn convert<'b>(bytes: &'b [u8]) -> Result<Self::Out<'b>, ValidationError> {
        todo!()
    }

    fn convert_unchecked<'b>(bytes: &'b [u8]) -> Self::Out<'b> {
        todo!()
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}
*/

/*
trait DualSession {
    type FrontendOut<'a>: LayerRef<'a>;
    type BackendOut<'a>: LayerRef<'a>;

    fn frontend_validate(bytes: &[u8]) -> Result<(), ValidationError>;

    fn frontend_convert<'b>(bytes: &'b [u8]) -> Result<Self::FrontendOut<'b>, ValidationError>;

    fn frontend_convert_unchecked<'b>(bytes: &'b [u8]) -> Self::FrontendOut<'b>;

    fn backend_validate(bytes: &[u8]) -> Result<(), ValidationError>;

    fn backend_convert<'b>(bytes: &'b [u8]) -> Result<Self::BackendOut<'b>, ValidationError>;

    fn backend_convert_unchecked<'b>(bytes: &'b [u8]) -> Self::BackendOut<'b>;
}

trait MultiSession {
    type Out: LayerObject;

    fn new(session_cnt: usize) -> Self;

    fn put(&mut self, pkt: &[u8], idx: usize) -> Result<(), ValidationError>;

    fn get(&mut self, idx: usize) -> Option<Self::Out>;
}
*/
