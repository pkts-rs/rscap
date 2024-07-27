// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Protocol layers used for communication between PostgreSQL clients and databases.
//!

use core::ffi::CStr;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use core::iter::Iterator;
use core::{cmp, str};
#[cfg(feature = "std")]
use std::ffi::CString;

use pkts_macros::{Layer, LayerRef, StatelessLayer};

use crate::layers::dev_traits::*;
use crate::layers::traits::*;
use crate::{error::*, utils};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::collections::BTreeMap;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::ffi::CString;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

const CLIENT_MSG_BIND: u8 = b'B';
const CLIENT_MSG_STARTUP: u8 = 0x00;
const CLIENT_MSG_CLOSE: u8 = b'C';
const CLIENT_MSG_COPY_DATA: u8 = b'd';
const CLIENT_MSG_COPY_DONE: u8 = b'c';
const CLIENT_MSG_COPY_FAIL: u8 = b'f';
const CLIENT_MSG_DESCRIBE: u8 = b'D';
const CLIENT_MSG_EXECUTE: u8 = b'E';
const CLIENT_MSG_FLUSH: u8 = b'H';
const CLIENT_MSG_FN_CALL: u8 = b'F';
const CLIENT_MSG_AUTH_RESP: u8 = b'p';
const CLIENT_MSG_PARSE: u8 = b'P';
const CLIENT_MSG_QUERY: u8 = b'Q';
const CLIENT_MSG_SYNC: u8 = b'S';
const CLIENT_MSG_TERMINATE: u8 = b'X';

const CLIENT_STARTUP_V3_0: i32 = 0x0003_0000;
const CLIENT_STARTUP_CANCEL_REQ: i32 = 0x1234_5678;
const CLIENT_STARTUP_SSL_REQ: i32 = 0x1234_5679;
const CLIENT_STARTUP_GSS_ENC_REQ: i32 = 0x1234_5680;

/*
const SERVER_MSG_AUTH: u8 = b'R';
const SERVER_MSG_BACKEND_KEY_DATA: u8 = b'K';
const SERVER_MSG_BIND_COMPLETE: u8 = b'2';
const SERVER_MSG_CLOSE_COMPLETE: u8 = b'3';
const SERVER_MSG_COMMAND_COMPLETE: u8 = b'C';
const SERVER_MSG_COPY_DATA: u8 = b'd';
const SERVER_MSG_COPY_DONE: u8 = b'c';
const SERVER_MSG_COPY_IN_RESP: u8 = b'G';
const SERVER_MSG_COPY_OUT_RESP: u8 = b'H';
const SERVER_MSG_COPY_BOTH_RESP: u8 = b'W';
const SERVER_MSG_DATA_ROW: u8 = b'D';
const SERVER_MSG_EMPTY_QUERY_RESP: u8 = b'I';
const SERVER_MSG_ERROR_RESP: u8 = b'E';
const SERVER_MSG_FN_CALL_RESP: u8 = b'V';
const SERVER_MSG_NEGOTIATE_PROTO_VERSION: u8 = b'v';
const SERVER_MSG_NO_DATA: u8 = b'n';
const SERVER_MSG_NOTICE_RESP: u8 = b'N';
const SERVER_MSG_NOTIFICATION_RESP: u8 = b'A';
const SERVER_MSG_PARAM_DESCRIPTION: u8 = b't';
const SERVER_MSG_PARAM_STATUS: u8 = b'S';
const SERVER_MSG_PARSE_COMPLETE: u8 = b'1';
const SERVER_MSG_PORTAL_SUSPENDED: u8 = b's';
const SERVER_MSG_READY_FOR_QUERY: u8 = b'Z';
const SERVER_MSG_ROW_DESCRIPTION: u8 = b'T';

const SERVER_AUTH_OK: i32 = 0;
const SERVER_AUTH_KERBEROS_V5: i32 = 2;
const SERVER_AUTH_CLEARTEXT_PWD: i32 = 3;
const SERVER_AUTH_MD5_PWD: i32 = 5;
const SERVER_AUTH_SCM_CRED: i32 = 6;
const SERVER_AUTH_GSS: i32 = 7;
const SERVER_AUTH_GSS_CONTINUE: i32 = 8;
const SERVER_AUTH_SSPI: i32 = 9;
const SERVER_AUTH_SASL: i32 = 10;
const SERVER_AUTH_SASL_CONTINUE: i32 = 11;
const SERVER_AUTH_SASL_FINAL: i32 = 12;
*/

// Psql Server messages can be statelessly parsed, i.e. we don't need to know the
// current state of the protocol to parse message structure.

// Psql Client messages can *almost* be statelessly parsed, with one exception.
// Every Psql Client message has the first byte uniquely identify what message will
// be in the packet, except for the startup packet--it just has the length field.
// HOWEVER, psql limits startup messages to 10,000 bytes:
// https://github.com/postgres/postgres/blob/master/src/include/libpq/pqcomm.h
// this means that the first byte of a startup message must always be 0x00, SO we
// can safely pretend that 0x00 is the identifying byte for a startup message.
// Thus, PsqlClient can be a StatelessLayer.

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(PsqlClientMetadata)]
#[ref_type(PsqlClientRef)]
pub struct PsqlClient {
    packet: ClientMessage,
}

impl PsqlClient {
    #[inline]
    pub fn message(&self) -> &ClientMessage {
        &self.packet
    }

    #[inline]
    pub fn message_mut(&mut self) -> &mut ClientMessage {
        &mut self.packet
    }
}

#[doc(hidden)]
impl FromBytesCurrent for PsqlClient {
    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, _bytes: &[u8]) {}

    fn from_bytes_current_layer_unchecked(_bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerLength for PsqlClient {
    #[inline]
    fn len(&self) -> usize {
        self.packet.len()
    }
}

impl LayerObject for PsqlClient {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        false
    }

    #[inline]
    fn add_payload_unchecked(&mut self, _payload: Box<dyn LayerObject>) {
        todo!() //self.payload = Some(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        todo!()
        /*
        match self.payload {
            Some(payload) => slice::from_ref(&payload),
            None => &[]
        }
        */
    }

    #[inline]
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        todo!()
        /*
        match &mut self.payload {
            Some(payload) => slice::from_mut(payload),
            None => &mut []
        }
        */
    }

    fn remove_payload_at(&mut self, _index: usize) -> Option<Box<dyn LayerObject>> {
        todo!()
        /*
        if index != 0 {
            return None
        }

        let mut ret = None;
        core::mem::swap(&mut ret, &mut self.payload);
        ret
        */
    }
}

impl ToBytes for PsqlClient {
    fn to_bytes_checksummed(
        &self,
        _bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub enum ClientMessage {
    /// Encapsulates any of SASL, GSSAPI, SSPI and password response messages
    AuthDataResponse(AuthDataResponse),
    /// Indicates a Bind command
    /// (destination portal, source prepared statement, parameter format codes, parameters, result-column format codes)
    Bind(Bind),
    /// Indicates that a request should be cancelled TODO: update documentation
    CancelRequest(CancelRequest),
    /// Requests that the given portal be closed
    ClosePortal(ClosePortal),
    /// Requests that the given prepared statement be closed
    ClosePrepared(ClosePortal),
    /// Carries data being copied using a COPY command
    CopyData(CopyData),
    /// Indicates a COPY command has finished sending data
    CopyDone,
    /// Indicates a COPY command has failed
    CopyFail(CopyFail),
    /// Requests that the given portal be described
    DescribePortal(DescribePortal),
    /// Requests that the given prepared statement be described
    DescribePrepared(DescribePrepared),
    /// Requests the given portal be executed
    /// (name of portal, maximum number of rows to return--0 means no limit)
    Execute(Execute),
    /// Requests a flush command be performed
    Flush,
    /// Requests a function be called
    /// (object ID of function, argument format codes--is_text, arguments, format code for function result)
    FunctionCall(FunctionCall),
    /// Requests GSSAPI Encryption
    GssEncRequest,
    /*
    /// Sends GSSAPI/SSAPI authentication data in the form of bytes
    GSSResponse(&'a [u8]),
    */
    /// Requests a command be parsed
    /// (prepared statement name, query string, parameter data types)
    Parse(Parse),
    /*
    /// Indicates a password is being sent, and contains the given password string
    PasswordMessage(&'a str),
    */
    /// Requests that he given simple SQL query be executed
    Query(Query),
    /*
    /// An initial SASL response, or else data for a GSSAPI, SSAPI or password response
    /// (selected SASL authentication mechanism, SASL mechanism specific "initial Response")
    SASLInitialResponse(&'a str, Option<&'a [u8]>),

    /// A SASL response, or else data for a GSSAPI, SSAPI or password response containing
    /// SASL mechanism specific message data
    SASLResponse(&'a [u8]),
    */
    /// Requests the connection be encrypted with SSL
    SslRequest,
    /// Requests a particular user be connected to the database
    StartupMessage(StartupMessage),
    /// Requests a Sync command be performed
    Sync,
    /// Identifies the message as a termination
    Terminate,
}

impl ClientMessage {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        match self {
            ClientMessage::AuthDataResponse(_) => CLIENT_MSG_AUTH_RESP,
            ClientMessage::Bind(_) => CLIENT_MSG_BIND,
            ClientMessage::CancelRequest(_) => CLIENT_MSG_STARTUP,
            ClientMessage::ClosePortal(_) => CLIENT_MSG_CLOSE,
            ClientMessage::ClosePrepared(_) => CLIENT_MSG_CLOSE,
            ClientMessage::CopyData(_) => CLIENT_MSG_COPY_DATA,
            ClientMessage::CopyDone => CLIENT_MSG_COPY_DONE,
            ClientMessage::CopyFail(_) => CLIENT_MSG_COPY_FAIL,
            ClientMessage::DescribePortal(_) => CLIENT_MSG_DESCRIBE,
            ClientMessage::DescribePrepared(_) => CLIENT_MSG_DESCRIBE,
            ClientMessage::Execute(_) => CLIENT_MSG_EXECUTE,
            ClientMessage::Flush => CLIENT_MSG_FLUSH,
            ClientMessage::FunctionCall(_) => CLIENT_MSG_FN_CALL,
            ClientMessage::GssEncRequest => CLIENT_MSG_STARTUP,
            ClientMessage::Parse(_) => CLIENT_MSG_PARSE,
            ClientMessage::Query(_) => CLIENT_MSG_QUERY,
            ClientMessage::SslRequest => CLIENT_MSG_STARTUP,
            ClientMessage::StartupMessage(_) => CLIENT_MSG_STARTUP,
            ClientMessage::Sync => CLIENT_MSG_SYNC,
            ClientMessage::Terminate => CLIENT_MSG_TERMINATE,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            ClientMessage::AuthDataResponse(m) => m.len(),
            ClientMessage::Bind(m) => m.len(),
            ClientMessage::CancelRequest(m) => m.len(),
            ClientMessage::ClosePortal(m) => m.len(),
            ClientMessage::ClosePrepared(m) => m.len(),
            ClientMessage::CopyData(m) => m.len(),
            ClientMessage::CopyDone => 5,
            ClientMessage::CopyFail(m) => m.len(),
            ClientMessage::DescribePortal(m) => m.len(),
            ClientMessage::DescribePrepared(m) => m.len(),
            ClientMessage::Execute(m) => m.len(),
            ClientMessage::Flush => 5,
            ClientMessage::FunctionCall(m) => m.len(),
            ClientMessage::GssEncRequest => 8,
            ClientMessage::Parse(m) => m.len(),
            ClientMessage::Query(m) => m.len(),
            ClientMessage::SslRequest => 8,
            ClientMessage::StartupMessage(m) => m.len(),
            ClientMessage::Sync => 5,
            ClientMessage::Terminate => 5,
        }
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        match self {
            ClientMessage::AuthDataResponse(m) => m.to_bytes_extended(bytes),
            ClientMessage::Bind(_) => todo!(),
            ClientMessage::CancelRequest(_) => todo!(),
            ClientMessage::ClosePortal(_) => todo!(),
            ClientMessage::ClosePrepared(_) => todo!(),
            ClientMessage::CopyData(_) => todo!(),
            ClientMessage::CopyDone => {
                bytes.push(CLIENT_MSG_COPY_DONE);
                bytes.extend(5i32.to_be_bytes());
            }
            ClientMessage::CopyFail(_) => todo!(),
            ClientMessage::DescribePortal(_) => todo!(),
            ClientMessage::DescribePrepared(_) => todo!(),
            ClientMessage::Execute(_) => todo!(),
            ClientMessage::Flush => {
                bytes.push(CLIENT_MSG_FLUSH);
                bytes.extend(5i32.to_be_bytes());
            }
            ClientMessage::FunctionCall(_) => todo!(),
            ClientMessage::GssEncRequest => {
                bytes.extend(8i32.to_be_bytes());
                bytes.extend(CLIENT_STARTUP_GSS_ENC_REQ.to_be_bytes());
            }
            ClientMessage::Parse(_) => todo!(),
            ClientMessage::Query(_) => todo!(),
            ClientMessage::SslRequest => {
                bytes.extend(8i32.to_be_bytes());
                bytes.extend(CLIENT_STARTUP_SSL_REQ.to_be_bytes());
            }
            ClientMessage::StartupMessage(_) => todo!(),
            ClientMessage::Sync => {
                bytes.push(CLIENT_MSG_SYNC);
                bytes.extend(5i32.to_be_bytes());
            }
            ClientMessage::Terminate => {
                bytes.push(CLIENT_MSG_TERMINATE);
                bytes.extend(5i32.to_be_bytes());
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthDataResponse {
    data: Vec<u8>,
}

impl AuthDataResponse {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_AUTH_RESP
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.data.len()
    }

    #[inline]
    pub fn auth_data(&self) -> &Vec<u8> {
        &self.data
    }

    #[inline]
    pub fn auth_data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((4 + self.data.len() as i32).to_be_bytes());
        bytes.extend(&self.data);
    }
}

#[derive(Clone, Debug)]
pub struct CancelRequest {
    proc_id: i32,
    key: i32,
}

impl CancelRequest {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_STARTUP
    }

    #[inline]
    pub fn len(&self) -> usize {
        17
    }

    #[inline]
    pub fn startup_code(&self) -> i32 {
        CLIENT_STARTUP_CANCEL_REQ
    }

    #[inline]
    pub fn process_id(&self) -> i32 {
        self.proc_id
    }

    #[inline]
    pub fn set_process_id(&mut self, proc_id: i32) {
        self.proc_id = proc_id;
    }

    #[inline]
    pub fn key(&self) -> i32 {
        self.key
    }

    #[inline]
    pub fn set_key(&mut self, key: i32) {
        self.key = key;
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend(16i32.to_be_bytes());
        bytes.extend(self.proc_id.to_be_bytes());
        bytes.extend(self.key.to_be_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct ClosePortal {
    portal_name: CString,
}

impl ClosePortal {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_CLOSE
    }

    #[inline]
    pub fn len(&self) -> usize {
        6 + self.portal_name.as_bytes().len()
    }

    #[inline]
    pub fn close_type(&self) -> u8 {
        b'P'
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        &self.portal_name
    }

    #[inline]
    pub fn set_name(&mut self, name: CString) {
        self.portal_name = name
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.push(self.close_type());
        bytes.extend(self.portal_name.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct ClosePrepared {
    stmt_name: CString,
}

impl ClosePrepared {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_CLOSE
    }

    #[inline]
    pub fn len(&self) -> usize {
        6 + self.stmt_name.as_bytes().len()
    }

    #[inline]
    pub fn close_type(&self) -> u8 {
        b'S'
    }

    #[inline]
    pub fn stmt_name(&self) -> &CStr {
        &self.stmt_name
    }

    #[inline]
    pub fn set_stmt_name(&mut self, name: CString) {
        self.stmt_name = name
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.push(self.close_type());
        bytes.extend(self.stmt_name.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct CopyData {
    data_stream: Vec<u8>,
}

impl CopyData {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_COPY_DATA
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.data_stream.len()
    }

    #[inline]
    pub fn data_stream(&self) -> &Vec<u8> {
        &self.data_stream
    }

    #[inline]
    pub fn data_stream_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data_stream
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(&self.data_stream);
    }
}

#[derive(Clone, Debug)]
pub struct CopyFail {
    err_msg: CString,
}

impl CopyFail {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_COPY_DATA
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.err_msg.as_bytes().len()
    }

    #[inline]
    pub fn err_message(&self) -> &CStr {
        &self.err_msg
    }

    #[inline]
    pub fn set_err_message(&mut self, err_msg: CString) {
        self.err_msg = err_msg;
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(self.err_msg.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct DescribePortal {
    portal_name: CString,
}

impl DescribePortal {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_DESCRIBE
    }

    #[inline]
    pub fn len(&self) -> usize {
        6 + self.portal_name.as_bytes().len()
    }

    #[inline]
    pub fn describe_type(&self) -> u8 {
        b'P'
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        &self.portal_name
    }

    #[inline]
    pub fn set_name(&mut self, name: CString) {
        self.portal_name = name
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.push(self.describe_type());
        bytes.extend(self.portal_name.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct DescribePrepared {
    stmt_name: CString,
}

impl DescribePrepared {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_DESCRIBE
    }

    #[inline]
    pub fn len(&self) -> usize {
        6 + self.stmt_name.as_bytes().len()
    }

    #[inline]
    pub fn describe_type(&self) -> u8 {
        b'S'
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        &self.stmt_name
    }

    #[inline]
    pub fn set_name(&mut self, name: CString) {
        self.stmt_name = name
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.push(self.describe_type());
        bytes.extend(self.stmt_name.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct Execute {
    portal_name: CString,   // empty string means unnamed portal
    max_rows: Option<i32>, // None corresponds to 0
}

impl Execute {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_EXECUTE
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.portal_name.as_bytes().len() + 4
    }

    #[inline]
    pub fn portal_name(&self) -> &CStr {
        &self.portal_name
    }

    #[inline]
    pub fn set_portal_name(&mut self, name: CString) {
        self.portal_name = name;
    }

    #[inline]
    pub fn max_rows(&self) -> Option<i32> {
        self.max_rows
    }

    #[inline]
    pub fn set_max_rows(&mut self, max: Option<i32>) {
        self.max_rows = max;
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(self.portal_name.as_bytes());
        bytes.extend(self.max_rows.unwrap_or(0).to_be_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct Parse {
    dst_stmt: CString,
    query: CString,
    type_ids: Vec<Option<i32>>,
}

impl Parse {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_PARSE
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.dst_stmt.as_bytes().len() + self.query.as_bytes().len() + 2 + 4 * self.type_ids.len()
    }

    #[inline]
    pub fn dst_stmt(&self) -> &CStr {
        &self.dst_stmt
    }

    #[inline]
    pub fn set_dst_stmt(&mut self, stmt: CString) {
        self.dst_stmt = stmt;
    }

    #[inline]
    pub fn parsed_query(&self) -> &CStr {
        &self.query
    }

    #[inline]
    pub fn set_parsed_query(&mut self, query: CString) {
        self.query = query;
    }

    #[inline]
    pub fn param_data_types(&self) -> &Vec<Option<i32>> {
        &self.type_ids
    }

    #[inline]
    pub fn param_data_types_mut(&mut self) -> &mut Vec<Option<i32>> {
        &mut self.type_ids
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(self.dst_stmt.as_bytes());
        bytes.extend(self.query.as_bytes());
        bytes.extend((self.type_ids.len() as u16).to_be_bytes());
        for id in &self.type_ids {
            bytes.extend(id.unwrap_or(0).to_be_bytes());
        }
    }
}

#[derive(Clone, Debug)]
pub struct Query {
    query: CString,
}

impl Query {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_QUERY
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.query.as_bytes().len()
    }

    #[inline]
    pub fn query(&self) -> &CStr {
        &self.query
    }

    #[inline]
    pub fn set_query(&mut self, query: CString) {
        self.query = query;
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(self.query.as_bytes());
    }
}

#[derive(Clone, Debug)]
pub struct StartupMessage {
    //    minor_version: u16,
    params: Vec<(CString, CString)>,
}

impl StartupMessage {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_STARTUP
    }

    #[inline]
    pub fn len(&self) -> usize {
        8 + self
            .params
            .iter()
            .map(|(k, v)| k.as_bytes().len() + v.as_bytes().len())
            .sum::<usize>()
            + 1 // constant '2' for null bytes; constant '1' for ending null byte
    }

    #[inline]
    pub fn startup_code(&self) -> i32 {
        CLIENT_STARTUP_V3_0 // We only support postgres version 3.0 for now
    }

    #[inline]
    pub fn major_proto_version(&self) -> u16 {
        0x0003
    }

    #[inline]
    pub fn minor_proto_version(&self) -> u16 {
        0x0000
    }

    #[inline]
    pub fn params(&self) -> &Vec<(CString, CString)> {
        &self.params
    }

    #[inline]
    pub fn params_mut(&mut self) -> &mut Vec<(CString, CString)> {
        &mut self.params
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend((self.len() as i32).to_be_bytes());
        bytes.extend(CLIENT_STARTUP_V3_0.to_be_bytes());
        for (k, v) in &self.params {
            bytes.extend(k.as_bytes());
            bytes.extend(v.as_bytes());
        }
        bytes.push(0x00); // null-terminating byte
    }
}

#[derive(Clone, Debug)]
pub struct Bind {
    dst_portal: CString,           // empty indicates unnamed portal
    src_prepared: CString,         // empty indicates the unnamed prepared statement
    params_fmt: Vec<FormatCode>,  // 0 indicates text; 1 indicates binary.
    params: Vec<Option<Vec<u8>>>, // None means null parameter value
    results_fmt: Vec<FormatCode>,
}

impl Bind {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_BIND
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + self.dst_portal.as_bytes().len()
            + self.src_prepared.as_bytes().len()
            + 2
            + 2 * self.params_fmt.len()
            + 2
            + self
                .params
                .iter()
                .map(|v| 4 + v.as_ref().map_or(0, |p| p.len()))
                .sum::<usize>()
            + 2
            + 2 * self.results_fmt.len()
    }

    #[inline]
    pub fn dst_portal(&self) -> &CStr {
        &self.dst_portal
    }

    #[inline]
    pub fn set_dst_portal(&mut self, dst_portal: CString) {
        self.dst_portal = dst_portal;
    }

    #[inline]
    pub fn src_stmt(&self) -> &CStr {
        &self.dst_portal
    }

    #[inline]
    pub fn set_src_stmt(&mut self, src_stmt: CString) {
        self.src_prepared = src_stmt;
    }

    #[inline]
    pub fn params_fmt(&self) -> &Vec<FormatCode> {
        &self.params_fmt
    }

    #[inline]
    pub fn params_fmt_mut(&mut self) -> &Vec<FormatCode> {
        &mut self.params_fmt
    }

    #[inline]
    pub fn params(&self) -> &Vec<Option<Vec<u8>>> {
        &self.params
    }

    #[inline]
    pub fn params_mut(&mut self) -> &mut Vec<Option<Vec<u8>>> {
        &mut self.params
    }

    #[inline]
    pub fn results_fmt(&self) -> &Vec<FormatCode> {
        &self.results_fmt
    }

    #[inline]
    pub fn results_fmt_mut(&mut self) -> &mut Vec<FormatCode> {
        &mut self.results_fmt
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(self.dst_portal.as_bytes());
        bytes.extend(self.src_prepared.as_bytes());
        bytes.extend((self.params_fmt.len() as i16).to_be_bytes());
        for f in &self.params_fmt {
            f.to_bytes_extended(bytes);
        }
        bytes.extend((self.params.len() as i16).to_be_bytes());
        for p in &self.params {
            bytes.extend(p.as_ref().map_or(-1, |v| v.len() as i32).to_be_bytes());
        }
        bytes.extend((self.results_fmt.len() as i16).to_be_bytes());
        for f in &self.results_fmt {
            f.to_bytes_extended(bytes);
        }
    }
}

#[derive(Clone, Debug)]
pub struct FunctionCall {
    function_id: i32,
    args_fmt: Vec<FormatCode>,
    args: Vec<Option<Vec<u8>>>,
    result_fmt: FormatCode,
}

impl FunctionCall {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        CLIENT_MSG_FN_CALL
    }

    #[inline]
    pub fn len(&self) -> usize {
        5 + 4
            + 2
            + 2 * self.args_fmt.len()
            + 2
            + self
                .args
                .iter()
                .map(|v| 4 + v.as_ref().map_or(0, |a| a.len()))
                .sum::<usize>()
            + 2
    }

    #[inline]
    pub fn function_id(&self) -> i32 {
        self.function_id
    }

    #[inline]
    pub fn set_function_id(&mut self, fn_id: i32) {
        self.function_id = fn_id;
    }

    #[inline]
    pub fn args_fmt(&self) -> &Vec<FormatCode> {
        &self.args_fmt
    }

    #[inline]
    pub fn args_fmt_mut(&mut self) -> &mut Vec<FormatCode> {
        &mut self.args_fmt
    }

    #[inline]
    pub fn args(&self) -> &Vec<Option<Vec<u8>>> {
        &self.args
    }

    #[inline]
    pub fn args_mut(&mut self) -> &mut Vec<Option<Vec<u8>>> {
        &mut self.args
    }

    #[inline]
    pub fn result_fmt(&self) -> FormatCode {
        self.result_fmt
    }

    #[inline]
    pub fn set_result_fmt(&mut self, result_fmt: FormatCode) {
        self.result_fmt = result_fmt;
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.msg_id());
        bytes.extend((self.len() as i32 - 1).to_be_bytes());
        bytes.extend(self.function_id.to_be_bytes());
        bytes.extend((self.args_fmt.len() as i16).to_be_bytes());
        for f in &self.args_fmt {
            f.to_bytes_extended(bytes);
        }
        bytes.extend((self.args.len() as i16).to_be_bytes());
        for p in &self.args {
            bytes.extend(p.as_ref().map_or(-1, |v| v.len() as i32).to_be_bytes());
        }
        self.result_fmt.to_bytes_extended(bytes);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FormatCode {
    Text,         // = 0
    Binary,       // = 1
    Unknown(i16), // x < 0 || x > 1
}

impl FormatCode {
    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(
            match self {
                FormatCode::Text => 0,
                FormatCode::Binary => 1,
                FormatCode::Unknown(b) => *b,
            }
            .to_be_bytes(),
        );
    }
}

impl From<i16> for FormatCode {
    #[inline]
    fn from(value: i16) -> Self {
        match value {
            0 => FormatCode::Text,
            1 => FormatCode::Binary,
            u => FormatCode::Unknown(u),
        }
    }
}

#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(PsqlClient)]
#[metadata_type(PsqlClientMetadata)]
pub struct PsqlClientRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> PsqlClientRef<'a> {}

impl<'a> FromBytesRef<'a> for PsqlClientRef<'a> {
    fn from_bytes_unchecked(_bytes: &'a [u8]) -> Self {
        todo!()
    }
}

impl<'a> LayerOffset for PsqlClientRef<'a> {
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        todo!()
    }
}

impl<'a> Validate for PsqlClientRef<'a> {
    fn validate_current_layer(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub enum ClientMessageRef<'a> {
    /// Encapsulates any of SASL, GSSAPI, SSPI and password response messages
    AuthDataResponse(AuthDataResponseRef<'a>),
    /// Indicates a Bind command
    /// (destination portal, source prepared statement, parameter format codes, parameters, result-column format codes)
    Bind(BindRef<'a>),
    /// Indicates that a request should be cancelled TODO: update documentation
    CancelRequest(CancelRequestRef<'a>),
    /// Requests that the given portal be closed
    ClosePortal(ClosePortalRef<'a>),
    /// Requests that the given prepared statement be closed
    ClosePrepared(ClosePortalRef<'a>),
    /// Carries data being copied using a COPY command
    CopyData(CopyDataRef<'a>),
    /// Indicates a COPY command has finished sending data
    CopyDone(CopyDoneRef<'a>),
    /// Indicates a COPY command has failed
    CopyFail(CopyFailRef<'a>),
    /// Requests that the given portal be described
    DescribePortal(DescribePortalRef<'a>),
    /// Requests that the given prepared statement be described
    DescribePrepared(DescribePreparedRef<'a>),
    /// Requests the given portal be executed
    /// (name of portal, maximum number of rows to return--0 means no limit)
    Execute(ExecuteRef<'a>),
    /// Requests a flush command be performed
    Flush(FlushRef<'a>),
    /// Requests a function be called
    /// (object ID of function, argument format codes--is_text, arguments, format code for function result)
    FunctionCall(FunctionCallRef<'a>),
    /// Requests GSSAPI Encryption
    GssEncRequest(GssEncRequestRef<'a>),
    /*
    /// Sends GSSAPI/SSAPI authentication data in the form of bytes
    GSSResponse(&'a [u8]),
    */
    /// Requests a command be parsed
    /// (prepared statement name, query string, parameter data types)
    Parse(ParseRef<'a>),
    /*
    /// Indicates a password is being sent, and contains the given password string
    PasswordMessage(&'a str),
    */
    /// Requests that he given simple SQL query be executed
    Query(QueryRef<'a>),
    /*
    /// An initial SASL response, or else data for a GSSAPI, SSAPI or password response
    /// (selected SASL authentication mechanism, SASL mechanism specific "initial Response")
    SASLInitialResponse(&'a str, Option<&'a [u8]>),

    /// A SASL response, or else data for a GSSAPI, SSAPI or password response containing
    /// SASL mechanism specific message data
    SASLResponse(&'a [u8]),
    */
    /// Requests the connection be encrypted with SSL
    SslRequest(SslRequestRef<'a>),
    /// Requests a particular user be connected to the database
    StartupMessage(StartupMessageRef<'a>),
    /// Requests a Sync command be performed
    Sync(SyncRef<'a>),
    /// Identifies the message as a termination
    Terminate(TerminateRef<'a>),
}

#[derive(Clone, Debug)]
pub struct AuthDataResponseRef<'a> {
    data: &'a [u8],
}

impl<'a> AuthDataResponseRef<'a> {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn auth_data(&self) -> &[u8] {
        &self.data[5..]
    }
}

#[derive(Clone, Debug)]
pub struct BindRef<'a> {
    data: &'a [u8],
    //    dst_portal: String, // empty indicates unnamed portal
    //    src_prepared: String, // empty indicates the unnamed prepared statement
    //    param_fmt: Vec<FormatCode>, // 0 indicates text; 1 indicates binary.
    //    param_values: Vec<Option<Vec<u8>>>, // None means null parameter value
    //    result_fmt: Vec<FormatCode>
}

impl<'a> BindRef<'a> {
    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    pub fn dst_portal(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[5..]).unwrap()
    }

    pub fn src_stmt(&self) -> &CStr {
        let mut cstrs = self.data[5..].split_inclusive(|b| *b == b'\0');
        cstrs.next(); // dst_portal
        CStr::from_bytes_with_nul(cstrs.next().unwrap()).unwrap()
    }

    pub fn params_fmt(&self) -> FormatCodeIter {
        let mut rem = &self.data[5..];
        let mut remaining_strings = 2;
        while remaining_strings > 0 {
            let c;
            (c, rem) = rem.split_first().unwrap();
            if *c == 0 {
                remaining_strings -= 1;
            }
        }

        let fmt_cnt_arr;
        (fmt_cnt_arr, rem) = utils::split_array(rem).unwrap();
        let fmt_code_cnt = i16::from_be_bytes(*fmt_cnt_arr);

        FormatCodeIter {
            data: rem,
            num_codes: fmt_code_cnt,
        }
    }

    pub fn params(&self) -> ParamIter {
        let fmt_codes = self.params_fmt();
        let mut rem = &fmt_codes.data[cmp::max(0, fmt_codes.num_codes) as usize * 2..];

        let param_cnt_arr;
        (param_cnt_arr, rem) = utils::split_array(rem).unwrap();
        let param_cnt = i16::from_be_bytes(*param_cnt_arr);

        ParamIter {
            data: rem,
            num_params: param_cnt,
        }
    }

    pub fn results_fmt(&self) -> FormatCodeIter {
        let mut params = self.params();
        for _ in params.by_ref() {}

        let mut rem = params.data;

        let fmt_cnt_arr;
        (fmt_cnt_arr, rem) = utils::split_array(rem).unwrap();
        let fmt_code_cnt = i16::from_be_bytes(*fmt_cnt_arr);

        FormatCodeIter {
            data: rem,
            num_codes: fmt_code_cnt,
        }
    }
}

pub struct FormatCodeIter<'a> {
    data: &'a [u8],
    num_codes: i16,
}

impl<'a> Iterator for FormatCodeIter<'a> {
    type Item = FormatCode;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num_codes <= 0 {
            return None;
        }

        let fmt_code_arr;
        (fmt_code_arr, self.data) = utils::split_array(self.data).unwrap();

        self.num_codes -= 1;
        Some(i16::from_be_bytes(*fmt_code_arr).into())
    }
}

pub struct ParamIter<'a> {
    data: &'a [u8],
    num_params: i16,
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = Option<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num_params <= 0 {
            return None;
        }

        let param_len_arr;
        (param_len_arr, self.data) = utils::split_array(self.data).unwrap();

        self.num_params -= 1;
        let param_len = i32::from_be_bytes(*param_len_arr);
        if param_len < 0 {
            // When -1, treat as None
            Some(None)
        } else {
            let param;
            (param, self.data) = utils::split_at(self.data, param_len as usize).unwrap();
            Some(Some(param))
        }
    }
}

#[derive(Clone, Debug)]
pub struct CancelRequestRef<'a> {
    data: &'a [u8],
    //    proc_id: i32,
    //    key: i32,
}

impl<'a> CancelRequestRef<'a> {
    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn cancel_req_code(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    #[inline]
    pub fn process_id(&self) -> i32 {
        i32::from_be_bytes(*utils::get_array(self.data, 8).unwrap())
    }

    #[inline]
    pub fn key(&self) -> i32 {
        i32::from_be_bytes(*utils::get_array(self.data, 12).unwrap())
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_length, cancel_req_code) = match (utils::get_array(bytes, 0), utils::get_array(bytes, 4)) {
            (Some(m), Some(c)) if bytes.len() >= 16 => (i32::from_be_bytes(*m), i32::from_be_bytes(*c)),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Cancel Request packet to extract Message fields",
            })
        };

        if msg_length != 16 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "Length field in PsqlClient Cancel Request packet did not match expected (must be equal to 16)",
            });
        }

        if cancel_req_code != CLIENT_STARTUP_CANCEL_REQ {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "Cancel Request Code field in PsqlClient Cancel Request packet did not match expected (must be equal to 0x12345678)",
            });
        }

        if bytes.len() > 16 {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - 16),
                #[cfg(feature = "error_string")]
                reason: "extra bytes remained at end of PsqlClient Cancel Request packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClosePortalRef<'a> {
    data: &'a [u8],
    //    portal_name: String,
}

impl<'a> ClosePortalRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ClosePortalRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn close_type(&self) -> u8 {
        self.data[5]
    }

    pub fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[6..]).unwrap()
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length, close_type) = match (
            bytes.first(),
            utils::get_array(bytes, 1),
            bytes.get(6),
        ) {
            (Some(m), Some(c), Some(t)) => (*m, i32::from_be_bytes(*c), *t),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in PsqlClient Close Portal packet to extract message fields",
            }),
        };

        let msg_length = cmp::max(0, msg_length) as usize;

        let (null_term, portal_name_bytes) = match bytes
            .get(6..cmp::max(7, msg_length))
            .and_then(|b| b.split_last())
        {
            // 1 for msg_type + 4 for msg_len + 1 for close_type + 1 for minimum size of string (null terminator)
            Some(t) => t,
            None => {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason:
                        "insufficient bytes in PsqlClient Close Portal packet for Portal Name field",
                })
            }
        };

        if msg_type != CLIENT_MSG_CLOSE {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason:
                    "wrong Message Type field in PsqlClient Close Portal packet (expected 0x43)",
            });
        }

        if msg_length < 7 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason:
                    "invalid Length field in PsqlClient Close Portal packet (must be at least 7)",
            });
        }

        if close_type != b'P' {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Close Type field in PsqlClient Close Portal packet (expected 0x50)",
            });
        }

        match str::from_utf8(portal_name_bytes) {
            Ok(s) => if s.find('\x00').is_some() {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InvalidValue,
                    #[cfg(feature = "error_string")]
                    reason: "null character found before end of string in PsqlClient Close Portal packet Portal Name field",
                })
            },
            Err(_) => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid UTF-8 character found in PsqlClient Close Portal packet Portal Name field",
            }),
        }

        if *null_term != 0 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "missing null terminating byte at end of PsqlClient Close Portal packet Portal Name field",
            });
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Close Portal packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClosePreparedRef<'a> {
    data: &'a [u8],
}

impl<'a> ClosePreparedRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ClosePreparedRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn close_type(&self) -> u8 {
        self.data[5]
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[6..]).unwrap()
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length, close_type) = match (bytes.first(), utils::get_array(bytes, 1), bytes.get(6)) {
            (Some(m), Some(c), Some(t)) => (*m, i32::from_be_bytes(*c), *t),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Close Prepared Statement packet to extract message fields",
            })
        };

        let msg_length = cmp::max(0, msg_length) as usize;

        let (null_term, portal_name_bytes) = match bytes.get(6..cmp::max(7, msg_length)).and_then(|b| b.split_last()) { // 1 for msg_type + 4 for msg_len + 1 for close_type + 1 for minimum size of string (null terminator)
            Some(t) => t,
            None => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Close Prepared Statement packet for Prepared Statement Name field",
            })
        };

        if msg_type != CLIENT_MSG_CLOSE {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Close Prepared Statement packet (expected 0x43)",
            });
        }

        if msg_length < 7 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid Length field in PsqlClient Close Prepared Statement packet (must be at least 7)",
            });
        }

        if close_type != b'S' {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Close Type field in PsqlClient Close Prepared Statement packet (expected 0x53)",
            });
        }

        match str::from_utf8(portal_name_bytes) {
            Ok(s) => if s.find('\x00').is_some() {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InvalidValue,
                    #[cfg(feature = "error_string")]
                    reason: "null character found before end of string in PsqlClient Close Prepared Statement packet Prepared Statement Name field",
                })
            },
            Err(_) => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid UTF-8 character found in PsqlClient Close Prepared Statement packet Prepared Statement Name field",
            }),
        }

        if *null_term != 0 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "missing null terminating byte at end of PsqlClient Close Prepared Statement packet Prepared Statement Name field",
            });
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Close Prepared Statement packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct CopyDataRef<'a> {
    data: &'a [u8],
    //    data_stream: Vec<u8>,
}

impl<'a> CopyDataRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        CopyDataRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn data_stream(&self) -> &[u8] {
        &self.data[5..]
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length) = match (bytes.first(), utils::get_array(bytes, 1)) {
            (Some(m), Some(c)) => (*m, i32::from_be_bytes(*c)),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in PsqlClient Copy Data packet to extract message fields",
            }),
        };

        let msg_length = cmp::max(5, msg_length) as usize;
        if bytes.len() < msg_length {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in PsqlClient Copy Data packet to extract Data Stream field",
            });
        }

        if msg_type != CLIENT_MSG_COPY_DATA {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Copy Data packet (expected 0x43)",
            });
        }

        if msg_length < 5 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "invalid Message Length field in PsqlClient Copy Data packet (too short--must be >= 5)",
            });
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Copy Data packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct CopyDoneRef<'a> {
    data: &'a [u8],
}

impl<'a> CopyDoneRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        CopyDoneRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length) = match (bytes.first(), utils::get_array(bytes, 1)) {
            (Some(m), Some(c)) => (*m, i32::from_be_bytes(*c)),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Copy Done packet to extract message header fields",
            })
        };

        if msg_type != CLIENT_MSG_COPY_DONE {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Copy Done packet (expected 0x63)",
            });
        }

        if msg_length != 5 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "invalid Message Length field in PsqlClient Copy Done packet (must be equal to 5)",
            });
        }

        if bytes.len() > 5 {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - 5),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Copy Done packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct CopyFailRef<'a> {
    data: &'a [u8],
    //    err_msg: String,
}

impl<'a> CopyFailRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        CopyFailRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    pub fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[5..]).unwrap()
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length) = match (bytes.first(), utils::get_array(bytes, 1)) {
            (Some(m), Some(c)) => (*m, i32::from_be_bytes(*c)),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in PsqlClient Copy Fail packet to extract message fields",
            }),
        };

        let msg_length = cmp::max(0, msg_length) as usize;

        let (null_term, portal_name_bytes) =
            match bytes
                .get(5..cmp::max(6, msg_length))
                .and_then(|b| b.split_last())
            {
                // 1 for msg_type + 4 for msg_len + 1 for minimum size of string (null terminator)
                Some(t) => t,
                None => return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason:
                        "insufficient bytes in PsqlClient Copy Fail packet for Error Message field",
                }),
            };

        if msg_type != CLIENT_MSG_COPY_FAIL {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Copy Fail packet (expected 0x66)",
            });
        }

        if msg_length < 6 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid Length field in PsqlClient Copy Fail packet (must be at least 6)",
            });
        }

        match str::from_utf8(portal_name_bytes) {
            Ok(s) => if s.find('\x00').is_some() {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InvalidValue,
                    #[cfg(feature = "error_string")]
                    reason: "null character found before end of string in PsqlClient Copy Fail packet Error Message field",
                })
            },
            Err(_) => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid UTF-8 character found in PsqlClient Copy Fail packet Error Message field",
            }),
        }

        if *null_term != 0 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "missing null terminating byte at end of PsqlClient Copy Fail packet Prepared Statement Name field",
            });
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Copy Fail packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct DescribePortalRef<'a> {
    data: &'a [u8],
    //    portal_name: String,
}

impl<'a> DescribePortalRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        DescribePortalRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn describe_type(&self) -> u8 {
        self.data[5]
    }

    pub fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[6..]).unwrap()
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length, describe_type) = match (bytes.first(), utils::get_array(bytes, 1), bytes.get(6)) {
            (Some(m), Some(c), Some(t)) => (*m, i32::from_be_bytes(*c), *t),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Describe Portal packet to extract message fields",
            })
        };

        let msg_length = cmp::max(0, msg_length) as usize;

        let (null_term, portal_name_bytes) = match bytes
            .get(6..cmp::max(7, msg_length))
            .and_then(|b| b.split_last())
        {
            // 1 for msg_type + 4 for msg_len + 1 for close_type + 1 for minimum size of string (null terminator)
            Some(t) => t,
            None => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in PsqlClient Describe Portal packet for Portal Name field",
            }),
        };

        if msg_type != CLIENT_MSG_DESCRIBE {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason:
                    "wrong Message Type field in PsqlClient Describe Portal packet (expected 0x44)",
            });
        }

        if msg_length < 7 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason:
                    "invalid Length field in PsqlClient Describe Portal packet (must be at least 7)",
            });
        }

        if describe_type != b'P' {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason:
                    "wrong Describe Type field in PsqlClient Describe Portal packet (expected 0x50)",
            });
        }

        match str::from_utf8(portal_name_bytes) {
            Ok(s) => if s.find('\x00').is_some() {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InvalidValue,
                    #[cfg(feature = "error_string")]
                    reason: "null character found before end of string in PsqlClient Describe Portal packet Portal Name field",
                })
            },
            Err(_) => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid UTF-8 character found in PsqlClient Describe Portal packet Portal Name field",
            }),
        }

        if *null_term != 0 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "missing null terminating byte at end of PsqlClient Describe Portal packet Portal Name field",
            });
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Describe Portal packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct DescribePreparedRef<'a> {
    data: &'a [u8],
    //    prepared_name: String,
}

impl<'a> DescribePreparedRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        DescribePreparedRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    #[inline]
    pub fn describe_type(&self) -> u8 {
        self.data[5]
    }

    pub fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[6..]).unwrap()
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length, describe_type) = match (bytes.first(), utils::get_array(bytes, 1), bytes.get(6)) {
            (Some(m), Some(c), Some(t)) => (*m, i32::from_be_bytes(*c), *t),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Describe Prepared Statement packet to extract message fields",
            })
        };

        let msg_length = cmp::max(0, msg_length) as usize;

        let (null_term, portal_name_bytes) = match bytes.get(6..cmp::max(7, msg_length)).and_then(|b| b.split_last()) { // 1 for msg_type + 4 for msg_len + 1 for close_type + 1 for minimum size of string (null terminator)
            Some(t) => t,
            None => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Describe Prepared Statement packet for Prepared Statement Name field",
            })
        };

        if msg_type != CLIENT_MSG_DESCRIBE {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Describe Prepared Statement packet (expected 0x44)",
            });
        }

        if msg_length < 7 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid Length field in PsqlClient Describe Prepared Statement packet (must be at least 7)",
            });
        }

        if describe_type != b'S' {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Describe Type field in PsqlClient Describe Prepared Statement packet (expected 0x53)",
            });
        }

        match str::from_utf8(portal_name_bytes) {
            Ok(s) => if s.find('\x00').is_some() {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InvalidValue,
                    #[cfg(feature = "error_string")]
                    reason: "null character found before end of string in PsqlClient Describe Prepared Statement packet Prepared Statement Name field",
                })
            },
            Err(_) => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid UTF-8 character found in PsqlClient Describe Prepared Statement packet Prepared Statement Name field",
            }),
        }

        if *null_term != 0 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "missing null terminating byte at end of PsqlClient Close Prepared Statement packet Prepared Statement Name field",
            });
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Close Prepared Statement packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecuteRef<'a> {
    data: &'a [u8],
    //    portal_name: String, // empty string means unnamed portal
    //    max_rows: Option<i32>, // None corresponds to 0 (no maximum)
}

impl<'a> ExecuteRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        ExecuteRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    pub fn portal_name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.data[5..]).unwrap()
    }

    pub fn max_rows(&self) -> Option<i32> {
        let payload = &self.data[5..];

        let (_, rem) = utils::split_delim(payload, 0x00).unwrap();
        let max_rows_arr = utils::to_array(rem, 0).unwrap();
        match i32::from_be_bytes(max_rows_arr) {
            0 => None,
            i => Some(i),
        }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length) = match (bytes.first(), utils::get_array(bytes, 1)) {
            (Some(m), Some(c)) => (*m, i32::from_be_bytes(*c)),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in PsqlClient Execute packet to extract message header fields",
            })
        };

        let msg_length = cmp::max(10, msg_length) as usize; // 1 (msg type) + 4 (len) + 1 (null term) + 4 (max_rows)

        let rem = match bytes.get(msg_length..) {
            Some(r) => r,
            None => {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    #[cfg(feature = "error_string")]
                    reason: "insufficient bytes in PsqlClient Execute packet for Portal Name field",
                })
            }
        };

        let (portal_name_bytes, _max_rows_bytes) = match utils::split_delim(rem, 0x00) {
            Some(t) => t,
            None => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "missing null terminating byte in PsqlClient Execute packet for Portal Name field"
            })
        };

        if msg_type != CLIENT_MSG_DESCRIBE {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Describe Prepared Statement packet (expected 0x44)",
            });
        }

        if msg_length < 7 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid Length field in PsqlClient Describe Prepared Statement packet (must be at least 7)",
            });
        }

        match str::from_utf8(portal_name_bytes) {
            Ok(s) => if s.find('\x00').is_some() {
                return Err(ValidationError {
                    layer: PsqlClient::name(),
                    class: ValidationErrorClass::InvalidValue,
                    #[cfg(feature = "error_string")]
                    reason: "null character found before end of string in PsqlClient Describe Prepared Statement packet Prepared Statement Name field",
                })
            },
            Err(_) => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "invalid UTF-8 character found in PsqlClient Describe Prepared Statement packet Prepared Statement Name field",
            }),
        }

        if bytes.len() > msg_length {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - msg_length),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Close Prepared Statement packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlushRef<'a> {
    data: &'a [u8],
}

impl<'a> FlushRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        FlushRef { data: bytes }
    }

    #[inline]
    pub fn msg_id(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn msg_length(&self) -> i32 {
        i32::from_be_bytes(utils::to_array(self.data, 1).unwrap())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msg_length() as usize + 1
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        let (msg_type, msg_length) = match (bytes.first(), utils::get_array(bytes, 1)) {
            (Some(m), Some(c)) => (*m, i32::from_be_bytes(*c)),
            _ => return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "insufficient bytes in PsqlClient Flush packet to extract message header fields",
            }),
        };

        if msg_type != CLIENT_MSG_FLUSH {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
                reason: "wrong Message Type field in PsqlClient Flush packet (expected 0x48)",
            });
        }

        if msg_length != 5 {
            return Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason:
                    "invalid Message Length field in PsqlClient Flush packet (must be equal to 5)",
            });
        }

        if bytes.len() > 5 {
            Err(ValidationError {
                layer: PsqlClient::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - 5),
                #[cfg(feature = "error_string")]
                reason: "trailing bytes found at end of PsqlClient Flush packet",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct FunctionCallRef<'a> {
    data: &'a [u8],
    //    object_id: i32,
    //    arg_fmt: Vec<FormatCode>,
    //    arg_values: Vec<Option<Vec<u8>>>,
    //    result_fmt: FormatCode,
}

#[derive(Clone, Debug)]
pub struct GssEncRequestRef<'a> {
    data: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct ParseRef<'a> {
    data: &'a [u8],
    //    dst_stmt: String,
    //    query: String,
    //    type_ids: Vec<Option<i32>>,
}

#[derive(Clone, Debug)]
pub struct QueryRef<'a> {
    data: &'a [u8],
    //    query: String,
}

#[derive(Clone, Debug)]
pub struct SslRequestRef<'a> {
    data: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct StartupMessageRef<'a> {
    data: &'a [u8],
    //    params: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct SyncRef<'a> {
    data: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct TerminateRef<'a> {
    data: &'a [u8],
}

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(PsqlServerMetadata)]
#[ref_type(PsqlServerRef)]
pub struct PsqlServer {
    packet: ServerMessage,
}

impl PsqlServer {
    #[inline]
    pub fn message(&self) -> &ServerMessage {
        &self.packet
    }

    #[inline]
    pub fn message_mut(&mut self) -> &mut ServerMessage {
        &mut self.packet
    }
}

#[doc(hidden)]
impl FromBytesCurrent for PsqlServer {
    fn payload_from_bytes_unchecked_default(&mut self, _bytes: &[u8]) {
        todo!()
    }

    fn from_bytes_current_layer_unchecked(_bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerLength for PsqlServer {
    fn len(&self) -> usize {
        todo!()
    }
}

impl LayerObject for PsqlServer {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        false
    }

    #[inline]
    fn add_payload_unchecked(&mut self, _payload: Box<dyn LayerObject>) {
        todo!()
        // self.payload = Some(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        todo!()
        /*
        match self.payload {
            Some(payload) => slice::from_ref(&payload),
            None => &[]
        }
        */
    }

    #[inline]
    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        todo!()
        /*
        match &mut self.payload {
            Some(payload) => slice::from_mut(payload),
            None => &mut []
        }
        */
    }

    fn remove_payload_at(&mut self, _index: usize) -> Option<Box<dyn LayerObject>> {
        todo!()
        /*
        if index != 0 {
            return None
        }

        let mut ret = None;
        core::mem::swap(&mut ret, &mut self.payload);
        ret
        */
    }
}

impl ToBytes for PsqlServer {
    fn to_bytes_checksummed(
        &self,
        _bytes: &mut Vec<u8>,
        _prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub enum ServerMessage {
    /// Indicates successful authentication
    AuthenticationOk,
    /// Indicates that Kerberos V5 authentication is required
    AuthenticationKerberosV5,
    /// Indicates that a cleartext password is required
    AuthenticationCleartextPassword,
    /// Indicates that an MD5 hash of the password with the given 4-byte salt should be sent for authentication
    AuthenticationMD5Password([u8; 4]),
    /// Indicates that SCM credentials are required
    AuthenticationSCMCredential,
    /// Indicates that GSSAPI authentication is required
    AuthenticationGSS,
    /// Indicates that additional GSSAPI or SSPI authentication data is required
    AuthenticationGSSContinue(Vec<u8>),
    /// Indicates that SSPI authentication is required
    AuthenticationSSPI,
    /// Indicates SASL authentication is required; contains the server's list of authentication mechanisms ordered by preference
    AuthenticationSASL(Vec<String>),
    /// Interim SASL authentication message containing SASL data specific to the SASL mechanism being used
    AuthenticationSASLContinue(Vec<u8>),
    /// Final SASL message containing "additional data" specific to the SASL mechanism being used
    AuthenticationSASLFinal(Vec<u8>),
    /// Provides cancellation key data (process ID and a secret key) that the frontend must use to issue CancelRequest messages later
    BackendKeyData(i32, i32),
    /// Indicates that a Bind request has completed successfully
    BindComplete,
    /// Indicates that a close request was successful
    CloseComplete,
    /// Indicates that the command specified by the given tag was completed
    CommandComplete(String),
    /// Carries data being copied using a COPY command
    CopyData(Vec<u8>),
    /// Indicates a COPY command has finished sending data
    CopyDone,
    /// Indicates the beginning of a COPY from the client to the server
    /// (is_binary, format codes for each column (and number of columns))
    CopyInResponse(bool, Vec<bool>),
    /// Indicates the beginning of a COPY from the server to the client
    /// (is_binary, format codes for each column (and number of columns))
    CopyOutResponse(bool, Vec<bool>),
    /// Indicates the beginning of a copy that uses Streaming Replication
    CopyBothResponse(bool, Vec<bool>),
    /// Indicates the given message is a data row containing a number of columns with values (None = null)
    DataRow(Vec<Option<Vec<u8>>>),
    /// Response to an empty query string (substitues for CommandComplete)
    EmptyQueryResponse,
    /// Indicates an error has occurred
    ErrorResponse(BTreeMap<u8, String>),
    /// Response to a given FunctionCall containing a result value--None means null
    FunctionCallResponse(Option<Vec<u8>>),
    /// Indicates protocol version must be negotiated.
    /// (newest minor protocol version supported, protocol options not recognized by server)
    NegotiateProtocolVersion(i32, Vec<String>),
    /// Indicates that no data could be sent
    NoData,
    /// A response that asynchronously conveys information to the client
    NoticeResponse(BTreeMap<u8, String>),
    /// Indicates a notification has been raised from a backend process
    /// (process ID, name of channel, payload string notification)
    NotificationResponse(i32, String, String),
    /// The message describes parameters for a query, with each `u32` specifying the object ID of the parameter at the given index
    ParameterDescription(Vec<i32>),
    /// A one-time parameter status report
    /// (parameter being reported, current value for parameter)
    ParameterStatus(String, String),
    /// Indicates a Parse command has been completed
    ParseComplete,
    /// Indicates an Execute message's row-count limit was reached, so the portal was suspended
    PortalSuspended,
    /// Indicates the backend is ready for its next query, with the given `char` specifying either
    /// 'I' if idle (not in any transaction block), 'T' if in a transaction block, or 'E' if
    /// a failed instruction occurred in the current transaction block.
    ReadyForQuery(TransactionStatus),
    /// Returns data for a single row
    /// (field name, table ID, column ID, data type object ID, data type size, type modifier, is_binary)
    RowDescription(Vec<RowField>),
}

#[derive(Clone, Debug)]
pub enum TransactionStatus {
    Idle,              // = 'I'
    Transaction,       // = 'T'
    FailedTransaction, // = 'E'
}

#[derive(Clone, Debug)]
pub struct RowField {
    name: String,
    table_id: Option<i32>, // None = 0, which means field can't be identified as the column of a particular table
    column_attr_num: Option<i16>, // None = 0, which means field can't be identified as the column of a particular table (thus no column attribute number)
    data_id: i32,
    size: Option<i16>, // None = negative val, which means variable length size
    type_mod: i16,
    fmt_code: i16, // enum (Text = 0, Binary = 1, Unknown = 2..)
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(PsqlServer)]
#[metadata_type(PsqlServerMetadata)]
pub struct PsqlServerRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> PsqlServerRef<'a> {}

impl<'a> FromBytesRef<'a> for PsqlServerRef<'a> {
    fn from_bytes_unchecked(_bytes: &'a [u8]) -> Self {
        todo!()
    }
}

impl<'a> LayerOffset for PsqlServerRef<'a> {
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        todo!()
    }
}

impl<'a> Validate for PsqlServerRef<'a> {
    fn validate_current_layer(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}
