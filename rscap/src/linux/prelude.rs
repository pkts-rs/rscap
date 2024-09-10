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

pub use super::addr::{L2Addr, L2AddrAny, L2AddrIp, L2AddrUnspec};
pub use super::l2::L2Socket;
#[cfg(feature = "libcfull")]
pub use super::l2::{L2MappedSocket, L2RxMappedSocket, L2TxMappedSocket};
pub use super::{FanoutAlgorithm, RxTimestamping, TxTimestamping};
pub use crate::Interface;
pub use crate::filter::PacketStatistics;
