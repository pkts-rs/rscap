// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(doc, not(target_os = "windows"), feature = "npcap"))]
mod sniffer;

#[cfg(any(doc, not(target_os = "windows"), feature = "npcap"))]
pub use sniffer::AsyncSniffer;
