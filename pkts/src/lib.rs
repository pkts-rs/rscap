// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A library for creating, decoding and modifying packet layers.
//!

#![forbid(unsafe_code)]

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

use core::cmp;
use error::SerializationError;
use layers::dev_traits::LayerName;
use pkts_common::{Buffer, BufferMut};


pub mod error;
pub mod layers;
#[doc(hidden)]
pub mod prelude;
pub mod sequence;
pub mod session;
pub mod utils;

mod private {
    pub trait Sealed {}
}

pub struct PacketWriter<'a, T: IndexedWritable> {
    writable: &'a mut T,
    error_layer: &'static str,
}

impl<'a, T: IndexedWritable> PacketWriter<'a, T> {
    /// Constructs a new writer with errors reported as originating from layer `L`.
    pub fn new<L: LayerName>(writable: &'a mut T) -> Self {
        Self {
            writable,
            error_layer: L::name(),
        }
    }

    /// Writes the data to the writer at its current index.
    pub fn write(&mut self, data: &[u8]) -> Result<(), SerializationError> {
        self.writable.write(data).map_err(|e| match e {
            IndexedWriteError::OutOfRange => panic!(),
            IndexedWriteError::InsufficientBytes => SerializationError::insufficient_buffer(self.error_layer),
        })
    }

    /// Writes the data at the specified index position.
    /// 
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    pub fn write_at(&mut self, data: &[u8], pos: usize) -> Result<(), SerializationError> {
        self.writable.write_at(data, pos).map_err(|e| match e {
            IndexedWriteError::OutOfRange => panic!(),
            IndexedWriteError::InsufficientBytes => SerializationError::insufficient_buffer(self.error_layer),
        })
    }

    /// Returns the current index of the writer.
    pub fn pos(&self) -> usize {
        self.writable.pos()
    }

    /// Shifts the writer's index back to the provided index position, truncating the stream.
    /// 
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    pub fn rewind_pos(&mut self, pos: usize) -> Result<(), SerializationError> {
        self.writable.rewind_pos(pos).map_err(|e| match e {
            IndexedWriteError::OutOfRange => panic!(),
            IndexedWriteError::InsufficientBytes => SerializationError::insufficient_buffer(self.error_layer),           
        })
    }
}

pub trait IndexedWritable {
    /// Writes the data to the writer at its current index.
    fn write(&mut self, data: &[u8]) -> Result<(), IndexedWriteError>;

    /// Writes the data at the specified index position.
    /// 
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    fn write_at(&mut self, data: &[u8], pos: usize) -> Result<(), IndexedWriteError>;

    /// Returns the current index of the writer.
    fn pos(&self) -> usize;

    /// Shifts the writer's index back to the provided index position, truncating the stream.
    /// 
    /// This method will panic if `pos` is greater than the current written length of the buffer.
    fn rewind_pos(&mut self, pos: usize) -> Result<(), IndexedWriteError>;
}

impl IndexedWritable for Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<(), IndexedWriteError> {
        self.extend(data);
        Ok(())
    }

    fn write_at(&mut self, data: &[u8], pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            return Err(IndexedWriteError::OutOfRange)
        }

        let split = cmp::max(self.len() - pos, data.len());

        self[pos..pos + split].copy_from_slice(&data[..split]);
        self.extend(&data[split..]);
        Ok(())
    }

    fn pos(&self) -> usize {
        self.len()
    }

    fn rewind_pos(&mut self, pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            Err(IndexedWriteError::OutOfRange)
        } else {
            self.truncate(pos);
            Ok(())
        }
    }
}

impl<const N: usize> IndexedWritable for Buffer<u8, N> {
    fn write(&mut self, slice: &[u8]) -> Result<(), IndexedWriteError> {
        self.append(slice);
        Ok(())
    }

    fn write_at(&mut self, slice: &[u8], pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            return Err(IndexedWriteError::OutOfRange)
        }

        let split = cmp::max(self.len() - pos, slice.len());

        self.as_mut_slice()[pos..pos + split].copy_from_slice(&slice[..split]);
        self.append(&slice[split..]);
        Ok(())
    }

    fn pos(&self) -> usize {
        self.len()
    }

    fn rewind_pos(&mut self, pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            Err(IndexedWriteError::OutOfRange)
        } else {
            self.truncate(pos);
            Ok(())
        }
    }
}

impl IndexedWritable for BufferMut<'_> {
    fn write(&mut self, slice: &[u8]) -> Result<(), IndexedWriteError> {
        self.append(slice);
        Ok(())
    }

    fn write_at(&mut self, slice: &[u8], pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            return Err(IndexedWriteError::OutOfRange)
        }

        let split = cmp::max(self.len() - pos, slice.len());

        self.as_mut_slice()[pos..pos + split].copy_from_slice(&slice[..split]);
        self.append(&slice[split..]);
        Ok(())
    }

    fn pos(&self) -> usize {
        self.len()
    }

    fn rewind_pos(&mut self, pos: usize) -> Result<(), IndexedWriteError> {
        if pos > self.len() {
            Err(IndexedWriteError::OutOfRange)
        } else {
            self.truncate(pos);
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub enum IndexedWriteError {
    /// An attempted indexed write would write beyond the end of the writer's buffer. 
    OutOfRange,
    /// An attempted write failed due to the underlying writable running out of storage space.
    InsufficientBytes,
}


pub trait Readable {
    fn read_slice(&mut self) -> Result<&[u8], SerializationError>;

    fn read_byte(&mut self) -> Result<u8, SerializationError>;   
}


#[cfg(test)]
mod tests {
    use crate::layers::ip::Ipv4;

    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::*;
    use crate::layers::udp::*;
    use crate::parse_layers;
    use crate::sequence::LayeredSequence;
    use crate::sequence::ipv4::*;
    use pkts_common::BufferMut;

    #[test]
    fn udp_builder() {
        let payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

        let mut buffer = [0u8; 128];

        let udp_builder = UdpBuilder::new(&mut buffer)
            .sport(65321)
            .dport(443)
            .chksum(0)
            .payload_raw(&payload);

        let _buf: BufferMut<'_> = match udp_builder.build() {
            Ok(buf) => buf,
            Err(e) => panic!("{:?}", e),
        };
    }

    #[test]
    fn udp_builder_2() {
        let inner_payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut buffer = [0u8; 100];

        let udp_builder = UdpBuilder::new(&mut buffer)
            .sport(65321)
            .dport(443)
            .chksum(0)
            .payload(|b| {
                UdpBuilder::from_buffer(b)
                    .sport(2452)
                    .dport(80)
                    .chksum(0)
                    .payload_raw(&inner_payload)
                    .build()
            });

        let _udp_packet = udp_builder.build().unwrap();
    }

    #[test]
    fn from_the_layers() {
        let bytes = b"hello".as_slice();
        let _tcp = Tcp::from_bytes(bytes);

        let tcpref = TcpRef::from_bytes_unchecked(bytes);

        let _into_tcp: Tcp = tcpref.into();

        let _layers = parse_layers!(bytes, Tcp, Tcp, Ipv4).unwrap();

        //let layers = Tcp::from_layers(bytes, [Tcp, Ipv4, Tcp]);
    }

    #[test]
    fn multi_layer_sequence() {
        let ip1 = Ipv4Sequence::new();

        let mut _layered_seq = LayeredSequence::new(ip1, false)
            .add(Ipv4Sequence::new(), true)
            .add(Ipv4Sequence::new(), false)
            .add(Ipv4Sequence::new(), true);
    }
}
