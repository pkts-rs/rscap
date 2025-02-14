// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_snake_case)]

use std::ffi::CStr;
use std::io;
use std::ptr::NonNull;

use windows_sys::Win32::Foundation::{BOOL, BOOLEAN, HANDLE};

use crate::filter::BpfProgram;

use super::{Adapter, BpfStat, NetType, NpfIfAddr, Packet, PacketOidData};

#[link(name = "Packet", kind = "dylib")]
extern "C" {
    fn PacketGetDriverVersion() -> windows_sys::core::PCSTR;

    fn PacketGetDriverName() -> windows_sys::core::PCSTR;

    fn PacketSetMinToCopy(adapter: *mut Adapter, nbytes: libc::c_int) -> BOOLEAN;

    fn PacketSetNumWrites(adapter: *mut Adapter, nwrites: libc::c_int) -> BOOLEAN;

    fn PacketSetMode(adapter: *mut Adapter, mode: libc::c_int) -> BOOLEAN;

    fn PacketSetReadTimeout(adapter: *mut Adapter, timeout: libc::c_int) -> BOOLEAN;

    fn PacketSetBpf(adapter: *mut Adapter, fp: *const BpfProgram) -> BOOLEAN;

    fn PacketSetLoopbackBehavior(adapter: *mut Adapter, behavior: libc::c_uint) -> BOOLEAN;

    fn PacketSetTimestampMode(adapter: *mut Adapter, mode: libc::c_ulong) -> BOOLEAN;

    fn PacketGetTimestampModes(adapter: *mut Adapter, modes: *mut libc::c_ulong) -> BOOLEAN;

    fn PacketSetSnaplen(adapter: *mut Adapter, snaplen: libc::c_int) -> libc::c_int;

    fn PacketGetStats(adapter: *mut Adapter, stats: *mut BpfStat) -> BOOLEAN;

    fn PacketGetStatsEx(adapter: *mut Adapter, stats: *mut BpfStat) -> BOOLEAN;

    fn PacketSetBuff(adapter: *mut Adapter, dim: libc::c_int) -> BOOLEAN;

    fn PacketGetNetType(adapter: *mut Adapter, ty: *mut NetType) -> BOOLEAN;

    fn PacketIsLoopbackAdapter(adapter_name: *const libc::c_char) -> BOOLEAN;

    fn PacketIsMonitorModeSupported(adapter_name: *const libc::c_char) -> libc::c_int;

    fn PacketSetMonitorMode(adapter_name: *const libc::c_char, mode: libc::c_int) -> libc::c_int;

    fn PacketGetMonitorMode(adapter_name: *const libc::c_char) -> libc::c_int;

    fn PacketOpenAdapter(adapter_name: *const libc::c_char) -> *mut Adapter;

    fn PacketSendPacket(adapter: *mut Adapter, packet: *mut Packet, sync: BOOLEAN) -> BOOLEAN;

    fn PacketSendPackets(
        adapter: *mut Adapter,
        packet_buf: *mut libc::c_void,
        size: libc::c_ulong,
        sync: BOOLEAN,
    ) -> libc::c_int;

    fn PacketAllocatePacket() -> *mut Packet;

    fn PacketInitPacket(packet: *mut Packet, buffer: *mut libc::c_void, length: libc::c_uint);

    fn PacketFreePacket(packet: *mut Packet);

    fn PacketReceivePacket(adapter: *mut Adapter, packet: *mut Packet, sync: BOOLEAN) -> BOOLEAN;

    fn PacketSetHwFilter(adapter: *mut Adapter, filter: libc::c_ulong) -> BOOLEAN;

    fn PacketGetAdapterNames(buf: *mut libc::c_char, buf_size: *mut libc::c_ulong);

    fn PacketGetNetInfoEx(
        adapter: *mut Adapter,
        buffer: *mut NpfIfAddr,
        n_entries: *mut libc::c_long,
    ) -> BOOLEAN;

    fn PacketRequest(adapter: *mut Adapter, set: BOOLEAN, oid_data: *mut PacketOidData) -> BOOLEAN;

    fn PacketGetReadEvent(adapter: *mut Adapter) -> HANDLE;

    // PacketSetDumpName, PacketSetDumpLimits and PacketIsDumpEnded are deprecated

    fn PacketStopDriver() -> BOOL;

    fn PacketStopDriver60() -> BOOL;

    fn PacketCloseAdapter(adapter: *mut Adapter);

    // PacketStartOem and PacketStartOemEx are deprecated WinPcap Pro functions

    // We don't define PAirpcapHandle
    // PacketGetAirPcapHandle: fn(adapter: *mut Adapter) -> PAirpcapHandle,
}

pub struct Npcap;

impl Npcap {
    pub fn new() -> io::Result<Self> {
        Ok(Self)
    }

    pub fn driver_version(&self) -> &CStr {
        unsafe { CStr::from_ptr(PacketGetDriverVersion() as *const i8) }
    }

    pub fn driver_name(&self) -> &CStr {
        unsafe { CStr::from_ptr(PacketGetDriverName() as *const i8) }
    }

    pub fn set_min_to_copy(&self, adapter: &mut Adapter, nbytes: libc::c_int) -> bool {
        unsafe {
            match PacketSetMinToCopy(adapter, nbytes) {
                0 => false,
                _ => true,
            }
        }
    }

    pub fn set_num_writes(&self, adapter: &mut Adapter, nwrites: libc::c_int) -> bool {
        unsafe {
            match PacketSetNumWrites(adapter, nwrites) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn set_mode(&self, adapter: &mut Adapter, mode: libc::c_int) -> bool {
        unsafe {
            match PacketSetMode(adapter, mode) {
                0 => false,
                _ => true,
            }
        }
    }

    pub fn set_read_timeout(&self, adapter: &mut Adapter, timeout: libc::c_int) -> bool {
        unsafe {
            match PacketSetReadTimeout(adapter, timeout) {
                0 => false,
                _ => true,
            }
        }
    }

    pub fn set_bpf(&self, adapter: &mut Adapter, program: &BpfProgram) -> bool {
        unsafe {
            match PacketSetBpf(adapter, program as *const BpfProgram) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn set_loopback_behavior(&self, adapter: &mut Adapter, behavior: libc::c_uint) -> bool {
        unsafe {
            match PacketSetLoopbackBehavior(adapter, behavior) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn set_timestamp_mode(&self, adapter: &mut Adapter, mode: libc::c_ulong) -> bool {
        unsafe {
            match PacketSetTimestampMode(adapter, mode) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn get_timestamp_modes(&self, adapter: &mut Adapter, modes: *mut libc::c_ulong) -> bool {
        unsafe {
            match PacketGetTimestampModes(adapter, modes) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn set_snaplen(&self, adapter: &mut Adapter, snaplen: libc::c_int) -> bool {
        unsafe {
            match PacketSetSnaplen(adapter, snaplen) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn get_stats(&self, adapter: &mut Adapter, stats: &mut BpfStat) -> bool {
        unsafe {
            match PacketGetStats(adapter, stats as *mut BpfStat) {
                0 => false,
                _ => true,
            }
        }
    }

    pub fn get_stats_ex(&self, adapter: &mut Adapter, stats: &mut BpfStat) -> bool {
        unsafe {
            match PacketGetStatsEx(adapter, stats as *mut BpfStat) {
                0 => false,
                _ => true,
            }
        }
    }

    pub fn set_buff(&self, adapter: &mut Adapter, dim: libc::c_int) -> bool {
        unsafe {
            match PacketSetBuff(adapter, dim) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn get_net_type(&self, adapter: &mut Adapter, ty: &mut NetType) -> bool {
        unsafe {
            match PacketGetNetType(adapter, ty as *mut NetType) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn is_loopback_adapter(&self, adapter_name: &CStr) -> bool {
        unsafe {
            match PacketIsLoopbackAdapter(adapter_name.as_ptr()) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn is_monitor_mode_supported(&self, adapter_name: &CStr) -> libc::c_int {
        unsafe { PacketIsMonitorModeSupported(adapter_name.as_ptr()) }
    }

    // TODO: adapter_name might be a *mut c_char, not *const
    pub fn set_monitor_mode(&self, adapter_name: &CStr, mode: libc::c_int) -> libc::c_int {
        unsafe { PacketSetMonitorMode(adapter_name.as_ptr(), mode) }
    }

    pub fn get_monitor_mode(&self, adapter_name: &CStr) -> libc::c_int {
        unsafe { PacketGetMonitorMode(adapter_name.as_ptr()) }
    }

    pub fn open_adapter(&self, adapter_name: &CStr) -> *mut Adapter {
        unsafe { PacketOpenAdapter(adapter_name.as_ptr()) }
    }

    pub fn send_packet(&self, adapter: &mut Adapter, packet: &mut Packet) -> bool {
        unsafe {
            match PacketSendPacket(adapter, packet as *mut Packet, 1) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn send_packets(&self, adapter: &mut Adapter, packets: &mut [Packet]) -> libc::c_int {
        // TODO: does this set the correct length?
        unsafe {
            PacketSendPackets(
                adapter,
                packets.as_mut_ptr() as *mut libc::c_void,
                packets.len() as u32,
                1,
            )
        }
    }

    pub fn allocate_packet(&self) -> *mut Packet {
        unsafe { PacketAllocatePacket() }
    }

    pub fn init_packet(&self, packet: &mut Packet, buffer: NonNull<u8>, buflen: usize) {
        unsafe {
            PacketInitPacket(
                packet,
                buffer.as_ptr() as *mut libc::c_void,
                buflen as libc::c_uint,
            )
        }
    }

    #[allow(unused)]
    pub fn free_packet(&self, packet: &mut Packet) {
        unsafe { PacketFreePacket(packet) }
    }

    pub fn receive_packet(&self, adapter: &mut Adapter, packet: &mut Packet) -> bool {
        unsafe {
            match PacketReceivePacket(adapter, packet, 1) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn set_hw_filter(&self, adapter: &mut Adapter, filter: libc::c_ulong) -> bool {
        unsafe {
            match PacketSetHwFilter(adapter, filter) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn get_adapter_names(&self, buf: &mut [u8], len: &mut libc::c_ulong) {
        unsafe {
            PacketGetAdapterNames(
                buf.as_mut_ptr() as *mut libc::c_char,
                len as *mut libc::c_ulong,
            )
        }
    }

    #[allow(unused)]
    pub fn get_net_info_ex(
        &self,
        adapter: &mut Adapter,
        addrs: &mut [NpfIfAddr],
        entries: &mut libc::c_long,
    ) -> bool {
        unsafe {
            match PacketGetNetInfoEx(adapter, addrs.as_mut_ptr(), entries as *mut libc::c_long) {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn get_request(
        &self,
        adapter: &mut Adapter,
        set: bool,
        oid_data: &mut PacketOidData,
    ) -> bool {
        let set = match set {
            true => 1,
            false => 0,
        };

        unsafe {
            match PacketRequest(adapter, set, oid_data as *mut PacketOidData) {
                0 => false,
                _ => true,
            }
        }
    }

    pub fn get_read_event(&self, adapter: &mut Adapter) -> HANDLE {
        unsafe { PacketGetReadEvent(adapter) }
    }

    #[allow(unused)]
    pub fn stop_driver(&self) -> bool {
        unsafe {
            match PacketStopDriver() {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub fn stop_driver_60(&self) -> bool {
        unsafe {
            match PacketStopDriver60() {
                0 => false,
                _ => true,
            }
        }
    }

    #[allow(unused)]
    pub unsafe fn close_adapter(&self, adapter: *mut Adapter) {
        unsafe { PacketCloseAdapter(adapter) }
    }
}
