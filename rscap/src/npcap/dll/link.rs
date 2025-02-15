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

    pub unsafe fn driver_version(&self) -> &CStr {
        CStr::from_ptr(PacketGetDriverVersion() as *const i8)
    }

    pub unsafe fn driver_name(&self) -> &CStr {
        CStr::from_ptr(PacketGetDriverName() as *const i8)
    }

    pub unsafe fn set_min_to_copy(&self, adapter: NonNull<Adapter>, nbytes: libc::c_int) -> bool {
        match PacketSetMinToCopy(adapter.as_ptr(), nbytes) {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn set_num_writes(&self, adapter: NonNull<Adapter>, nwrites: libc::c_int) -> bool {
        match PacketSetNumWrites(adapter.as_ptr(), nwrites) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn set_mode(&self, adapter: NonNull<Adapter>, mode: libc::c_int) -> bool {
        match PacketSetMode(adapter.as_ptr(), mode) {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn set_read_timeout(&self, adapter: NonNull<Adapter>, timeout: libc::c_int) -> bool {
        match PacketSetReadTimeout(adapter.as_ptr(), timeout) {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn set_bpf(&self, adapter: NonNull<Adapter>, program: &BpfProgram) -> bool {
        match PacketSetBpf(adapter.as_ptr(), program as *const BpfProgram) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn set_loopback_behavior(
        &self,
        adapter: NonNull<Adapter>,
        behavior: libc::c_uint,
    ) -> bool {
        match PacketSetLoopbackBehavior(adapter.as_ptr(), behavior) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn set_timestamp_mode(
        &self,
        adapter: NonNull<Adapter>,
        mode: libc::c_ulong,
    ) -> bool {
        match PacketSetTimestampMode(adapter.as_ptr(), mode) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn get_timestamp_modes(
        &self,
        adapter: NonNull<Adapter>,
        modes: *mut libc::c_ulong,
    ) -> bool {
        match PacketGetTimestampModes(adapter.as_ptr(), modes) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn set_snaplen(&self, adapter: NonNull<Adapter>, snaplen: libc::c_int) -> bool {
        match PacketSetSnaplen(adapter.as_ptr(), snaplen) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn get_stats(&self, adapter: NonNull<Adapter>, stats: &mut BpfStat) -> bool {
        match PacketGetStats(adapter.as_ptr(), stats as *mut BpfStat) {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn get_stats_ex(&self, adapter: NonNull<Adapter>, stats: &mut BpfStat) -> bool {
        match PacketGetStatsEx(adapter.as_ptr(), stats as *mut BpfStat) {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn set_buff(&self, adapter: NonNull<Adapter>, dim: libc::c_int) -> bool {
        match PacketSetBuff(adapter.as_ptr(), dim) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn get_net_type(&self, adapter: NonNull<Adapter>, ty: &mut NetType) -> bool {
        match PacketGetNetType(adapter.as_ptr(), ty as *mut NetType) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn is_loopback_adapter(&self, adapter_name: &CStr) -> bool {
        match PacketIsLoopbackAdapter(adapter_name.as_ptr()) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn is_monitor_mode_supported(&self, adapter_name: &CStr) -> libc::c_int {
        PacketIsMonitorModeSupported(adapter_name.as_ptr())
    }

    // TODO: adapter_name might be a *mut c_char, not *const
    pub unsafe fn set_monitor_mode(&self, adapter_name: &CStr, mode: libc::c_int) -> libc::c_int {
        PacketSetMonitorMode(adapter_name.as_ptr(), mode)
    }

    pub unsafe fn get_monitor_mode(&self, adapter_name: &CStr) -> libc::c_int {
        PacketGetMonitorMode(adapter_name.as_ptr())
    }

    pub unsafe fn open_adapter(&self, adapter_name: &CStr) -> Option<NonNull<Adapter>> {
        NonNull::new(PacketOpenAdapter(adapter_name.as_ptr()))
    }

    pub unsafe fn send_packet(&self, adapter: NonNull<Adapter>, packet: NonNull<Packet>) -> bool {
        match PacketSendPacket(adapter.as_ptr(), packet.as_ptr(), 1) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn send_packets(
        &self,
        adapter: NonNull<Adapter>,
        packets: &mut [Packet],
    ) -> libc::c_int {
        // TODO: does this set the correct length?
        PacketSendPackets(
            adapter.as_ptr(),
            packets.as_mut_ptr() as *mut libc::c_void,
            packets.len() as u32,
            1,
        )
    }

    pub unsafe fn allocate_packet(&self) -> Option<NonNull<Packet>> {
        NonNull::new(PacketAllocatePacket())
    }

    pub unsafe fn init_packet(&self, packet: NonNull<Packet>, buffer: NonNull<u8>, buflen: usize) {
        PacketInitPacket(
            packet.as_ptr(),
            buffer.as_ptr() as *mut libc::c_void,
            buflen as libc::c_uint,
        )
    }

    #[allow(unused)]
    pub unsafe fn free_packet(&self, packet: NonNull<Packet>) {
        PacketFreePacket(packet.as_ptr())
    }

    pub unsafe fn receive_packet(
        &self,
        adapter: NonNull<Adapter>,
        packet: NonNull<Packet>,
    ) -> bool {
        match PacketReceivePacket(adapter.as_ptr(), packet.as_ptr(), 1) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn set_hw_filter(&self, adapter: NonNull<Adapter>, filter: libc::c_ulong) -> bool {
        match PacketSetHwFilter(adapter.as_ptr(), filter) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn get_adapter_names(&self, buf: &mut [u8], len: &mut libc::c_ulong) {
        PacketGetAdapterNames(
            buf.as_mut_ptr() as *mut libc::c_char,
            len as *mut libc::c_ulong,
        )
    }

    #[allow(unused)]
    pub unsafe fn get_net_info_ex(
        &self,
        adapter: NonNull<Adapter>,
        addrs: &mut [NpfIfAddr],
        entries: &mut libc::c_long,
    ) -> bool {
        match PacketGetNetInfoEx(
            adapter.as_ptr(),
            addrs.as_mut_ptr(),
            entries as *mut libc::c_long,
        ) {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn get_request(
        &self,
        adapter: NonNull<Adapter>,
        set: bool,
        oid_data: NonNull<PacketOidData>,
    ) -> bool {
        let set = match set {
            true => 1,
            false => 0,
        };

        match PacketRequest(adapter.as_ptr(), set, oid_data.as_ptr()) {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn get_read_event(&self, adapter: NonNull<Adapter>) -> HANDLE {
        PacketGetReadEvent(adapter.as_ptr())
    }

    #[allow(unused)]
    pub unsafe fn stop_driver(&self) -> bool {
        match PacketStopDriver() {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn stop_driver_60(&self) -> bool {
        match PacketStopDriver60() {
            0 => false,
            _ => true,
        }
    }

    #[allow(unused)]
    pub unsafe fn close_adapter(&self, adapter: NonNull<Adapter>) {
        PacketCloseAdapter(adapter.as_ptr())
    }
}
