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

use std::mem;
use std::ptr::NonNull;
use std::{ffi::CStr, io};

use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::{BOOL, BOOLEAN, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

use crate::filter::BpfProgram;

use super::{Adapter, BpfStat, NetType, NpfIfAddr, Packet, PacketOidData};

const NPCAP_LIB: *const u8 = b"Packet.dll\0".as_ptr();

pub struct Npcap {
    container: NpcapApi,
}

struct NpcapApi {
    PacketGetDriverVersion: unsafe extern "C" fn() -> PCSTR,
    PacketGetDriverName: unsafe extern "C" fn() -> PCSTR,
    PacketSetMinToCopy: unsafe extern "C" fn(adapter: *mut Adapter, nbytes: libc::c_int) -> BOOLEAN,
    PacketSetNumWrites:
        unsafe extern "C" fn(adapter: *mut Adapter, nwrites: libc::c_int) -> BOOLEAN,
    PacketSetMode: unsafe extern "C" fn(adapter: *mut Adapter, mode: libc::c_int) -> BOOLEAN,
    PacketSetReadTimeout:
        unsafe extern "C" fn(adapter: *mut Adapter, timeout: libc::c_int) -> BOOLEAN,
    PacketSetBpf: unsafe extern "C" fn(adapter: *mut Adapter, fp: *const BpfProgram) -> BOOLEAN,
    PacketSetLoopbackBehavior:
        unsafe extern "C" fn(adapter: *mut Adapter, behavior: libc::c_uint) -> BOOLEAN,
    PacketSetTimestampMode:
        unsafe extern "C" fn(adapter: *mut Adapter, mode: libc::c_ulong) -> BOOLEAN,
    PacketGetTimestampModes:
        unsafe extern "C" fn(adapter: *mut Adapter, p_modes: *mut libc::c_ulong) -> BOOLEAN,
    PacketSetSnaplen:
        unsafe extern "C" fn(adapter: *mut Adapter, snaplen: libc::c_int) -> libc::c_int,
    PacketGetStats: unsafe extern "C" fn(adapter: *mut Adapter, stats: *mut BpfStat) -> BOOLEAN,
    PacketGetStatsEx: unsafe extern "C" fn(adapter: *mut Adapter, stats: *mut BpfStat) -> BOOLEAN,
    PacketSetBuff: unsafe extern "C" fn(adapter: *mut Adapter, dim: libc::c_int) -> BOOLEAN,
    PacketGetNetType: unsafe extern "C" fn(adapter: *mut Adapter, ty: *mut NetType) -> BOOLEAN,
    PacketIsLoopbackAdapter: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> BOOLEAN,
    PacketIsMonitorModeSupported:
        unsafe extern "C" fn(adapter_name: *const libc::c_char) -> libc::c_int,
    PacketSetMonitorMode:
        unsafe extern "C" fn(adapter_name: *const libc::c_char, mode: libc::c_int) -> libc::c_int,
    PacketGetMonitorMode: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> libc::c_int,
    PacketOpenAdapter: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> *mut Adapter,
    PacketSendPacket:
        unsafe extern "C" fn(adapter: *mut Adapter, packet: *mut Packet, sync: BOOLEAN) -> BOOLEAN,
    PacketSendPackets: unsafe extern "C" fn(
        adapter: *mut Adapter,
        packet_buf: *mut libc::c_void,
        size: libc::c_ulong,
        sync: BOOLEAN,
    ) -> libc::c_int,
    PacketAllocatePacket: unsafe extern "C" fn() -> *mut Packet,
    PacketInitPacket:
        unsafe extern "C" fn(packet: *mut Packet, buffer: *mut libc::c_void, length: libc::c_uint),
    PacketFreePacket: unsafe extern "C" fn(packet: *mut Packet),
    PacketReceivePacket:
        unsafe extern "C" fn(adapter: *mut Adapter, packet: *mut Packet, sync: BOOLEAN) -> BOOLEAN,
    PacketSetHwFilter:
        unsafe extern "C" fn(adapter: *mut Adapter, filter: libc::c_ulong) -> BOOLEAN,
    PacketGetAdapterNames:
        unsafe extern "C" fn(buf: *mut libc::c_char, buf_size: *mut libc::c_ulong),
    PacketGetNetInfoEx: unsafe extern "C" fn(
        adapter: *mut Adapter,
        buffer: *mut NpfIfAddr,
        n_entries: *mut libc::c_long,
    ) -> BOOLEAN,
    PacketRequest: unsafe extern "C" fn(
        adapter: *mut Adapter,
        set: BOOLEAN,
        oid_data: *mut PacketOidData,
    ) -> BOOLEAN,
    PacketGetReadEvent: unsafe extern "C" fn(adapter: *mut Adapter) -> HANDLE,
    // PacketSetDumpName, PacketSetDumpLimits and PacketIsDumpEnded are deprecated
    PacketStopDriver: unsafe extern "C" fn() -> BOOL,
    PacketStopDriver60: unsafe extern "C" fn() -> BOOL,
    PacketCloseAdapter: unsafe extern "C" fn(adapter: *mut Adapter),
    // PacketStartOem and PacketStartOemEx are deprecated WinPcap Pro functions
    // We don't define PAirpcapHandle
    // PacketGetAirPcapHandle: fn(adapter: *mut Adapter) -> PAirpcapHandle,
}

impl Npcap {
    ///
    ///
    /// # Safety
    ///
    /// This function must be supplied a null-terminated `func_name`.
    ///
    /// This function must only be used for creating function pointer types.
    unsafe fn resolve_func(
        lib: *mut libc::c_void,
        func_name: &[u8],
    ) -> io::Result<*const libc::c_void> {
        GetProcAddress(lib, func_name.as_ptr())
            .ok_or(io::Error::last_os_error())
            .map(|f| f as *const libc::c_void)
    }

    unsafe fn resolve_api(lib: *mut libc::c_void) -> io::Result<NpcapApi> {
        Ok(NpcapApi {
            PacketGetDriverVersion: mem::transmute(Self::resolve_func(
                lib,
                b"PacketGetDriverVersion\0",
            )?),
            PacketGetDriverName: mem::transmute(Self::resolve_func(lib, b"PacketGetDriverName\0")?),
            PacketSetMinToCopy: mem::transmute(Self::resolve_func(lib, b"PacketSetMinToCopy\0")?),
            PacketSetNumWrites: mem::transmute(Self::resolve_func(lib, b"PacketSetNumWrites\0")?),
            PacketSetMode: mem::transmute(Self::resolve_func(lib, b"PacketSetMode\0")?),
            PacketSetReadTimeout: mem::transmute(Self::resolve_func(
                lib,
                b"PacketSetReadTimeout\0",
            )?),
            PacketSetBpf: mem::transmute(Self::resolve_func(lib, b"PacketSetBpf\0")?),
            PacketSetLoopbackBehavior: mem::transmute(Self::resolve_func(
                lib,
                b"PacketSetLoopbackBehavior\0",
            )?),
            PacketSetTimestampMode: mem::transmute(Self::resolve_func(
                lib,
                b"PacketSetTimestampMode\0",
            )?),
            PacketGetTimestampModes: mem::transmute(Self::resolve_func(
                lib,
                b"PacketGetTimestampModes\0",
            )?),
            PacketSetSnaplen: mem::transmute(Self::resolve_func(lib, b"PacketSetSnaplen\0")?),
            PacketGetStats: mem::transmute(Self::resolve_func(lib, b"PacketGetStats\0")?),
            PacketGetStatsEx: mem::transmute(Self::resolve_func(lib, b"PacketGetStatsEx\0")?),
            PacketSetBuff: mem::transmute(Self::resolve_func(lib, b"PacketSetBuff\0")?),
            PacketGetNetType: mem::transmute(Self::resolve_func(lib, b"PacketGetNetType\0")?),
            PacketIsLoopbackAdapter: mem::transmute(Self::resolve_func(
                lib,
                b"PacketIsLoopbackAdapter\0",
            )?),
            PacketIsMonitorModeSupported: mem::transmute(Self::resolve_func(
                lib,
                b"PacketIsMonitorModeSupported\0",
            )?),
            PacketSetMonitorMode: mem::transmute(Self::resolve_func(
                lib,
                b"PacketSetMonitorMode\0",
            )?),
            PacketGetMonitorMode: mem::transmute(Self::resolve_func(
                lib,
                b"PacketGetMonitorMode\0",
            )?),
            PacketOpenAdapter: mem::transmute(Self::resolve_func(lib, b"PacketOpenAdapter\0")?),
            PacketSendPacket: mem::transmute(Self::resolve_func(lib, b"PacketSendPacket\0")?),
            PacketSendPackets: mem::transmute(Self::resolve_func(lib, b"PacketSendPackets\0")?),
            PacketAllocatePacket: mem::transmute(Self::resolve_func(
                lib,
                b"PacketAllocatePacket\0",
            )?),
            PacketInitPacket: mem::transmute(Self::resolve_func(lib, b"PacketInitPacket\0")?),
            PacketFreePacket: mem::transmute(Self::resolve_func(lib, b"PacketFreePacket\0")?),
            PacketReceivePacket: mem::transmute(Self::resolve_func(lib, b"PacketReceivePacket\0")?),
            PacketSetHwFilter: mem::transmute(Self::resolve_func(lib, b"PacketSetHwFilter\0")?),
            PacketGetAdapterNames: mem::transmute(Self::resolve_func(
                lib,
                b"PacketGetAdapterNames\0",
            )?),
            PacketGetNetInfoEx: mem::transmute(Self::resolve_func(lib, b"PacketGetNetInfoEx\0")?),
            PacketRequest: mem::transmute(Self::resolve_func(lib, b"PacketRequest\0")?),
            PacketGetReadEvent: mem::transmute(Self::resolve_func(lib, b"PacketGetReadEvent\0")?),
            PacketStopDriver: mem::transmute(Self::resolve_func(lib, b"PacketStopDriver\0")?),
            PacketStopDriver60: mem::transmute(Self::resolve_func(lib, b"PacketStopDriver60\0")?),
            PacketCloseAdapter: mem::transmute(Self::resolve_func(lib, b"PacketCloseAdapter\0")?),
        })
    }

    pub fn new() -> io::Result<Self> {
        unsafe {
            let lib = LoadLibraryA(NPCAP_LIB);
            if lib.is_null() {
                return Err(io::Error::last_os_error());
            }

            let api = Self::resolve_api(lib)?;

            Ok(Self { container: api })
        }
    }

    pub fn driver_version(&self) -> &CStr {
        unsafe { CStr::from_ptr((self.container.PacketGetDriverVersion)() as *const i8) }
    }

    pub fn driver_name(&self) -> &CStr {
        unsafe { CStr::from_ptr((self.container.PacketGetDriverName)() as *const i8) }
    }

    pub fn set_min_to_copy(&self, adapter: &mut Adapter, nbytes: libc::c_int) -> bool {
        match unsafe { (self.container.PacketSetMinToCopy)(adapter, nbytes) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_num_writes(&self, adapter: &mut Adapter, nwrites: libc::c_int) -> bool {
        match unsafe { (self.container.PacketSetNumWrites)(adapter, nwrites) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_mode(&self, adapter: &mut Adapter, mode: libc::c_int) -> bool {
        match unsafe { (self.container.PacketSetMode)(adapter, mode) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_read_timeout(&self, adapter: &mut Adapter, timeout: libc::c_int) -> bool {
        match unsafe { (self.container.PacketSetReadTimeout)(adapter, timeout) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_bpf(&self, adapter: &mut Adapter, program: &BpfProgram) -> bool {
        match unsafe { (self.container.PacketSetBpf)(adapter, program as *const BpfProgram) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_loopback_behavior(&self, adapter: &mut Adapter, behavior: libc::c_uint) -> bool {
        match unsafe { (self.container.PacketSetLoopbackBehavior)(adapter, behavior) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_timestamp_mode(&self, adapter: &mut Adapter, mode: libc::c_ulong) -> bool {
        match unsafe { (self.container.PacketSetTimestampMode)(adapter, mode) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_timestamp_modes(&self, adapter: &mut Adapter, modes: *mut libc::c_ulong) -> bool {
        match unsafe { (self.container.PacketGetTimestampModes)(adapter, modes) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_snaplen(&self, adapter: &mut Adapter, snaplen: libc::c_int) -> bool {
        match unsafe { (self.container.PacketSetSnaplen)(adapter, snaplen) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_stats(&self, adapter: &mut Adapter, stats: &mut BpfStat) -> bool {
        match unsafe { (self.container.PacketGetStats)(adapter, stats as *mut BpfStat) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_stats_ex(&self, adapter: &mut Adapter, stats: &mut BpfStat) -> bool {
        match unsafe { (self.container.PacketGetStatsEx)(adapter, stats as *mut BpfStat) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_buff(&self, adapter: &mut Adapter, dim: libc::c_int) -> bool {
        match unsafe { (self.container.PacketSetBuff)(adapter, dim) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_net_type(&self, adapter: &mut Adapter, ty: &mut NetType) -> bool {
        match unsafe { (self.container.PacketGetNetType)(adapter, ty as *mut NetType) } {
            0 => false,
            _ => true,
        }
    }

    pub fn is_loopback_adapter(&self, adapter_name: &CStr) -> bool {
        match unsafe { (self.container.PacketIsLoopbackAdapter)(adapter_name.as_ptr()) } {
            0 => false,
            _ => true,
        }
    }

    pub fn is_monitor_mode_supported(&self, adapter_name: &CStr) -> libc::c_int {
        unsafe { (self.container.PacketIsMonitorModeSupported)(adapter_name.as_ptr()) }
    }

    pub fn set_monitor_mode(&self, adapter_name: &CStr, mode: libc::c_int) -> libc::c_int {
        unsafe { (self.container.PacketSetMonitorMode)(adapter_name.as_ptr(), mode) }
    }

    pub fn get_monitor_mode(&self, adapter_name: &CStr) -> libc::c_int {
        unsafe { (self.container.PacketGetMonitorMode)(adapter_name.as_ptr()) }
    }

    pub fn open_adapter(&self, adapter_name: &CStr) -> *mut Adapter {
        unsafe { (self.container.PacketOpenAdapter)(adapter_name.as_ptr()) }
    }

    pub fn send_packet(&self, adapter: &mut Adapter, packet: &mut Packet) -> bool {
        match unsafe { (self.container.PacketSendPacket)(adapter, packet as *mut Packet, 1) } {
            0 => false,
            _ => true,
        }
    }

    pub fn send_packets(&self, adapter: &mut Adapter, packets: &mut [Packet]) -> libc::c_int {
        let packets_ptr = packets.as_mut_ptr() as *mut libc::c_void;
        let packets_len = packets.len() as u32;

        // TODO: does this set the correct length?
        unsafe { (self.container.PacketSendPackets)(adapter, packets_ptr, packets_len, 1) }
    }

    pub fn allocate_packet(&self) -> *mut Packet {
        unsafe { (self.container.PacketAllocatePacket)() }
    }

    pub fn init_packet(&self, packet: &mut Packet, buffer: NonNull<u8>, buflen: usize) {
        let buffer_ptr = buffer.as_ptr() as *mut libc::c_void;
        let buffer_len = buflen as libc::c_uint;

        unsafe { (self.container.PacketInitPacket)(packet, buffer_ptr, buffer_len) }
    }

    pub fn free_packet(&self, packet: &mut Packet) {
        unsafe { (self.container.PacketFreePacket)(packet) }
    }

    pub fn receive_packet(&self, adapter: &mut Adapter, packet: &mut Packet) -> bool {
        match unsafe { (self.container.PacketReceivePacket)(adapter, packet as *mut Packet, 1) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_hw_filter(&self, adapter: &mut Adapter, filter: libc::c_ulong) -> bool {
        match unsafe { (self.container.PacketSetHwFilter)(adapter, filter) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_adapter_names(&self, buf: &mut [u8], len: &mut libc::c_ulong) {
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_char;
        let buflen_ptr = len as *mut libc::c_ulong;

        unsafe { (self.container.PacketGetAdapterNames)(buf_ptr, buflen_ptr) }
    }

    pub fn get_net_info_ex(
        &self,
        adapter: &mut Adapter,
        addrs: &mut [NpfIfAddr],
        entries: &mut libc::c_long,
    ) -> bool {
        let addrs_ptr = addrs.as_mut_ptr();
        let entries_ptr = entries as *mut libc::c_long;

        match unsafe { (self.container.PacketGetNetInfoEx)(adapter, addrs_ptr, entries_ptr) } {
            0 => false,
            _ => true,
        }
    }

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

        match unsafe { (self.container.PacketRequest)(adapter, set, oid_data) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_read_event(&self, adapter: &mut Adapter) -> HANDLE {
        unsafe { (self.container.PacketGetReadEvent)(adapter) }
    }

    pub fn stop_driver(&self) -> bool {
        match unsafe { (self.container.PacketStopDriver)() } {
            0 => false,
            _ => true,
        }
    }

    pub fn stop_driver_60(&self) -> bool {
        match unsafe { (self.container.PacketStopDriver60)() } {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn close_adapter(&self, adapter: *mut Adapter) {
        (self.container.PacketCloseAdapter)(adapter)
    }
}
