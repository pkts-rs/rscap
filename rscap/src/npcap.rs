// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (Windows) npcap packet capture and transmission interface.
//!

// RSCAP_NPCAP_PATH:
// C:\Windows\System32\Npcap\Packet.dll
// Associated with Packet32.h

mod dll;

use std::error::Error;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED, ERROR_BAD_UNIT};
use windows_sys::Win32::Networking::WinSock::{
    WSACleanup, WSAStartup, WSADATA, WSAEPROCLIM, WSASYSNOTREADY, WSAVERNOTSUPPORTED,
};

use dll::{Adapter, BpfStat, Npcap, PACKET_MODE_CAPT, PACKET_MODE_STAT};

use crate::filter::PacketStatistics;
use crate::Interface;

const WSA_VERSION: u16 = 0x0202;

#[derive(Clone, Copy, Debug)]
pub enum NpcapMode {
    Capture,
    Statistic,
}

#[derive(Debug)]
pub struct NpcapError {
    kind: NpcapErrorKind,
    error: Option<Box<dyn Error + Send + Sync>>,
}

impl NpcapError {
    pub fn new<E>(kind: NpcapErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            error: Some(error.into()),
        }
    }

    pub fn kind(&self) -> NpcapErrorKind {
        self.kind
    }

    pub fn get_ref(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
        self.error.as_deref()
    }
}

impl From<NpcapErrorKind> for NpcapError {
    fn from(value: NpcapErrorKind) -> Self {
        Self {
            kind: value,
            error: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum NpcapErrorKind {
    /// The dynamic library used for interfacing with npcap could not be found.
    DllNotFound,
    /// An expected function or global variable was missing from the npcap dynamic library.
    MissingDllSymbol,
    /// An invalid value was used for a method call (such as an oversized or negative length
    /// value).
    InvalidValue,
    /// The npcap driver failed to carry out a given operation for an unspecified reason.
    OperationFailed,
    /// The Windows network subsystem was not ready for network communication.
    NetworkNotReady,
    /// The WSA version of the Windows system was too old for npcap.
    UnsupportedSystem,
    /// The desired packet capture mode (such as monitor mode) is not supported by the interface.
    UnsupportedMode,
    /// A limit on the number of tasks supported by the Windows Sockets implementation has
    /// sbeen reached.
    ProcessLimit,
    /// An unexpected internal error occurred in the library. This should be reported for triage.
    Internal,
    /// The interface name specified did not correspond to an active network interface on the
    /// system.
    InvalidInterface,
    /// An interface was active, but access was denied when attempting to open it.
    PermissionDenied,
}

#[derive(Clone, Copy, Debug)]
pub enum NpcapTimeout {
    /// A call to `read()` will return immediately if no packets are ready.
    Immediate,
    /// A call to `read()` will wait for up to the specified number of milliseconds for a packet
    /// to arrive before returning.
    Milliseconds(u32),
    /// Calls to `read()` will never time out
    None,
}

pub struct L2Socket {
    npcap: Npcap,
    adapter: NonNull<Adapter>,
    iface: Interface,
}

impl L2Socket {
    pub const DEFAULT_DRIVER_BUFFER: usize = 1024 * 1024 * 1024; // Default buffer of 1MB (similar to libpcap)

    pub fn new(iface: Interface) -> Result<Self, NpcapError> {
        let mut wsa_data: MaybeUninit<WSADATA> = MaybeUninit::uninit();

        unsafe {
            match WSAStartup(WSA_VERSION, ptr::addr_of_mut!(wsa_data) as *mut WSADATA) {
                0 => (),
                WSASYSNOTREADY => return Err(NpcapErrorKind::NetworkNotReady.into()),
                WSAVERNOTSUPPORTED => return Err(NpcapErrorKind::UnsupportedSystem.into()),
                WSAEPROCLIM => return Err(NpcapErrorKind::ProcessLimit.into()),
                e => {
                    return Err(NpcapError::new(
                        NpcapErrorKind::Internal,
                        format!("WSAStartup() returned error value {}", e),
                    ))
                }
            }
        }

        let npcap = Npcap::new()?;

        let adapter = match NonNull::new(npcap.open_adapter(iface.name())) {
            None => {
                return Err(match unsafe { GetLastError() } {
                    ERROR_BAD_UNIT => NpcapErrorKind::InvalidInterface.into(),
                    ERROR_ACCESS_DENIED => NpcapErrorKind::PermissionDenied.into(),
                    e => NpcapError::new(
                        NpcapErrorKind::Internal,
                        format!("unspecified error {} in opening npcap adapter", e),
                    ),
                })
            }
            Some(p) => p,
        };

        let mut socket = Self {
            npcap,
            adapter,
            iface,
        };

        socket.set_driver_buffer(Self::DEFAULT_DRIVER_BUFFER)?;

        Ok(socket)
    }

    /// Retrieves the name of the npcap driver.
    ///
    /// As Winpcap uses a very similar API to npcap, this function is useful in disambiguating
    /// the one from the other.
    #[inline]
    pub fn driver_name(&self) -> &CStr {
        self.npcap.driver_name()
    }

    /// Retrieves the version of the npcap driver.
    #[inline]
    pub fn driver_version(&self) -> &CStr {
        self.npcap.driver_version()
    }

    /// Indicates whether monitor mode is enabled for the associated network interface.
    pub fn monitor_mode(&self) -> bool {
        self.npcap.get_monitor_mode(self.iface.name()) == 1
    }

    pub fn set_monitor_mode(&self, enabled: bool) -> Result<(), NpcapError> {
        let enabled = match enabled {
            true => 1,
            false => 0,
        };

        match self.npcap.set_monitor_mode(self.iface.name(), enabled) {
            1 => Ok(()),
            0 => Err(NpcapErrorKind::UnsupportedMode.into()),
            error => Err(NpcapError::new(
                NpcapErrorKind::OperationFailed,
                format!("setting monitor mode failed with error {}", error),
            )),
        }
    }

    pub fn packet_stats(&mut self) -> Result<PacketStatistics, NpcapError> {
        let mut stat = BpfStat {
            bs_recv: 0,
            bs_drop: 0,
            ps_ifdrop: 0,
            bs_capt: 0,
        };

        match self
            .npcap
            .get_stats_ex(unsafe { self.adapter.as_mut() }, &mut stat)
        {
            true => Ok(PacketStatistics {
                received: stat.bs_recv,
                dropped: stat.bs_drop,
            }),
            false => Err(NpcapErrorKind::OperationFailed.into()),
        }
    }

    /// Sets the size of the buffer used by the npcap driver to queue packets for the socket.
    pub fn set_driver_buffer(&mut self, buffer_size: usize) -> Result<(), NpcapError> {
        let buffer_size = libc::c_int::try_from(buffer_size)
            .map_err(|_| NpcapError::from(NpcapErrorKind::InvalidValue))?;
        match self
            .npcap
            .set_buff(unsafe { self.adapter.as_mut() }, buffer_size)
        {
            true => Ok(()),
            false => Err(NpcapErrorKind::OperationFailed.into()),
        }
    }

    /// Defines the minimum amount of data npcap driver that will cause a `recv()` to return.
    pub fn set_min_to_copy(&mut self, copy_bytes: usize) -> Result<(), NpcapError> {
        let copy_bytes = libc::c_int::try_from(copy_bytes)
            .map_err(|_| NpcapError::from(NpcapErrorKind::InvalidValue))?;
        match self
            .npcap
            .set_min_to_copy(unsafe { self.adapter.as_mut() }, copy_bytes)
        {
            true => Ok(()),
            false => Err(NpcapErrorKind::OperationFailed.into()),
        }
    }

    /// Configures the number of times a packet written to the interface via `send()` will b
    /// repeated.
    pub fn set_repeat_send(&mut self, num_repeats: u32) -> Result<(), NpcapError> {
        let num_repeats = libc::c_int::try_from(num_repeats)
            .map_err(|_| NpcapError::from(NpcapErrorKind::InvalidValue))?;

        match self
            .npcap
            .set_num_writes(unsafe { self.adapter.as_mut() }, num_repeats)
        {
            true => Ok(()),
            false => Err(NpcapErrorKind::OperationFailed.into()),
        }
    }

    /*
    /// Sets the capture mode of the interface.
    ///
    /// By default, the capture mode is set to `NpcapMode::Capture`.
    pub fn set_mode(&self, mode: NpcapMode) -> Result<(), NpcapError> {
        let mode_int = match mode {
            NpcapMode::Capture => PACKET_MODE_CAPT,
            NpcapMode::Statistic => PACKET_MODE_STAT,
        };

        match self.npcap.set_mode(self.adapter.as_ptr(), mode_int) {
            true => Ok(()),
            false => Err(NpcapError::new(NpcapErrorKind::UnsupportedMode, format!("failed to set npcap mode to {}", mode_int))),
        }
    }
    */

    /// Sets the value of the read timeout associated with the socket.
    ///
    /// `timeout` indicates how long the socket will wait to receive a packet before returning.
    pub fn set_timeout(&mut self, timeout: NpcapTimeout) -> Result<(), NpcapError> {
        let timeout = match timeout {
            NpcapTimeout::None => -1,
            NpcapTimeout::Immediate => 0,
            NpcapTimeout::Milliseconds(ms) => libc::c_int::try_from(ms)
                .map_err(|_| NpcapError::from(NpcapErrorKind::InvalidValue))?,
        };

        match self
            .npcap
            .set_read_timeout(unsafe { self.adapter.as_mut() }, timeout)
        {
            true => Ok(()),
            false => Err(NpcapErrorKind::OperationFailed.into()),
        }
    }

    pub fn send(&self, packet: &[u8]) -> Result<(), NpcapError> {
        todo!()
    }

    pub fn recv(&self, packet: &mut [u8]) -> Result<usize, NpcapError> {
        todo!()
    }
}

impl Drop for L2Socket {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}
