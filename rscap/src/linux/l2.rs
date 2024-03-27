use std::{io, mem, os::fd::AsRawFd, ptr};

use super::addr::{L2Addr, L2AddrAny};
use super::mapped::{
    BlockConfig, FrameIndex, OsiLayer, PacketRxRing, PacketTxRing, RxFrame, TxFrame, TxFrameVariant,
};
use super::{PacketStatistics, RxTimestamping, TxTimestamping};

pub struct L2Socket {
    fd: i32,
}

impl L2Socket {
    /// Create a new Link-Layer socket.
    ///
    /// By default, L2 sockets do not listen or receive packets on any protocol or interface; to begin receiving packets, call [`L2Socket::bind()`].
    ///
    /// # Permissions
    ///
    /// A program must have the `CAP_NET_RAW` capability in order for this call to succeed;
    /// otherwise, `EPERM` will be returned.
    pub fn new() -> io::Result<L2Socket> {
        // Set the socket to receive no packets by default (protocol: 0)
        match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) } {
            ..=-1 => Err(std::io::Error::last_os_error()),
            fd => Ok(L2Socket { fd }),
        }
    }

    /// Bind a Link-Layer socket to a particular protocol/address and interface and begin
    /// receiving packets.
    pub fn bind<A: L2Addr>(&self, addr: A) -> io::Result<()> {
        let sockaddr = addr.to_sockaddr();

        match unsafe {
            libc::bind(
                self.fd,
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Configures the given socket's behavior when blocking would occur for calls to [`send()`](L2Socket::send()).
    ///
    /// If `nonblocking` is set to true, the socket will return immediate
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut fl = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            ..=-1 => return Err(io::Error::last_os_error()),
            f => f,
        };

        if nonblocking {
            fl |= libc::O_NONBLOCK;
        } else {
            fl &= !libc::O_NONBLOCK;
        }

        match unsafe { libc::fcntl(self.fd, libc::F_SETFL, fl) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn set_qdisc_bypass(&self, bypass: bool) -> io::Result<()> {
        let bypass_req = if bypass { 1u32 } else { 0u32 };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_QDISC_BYPASS,
                ptr::addr_of!(bypass_req) as *const libc::c_void,
                mem::size_of::<u32>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    #[inline]
    pub fn packet_stats(&self) -> io::Result<PacketStatistics> {
        let mut stats = libc::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };

        let mut stats_len = mem::size_of::<libc::tpacket_stats>() as u32;

        if unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                ptr::addr_of_mut!(stats) as *mut libc::c_void,
                ptr::addr_of_mut!(stats_len),
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }
        debug_assert!(stats_len == mem::size_of::<libc::tpacket_stats>() as u32);

        Ok(PacketStatistics {
            packets_seen: stats.tp_packets as usize,
            packets_dropped: stats.tp_drops as usize,
        })
    }

    /// Get the link-layer address the socket is currently bound to.
    pub fn bound_addr(&self) -> io::Result<L2AddrAny> {
        let mut sockaddr = libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };
        let mut sockaddr_len = mem::size_of::<libc::sockaddr_ll>() as u32;

        let res = unsafe {
            libc::getsockname(
                self.fd,
                ptr::addr_of_mut!(sockaddr) as *mut libc::sockaddr,
                ptr::addr_of_mut!(sockaddr_len),
            )
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        if sockaddr_len != mem::size_of::<libc::sockaddr_ll>() as u32
            || sockaddr.sll_family != libc::AF_PACKET as u16
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "bound address was not of type sockaddr_ll",
            ));
        }

        L2AddrAny::try_from(sockaddr).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "returned address did not match requested type",
            )
        })
    }

    /// Determines the source of timestamp information for TX_RING/RX_RING packets.
    /// If `true`, this option requests that the operating system use hardware timestamps
    /// provided by the NIC.
    ///
    /// NOTE: for hardware timestamping to be employed, the socket must be bound to an interface.
    ///
    /// # Errors
    ///
    /// `ERANGE` - the requested packets cannot be timestamped by hardware.
    ///
    /// `EINVAL` - hardware timestamping is not supported by the network card.
    pub fn set_timestamp_method(&self, tx: TxTimestamping, rx: RxTimestamping) -> io::Result<()> {
        if tx == TxTimestamping::Hardware || rx == RxTimestamping::Hardware {
            let mut hwtstamp_config = libc::hwtstamp_config {
                flags: 0,
                tx_type: if tx == TxTimestamping::Hardware {
                    libc::HWTSTAMP_TX_ON
                } else {
                    libc::HWTSTAMP_TX_OFF
                } as i32,
                rx_filter: if rx == RxTimestamping::Hardware {
                    libc::HWTSTAMP_FILTER_ALL
                } else {
                    libc::HWTSTAMP_FILTER_NONE
                } as i32,
            };

            let addr = self.bound_addr()?;

            let mut if_name = [0i8; libc::IF_NAMESIZE];
            let if_name_ptr = if_name.as_mut_ptr();

            let res = unsafe { libc::if_indextoname(addr.interface().index(), if_name_ptr) };
            if res == ptr::null_mut() {
                return Err(io::Error::last_os_error());
            }

            let mut ifreq = libc::ifreq {
                ifr_name: if_name,
                ifr_ifru: libc::__c_anonymous_ifr_ifru {
                    ifru_data: ptr::addr_of_mut!(hwtstamp_config) as *mut i8,
                },
            };

            let res =
                unsafe { libc::ioctl(self.fd, libc::SIOCSHWTSTAMP, ptr::addr_of_mut!(ifreq)) };
            if res != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let timestamp_req = match tx {
            TxTimestamping::Hardware => libc::SOF_TIMESTAMPING_TX_HARDWARE,
            TxTimestamping::Software => libc::SOF_TIMESTAMPING_TX_SOFTWARE,
            TxTimestamping::Sched => libc::SOF_TIMESTAMPING_TX_SCHED,
        } | match rx {
            RxTimestamping::Hardware => libc::SOF_TIMESTAMPING_RX_HARDWARE,
            RxTimestamping::Software => libc::SOF_TIMESTAMPING_RX_SOFTWARE,
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_TIMESTAMP,
                ptr::addr_of!(timestamp_req) as *const libc::c_void,
                mem::size_of::<libc::tpacket_versions>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Send a datagram over the socket.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match unsafe { libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            sent => Ok(sent as usize),
        }
    }

    /// Receive a datagram from the socket.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// TODO: add addr
    pub fn send_to<A: L2Addr>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        let sockaddr = addr.to_sockaddr();
        let addrlen = mem::size_of::<libc::sockaddr_ll>() as u32;

        match unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                ptr::addr_of!(sockaddr) as *const libc::sockaddr,
                addrlen,
            )
        } {
            ..=-1 => Err(io::Error::last_os_error()),
            recvd => Ok(recvd as usize),
        }
    }

    /// # Errors
    ///
    /// In the event that a packet is received that does not match either the address family
    /// (`AF_PACKET`) or the specified protocol type of `A`, this function will return.
    /// [`InvalidData`](io::ErrorKind::InvalidData). Note that `buf` will still be
    pub fn recv_from<A: L2Addr>(&self, buf: &mut [u8]) -> io::Result<(usize, A)> {
        let mut sockaddr = libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };
        let mut sockaddr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_ll>() as u32;

        let recvd = match unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                ptr::addr_of_mut!(sockaddr) as *mut libc::sockaddr,
                ptr::addr_of_mut!(sockaddr_len),
            )
        } {
            ..=-1 => return Err(io::Error::last_os_error()),
            recvd => recvd as usize,
        };

        if sockaddr.sll_family != libc::AF_PACKET as u16 {
            // Cannot guarantee received sockaddr is size_of::<libc::sockaddr_ll>()
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address received (address family not AF_PACKET)",
            ));
        }

        let Ok(addr) = A::try_from(sockaddr) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected address received (address protocol mismatch)",
            ));
        };

        Ok((recvd, addr))
    }

    /// PACKET_RESERVE socket option; reserves a number of bytes for private use at the start of each block.
    ///
    /// This is superceded by a field in the tpacket_req3 struct.
    fn _reserve_priv(&self, reserved: u32) -> io::Result<()> {
        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_RESERVE,
                ptr::addr_of!(reserved) as *const libc::c_void,
                mem::size_of::<u32>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sets the PACKET_VERSION socket option to TPACKET_V3.
    fn set_tpacket_v3_opt(&self) -> io::Result<()> {
        let pkt_version_3 = libc::tpacket_versions::TPACKET_V3;
        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                ptr::addr_of!(pkt_version_3) as *const libc::c_void,
                mem::size_of::<libc::tpacket_versions>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sets the PACKET_TX_RING socket option.
    fn set_tx_ring_opt(&self, config: BlockConfig) -> io::Result<()> {
        let req_tx = libc::tpacket_req3 {
            tp_block_size: config.block_size(),
            tp_block_nr: config.block_cnt(),
            tp_frame_size: config.frame_size(),
            tp_frame_nr: config.frame_cnt(),
            tp_retire_blk_tov: 0,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_TX_RING,
                ptr::addr_of!(req_tx) as *const libc::c_void,
                mem::size_of::<libc::tpacket_req>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Sets the PACKET_RX_RING socket option.
    fn set_rx_ring_opt(
        &self,
        config: BlockConfig,
        mut timeout: Option<u32>,
        private_size: Option<u32>,
    ) -> io::Result<()> {
        if timeout == Some(0) {
            timeout = Some(1); // Prevent user from accidentally selecting kernel default
        }

        let req_rx = libc::tpacket_req3 {
            tp_block_size: config.block_size(),
            tp_block_nr: config.block_cnt(),
            tp_frame_size: config.frame_size(),
            tp_frame_nr: config.frame_cnt(),
            tp_retire_blk_tov: timeout.unwrap_or(0),
            tp_sizeof_priv: private_size.unwrap_or(0),
            tp_feature_req_word: 0,
        };

        if unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                ptr::addr_of!(req_rx) as *const libc::c_void,
                mem::size_of::<libc::tpacket_req>() as u32,
            ) != 0
        } {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Memory-map the packet's TX/RX ringbuffers to enable zero-copy packet transmision/reception.
    ///
    /// On error, the consumed [`L2Socket`] will be closed.
    #[inline]
    fn mmap_socket(
        &self,
        config: BlockConfig,
        combined_tx_rx: bool,
    ) -> io::Result<*mut libc::c_void> {
        let map_length = if combined_tx_rx {
            config.map_length() * 2
        } else {
            config.map_length()
        };

        let mapped = unsafe {
            libc::mmap(
                ptr::null::<*mut libc::c_void>() as *mut libc::c_void,
                map_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED,
                self.fd,
                0,
            )
        };

        if mapped == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(mapped)
    }

    /// Memory-map the packet's TX ringbuffer to enable zero-copy packet transmision.
    ///
    /// On error, the consumed [`L2Socket`] will be closed.
    #[inline]
    pub fn packet_tx_ring(self, config: BlockConfig) -> io::Result<L2TxMappedSocket> {
        self.set_tpacket_v3_opt()?;
        self.set_tx_ring_opt(config)?;
        let mapping = self.mmap_socket(config, false)?;

        let tx_ring = unsafe {
            PacketTxRing::new(
                mapping as *mut u8,
                config.frame_size() as usize,
                config.block_cnt() as usize,
                config.block_size() as usize,
            )
        };

        Ok(L2TxMappedSocket::new(self, tx_ring))
    }

    /// Memory-map the packet's RX ringbuffer to enable zero-copy packet reception.
    ///
    /// On error, the consumed [`L2Socket`] will be closed.
    #[inline]
    pub fn packet_rx_ring(
        self,
        config: BlockConfig,
        timeout: Option<u32>,
        reserved: Option<u32>,
    ) -> io::Result<L2RxMappedSocket> {
        self.set_tpacket_v3_opt()?;
        self.set_rx_ring_opt(config, timeout, reserved)?;
        let mapping = self.mmap_socket(config, false)?;

        let rx_ring = unsafe {
            PacketRxRing::new(
                mapping as *mut u8,
                config.block_cnt() as usize,
                config.block_size() as usize,
                reserved.unwrap_or(0) as usize,
                OsiLayer::L2,
            )
        };

        Ok(L2RxMappedSocket::new(self, rx_ring))
    }

    /// Configure a memory-mapped ringbuf for zero-copy transfer of packets from the kernel to userspace.
    ///
    /// On error, the L2Socket will be closed.
    ///
    /// NOTE: some performance issues have been noted when TX_RING sockets are used in blocking mode (see
    /// [here](https://stackoverflow.com/questions/43193889/sending-data-with-packet-mmap-and-packet-tx-ring-is-slower-than-normal-withou)).
    /// It is recommended that the socket be set as nonblocking before calling `packet_ring`.
    #[inline]
    pub fn packet_ring(
        self,
        config: BlockConfig,
        timeout: Option<u32>,
        reserved: Option<u32>,
    ) -> io::Result<L2MappedSocket> {
        self.set_tpacket_v3_opt()?;
        self.set_rx_ring_opt(config, timeout, reserved)?;
        let mapping = self.mmap_socket(config, true)?;

        let rx_ring = unsafe {
            PacketRxRing::new(
                mapping as *mut u8,
                config.block_cnt() as usize,
                config.block_size() as usize,
                reserved.unwrap_or(0) as usize,
                OsiLayer::L2,
            )
        };

        let tx_ring = unsafe {
            PacketTxRing::new(
                (mapping as *mut u8).add(config.map_length()),
                config.frame_size() as usize,
                config.block_cnt() as usize,
                config.block_size() as usize,
            )
        };

        Ok(L2MappedSocket::new(self, rx_ring, tx_ring))
    }

    // Send a datagram over the socket.
    // pub fn send_ring<'a>(&'a mut self) -> Option<TxFrame<'a>> {

    // Receive a datagram from the socket.
    // pub fn recv_ring<'a>(&'a mut self, buf: &mut [u8]) -> Option<RxFrame<'a>> {
}

impl Drop for L2Socket {
    #[inline]
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for L2Socket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.fd
    }
}

pub struct L2MappedSocket {
    socket: L2Socket,
    rx_ring: PacketRxRing,
    next_rx: FrameIndex,
    tx_ring: PacketTxRing,
    last_checked_tx: FrameIndex,
    next_tx: FrameIndex,
    manual_tx_status: bool,
    tx_full: bool,
}

impl L2MappedSocket {
    #[inline]
    pub(crate) fn new(socket: L2Socket, rx_ring: PacketRxRing, tx_ring: PacketTxRing) -> Self {
        // This will immediately wrap around to the first packet due to `frame_offset: None`
        let start_frame = FrameIndex {
            blocks_index: tx_ring.blocks_cnt() - 1,
            frame_offset: None,
        };

        Self {
            socket,
            rx_ring,
            next_rx: start_frame,
            tx_ring,
            last_checked_tx: start_frame,
            next_tx: start_frame,
            manual_tx_status: false,
            tx_full: false,
        }
    }

    #[inline]
    pub fn bind<A: L2Addr>(&self, addr: A) -> io::Result<()> {
        self.socket.bind(addr)
    }

    /// Sets `mapped_send` results to be manually handled through repeated calls to `tx_status`.
    ///
    /// By default (i.e., when `manual` = `false`), the results of packet transmission are
    /// transparently handled. As a result, packets flagged as malformed by the kernel are
    /// aggregated into statistics rather than being reported back to the user on a case-by-case
    /// basis.
    ///
    /// If individual packet results are desired, setting this option to `true` modifies socket
    /// behavior such that each sent packet must have its status checked using `tx_status` prior
    /// to that packet being discarded from the ring.
    #[inline]
    pub fn manual_tx_status(&mut self, manual: bool) {
        self.manual_tx_status = manual;
    }

    /// Retrieves the next frame in the memory-mapped ringbuffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    #[inline]
    pub fn mapped_send(&mut self) -> Option<TxFrame<'_>> {
        if self.tx_full {
            return None;
        }

        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.next_tx);
        let TxFrameVariant::Available(frame) = frame_variant else {
            return None;
        };

        if !self.manual_tx_status {
            self.last_checked_tx = self.next_tx;
        } else if self.last_checked_tx == next_tx {
            // TX has looped around fully with manual_tx_status enabled--indicate TX ring is now full
            self.tx_full = true;
        }

        self.next_tx = next_tx;

        Some(frame)
    }

    /// Checks the status of previously-sent packets in the order they were sent.
    ///
    /// By default, or when `manual_tx_status` is set to `false`, this method will only return the
    /// status the last packet sent using `mapped_send()`. When `manual_tx_status()` is set to
    /// `true`, this method will return the status of each packet sent with `mapped_send()` in the
    /// order they were sent.
    ///
    /// To correctly handle TX statuses manually, one should count pending packets sent with
    /// `mapped_send()`. The status of each pending packet should then be retrieved via consecutive
    /// calls to `tx_status()`. If `tx_status()` returns [`TxFrameVariant::Available`], the packet
    /// was successfully sent and the count of packets can be decremented. If `tx_status()`
    /// returns [`TxFrameVariant::SendRequest`] or [`TxFrameVariant::Sending`], the packet is still
    /// being handled by the kernel. In this case, the count should not be decremented, as the next
    /// call to `tx_status()` will return the status of that same packet. If `tx_status()` returns
    /// [`TxFrameVariant::WrongFormat`], the kernel has rejected the packet, and the count of pending
    /// packets should be decremented. The contents of the packet can be retrieved from the
    /// [`InvalidTxFrame`](super::mapped::InvalidTxFrame) if desired.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{thread, time::Duration};
    ///
    /// let mut sock = L2Socket::new()?.packet_tx_ring(BlockConfig::new(65536, 16, 8192)?);
    /// sock.manual_tx_status(true);
    /// let mut sending = 0;
    /// let mut malformed = 0;
    /// for _ in 0..5 {
    ///     let mut tx_frame = sock.mapped_send().unwrap();
    ///     tx_frame.data()[0..11].copy_from_slice(b"hello world"); // This will obviously be malformed
    ///     tx_frame.send(11);
    ///     sending += 1;
    /// }
    ///
    /// while sending > 0 {
    ///     match sock.tx_status() {
    ///         TxFrameVariant::Available(_) => sending -= 1,
    ///         TxFrameVariant::WrongFormat(pkt) => {
    ///             println!("Malformed packet: {:?}", pkt.data());
    ///             malformed += 1;
    ///             sending -= 1;
    ///         }
    ///         TxFrameVariant::SendRequest | TxFrameVariant::Sending => thread::sleep(Duration::from_millis(50)),
    ///     }
    /// }
    ///
    /// assert!(malformed == 5);
    /// ```
    #[inline]
    pub fn tx_status(&mut self) -> TxFrameVariant<'_> {
        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.last_checked_tx);

        if self.manual_tx_status && (self.tx_full || self.last_checked_tx != self.next_tx) {
            // The TX ring is meant to be manually incremented _and_ is not empty
            if let TxFrameVariant::Available(_) | TxFrameVariant::WrongFormat(_) = frame_variant {
                // Increment the TX ring
                self.tx_full = false;
                self.last_checked_tx = next_tx;
            }
        }

        frame_variant
    }

    /// Retrieves the next frame in the memory-mapped ringbuffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrame<'_>> {
        let Some((rx_frame, next_rx)) = self.rx_ring.next_frame(self.next_rx) else {
            return None;
        };

        self.next_rx = next_rx;

        Some(rx_frame)
    }
}

impl Drop for L2MappedSocket {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.rx_ring.mapped_start() as *mut libc::c_void,
                self.rx_ring.mapped_size() * 2,
            );
        }
        // The L2Socket will close itself when dropped
    }
}

impl AsRawFd for L2MappedSocket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}

pub struct L2TxMappedSocket {
    socket: L2Socket,
    tx_ring: PacketTxRing,
    last_checked_tx: FrameIndex,
    next_tx: FrameIndex,
    manual_tx_status: bool,
    tx_full: bool,
}

impl L2TxMappedSocket {
    #[inline]
    pub(crate) fn new(socket: L2Socket, tx_ring: PacketTxRing) -> Self {
        // This will immediately wrap around to the first packet due to `frame_offset: None`
        let start_frame = FrameIndex {
            blocks_index: tx_ring.blocks_cnt() - 1,
            frame_offset: None,
        };

        Self {
            socket,
            tx_ring,
            last_checked_tx: start_frame,
            next_tx: start_frame,
            manual_tx_status: false,
            tx_full: false,
        }
    }

    #[inline]
    pub fn bind<A: L2Addr>(&self, addr: A) -> io::Result<()> {
        self.socket.bind(addr)
    }

    /// Sets `mapped_send` results to be manually handled through repeated calls to `tx_status`.
    ///
    /// By default (i.e., when `manual` = `false`), the results of packet transmission are
    /// transparently handled. As a result, packets flagged as malformed by the kernel are
    /// aggregated into statistics rather than being reported back to the user on a case-by-case
    /// basis.
    ///
    /// If individual packet results are desired, setting this option to `true` modifies socket
    /// behavior such that each sent packet must have its status checked using `tx_status` prior
    /// to that packet being discarded from the ring.
    #[inline]
    pub fn manual_tx_status(&mut self, manual: bool) {
        self.manual_tx_status = manual;
    }

    /// Retrieves the next frame in the memory-mapped ringbuffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    #[inline]
    pub fn mapped_send(&mut self) -> Option<TxFrame<'_>> {
        if self.tx_full {
            return None;
        }

        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.next_tx);
        let TxFrameVariant::Available(frame) = frame_variant else {
            return None;
        };

        if !self.manual_tx_status {
            self.last_checked_tx = self.next_tx;
        } else if self.last_checked_tx == next_tx {
            // TX has looped around fully with manual_tx_status enabled--indicate TX ring is now full
            self.tx_full = true;
        }

        self.next_tx = next_tx;

        Some(frame)
    }

    /// Checks the status of previously-sent packets in the order they were sent.
    ///
    /// By default, or when `manual_tx_status` is set to `false`, this method will only return the
    /// status the last packet sent using `mapped_send()`. When `manual_tx_status()` is set to
    /// `true`, this method will return the status of each packet sent with `mapped_send()` in the
    /// order they were sent.
    ///
    /// To correctly handle TX statuses manually, one should count pending packets sent with
    /// `mapped_send()`. The status of each pending packet should then be retrieved via consecutive
    /// calls to `tx_status()`. If `tx_status()` returns [`TxFrameVariant::Available`], the packet
    /// was successfully sent and the count of packets can be decremented. If `tx_status()`
    /// returns [`TxFrameVariant::SendRequest`] or [`TxFrameVariant::Sending`], the packet is still
    /// being handled by the kernel. In this case, the count should not be decremented, as the next
    /// call to `tx_status()` will return the status of that same packet. If `tx_status()` returns
    /// [`TxFrameVariant::WrongFormat`], the kernel has rejected the packet, and the count of pending
    /// packets should be decremented. The contents of the packet can be retrieved from the
    /// [`InvalidTxFrame`](super::mapped::InvalidTxFrame) if desired.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{thread, time::Duration};
    ///
    /// let mut sock = L2Socket::new()?.packet_tx_ring(BlockConfig::new(65536, 16, 8192)?);
    /// sock.manual_tx_status(true);
    /// let mut sending = 0;
    /// let mut malformed = 0;
    /// for _ in 0..5 {
    ///     let mut tx_frame = sock.mapped_send().unwrap();
    ///     tx_frame.data()[0..11].copy_from_slice(b"hello world"); // This will obviously be malformed
    ///     tx_frame.send(11);
    ///     sending += 1;
    /// }
    ///
    /// while sending > 0 {
    ///     match sock.tx_status() {
    ///         TxFrameVariant::Available(_) => sending -= 1,
    ///         TxFrameVariant::WrongFormat(pkt) => {
    ///             println!("Malformed packet: {:?}", pkt.data());
    ///             malformed += 1;
    ///             sending -= 1;
    ///         }
    ///         TxFrameVariant::SendRequest | TxFrameVariant::Sending => thread::sleep(Duration::from_millis(50)),
    ///     }
    /// }
    ///
    /// assert!(malformed == 5);
    /// ```
    #[inline]
    pub fn tx_status(&mut self) -> TxFrameVariant<'_> {
        let (frame_variant, next_tx) = self.tx_ring.next_frame(self.last_checked_tx);

        if self.manual_tx_status && (self.tx_full || self.last_checked_tx != self.next_tx) {
            // The TX ring is meant to be manually incremented _and_ is not empty
            if let TxFrameVariant::Available(_) | TxFrameVariant::WrongFormat(_) = frame_variant {
                // Increment the TX ring
                self.tx_full = false;
                self.last_checked_tx = next_tx;
            }
        }

        frame_variant
    }
}

impl Drop for L2TxMappedSocket {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.tx_ring.mapped_start() as *mut libc::c_void,
                self.tx_ring.mapped_size(),
            );
        }
        // The L2Socket will close itself when dropped
    }
}

impl AsRawFd for L2TxMappedSocket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}

pub struct L2RxMappedSocket {
    socket: L2Socket,
    rx_ring: PacketRxRing,
    next_rx: FrameIndex,
}

impl L2RxMappedSocket {
    #[inline]
    pub(crate) fn new(socket: L2Socket, rx_ring: PacketRxRing) -> Self {
        // This will immediately wrap around to the first packet due to `frame_offset: None`
        let start_frame = FrameIndex {
            blocks_index: rx_ring.blocks_cnt() - 1,
            frame_offset: None,
        };

        Self {
            socket,
            rx_ring,
            next_rx: start_frame,
        }
    }

    #[inline]
    pub fn bind<A: L2Addr>(&self, addr: A) -> io::Result<()> {
        self.socket.bind(addr)
    }

    /// Retrieves the next frame in the memory-mapped ringbuffer to transmit a packet with.
    ///
    /// The returned [`TxFrame`] should have data written to it via the
    /// [`data()`](`TxFrame::data()`) method. Following this, the packet can be sent with
    /// [`send()`](`TxFrame::send()`), with the number of bytes written to `data()` specified in
    /// `packet_length`. If `send()` is not called, the packet _will not_ be sent, and subsequent
    /// calls to [`mapped_send()`](Self::mapped_send()) will return the same frame.
    #[inline]
    pub fn mapped_recv(&mut self) -> Option<RxFrame<'_>> {
        let Some((rx_frame, next_rx)) = self.rx_ring.next_frame(self.next_rx) else {
            return None;
        };

        self.next_rx = next_rx;

        Some(rx_frame)
    }
}

impl Drop for L2RxMappedSocket {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.rx_ring.mapped_start() as *mut libc::c_void,
                self.rx_ring.mapped_size(),
            );
        }
        // The L2Socket will close itself when dropped
    }
}

impl AsRawFd for L2RxMappedSocket {
    #[inline]
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.socket.fd
    }
}
