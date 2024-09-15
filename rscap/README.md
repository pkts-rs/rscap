# rscap

[![Cross-Platform]][CI Status] [![Documentation]][docs.rs] [![Latest Version]][crates.io] [![v1.66+]][Rust 1.66]

[Cross-Platform]: https://github.com/pkts-rs/rscap/actions/workflows/full_CI.yml/badge.svg
[CI Status]: https://github.com/pkts-rs/rscap/actions/workflows/full_ci.yml
[Documentation]: https://docs.rs/rscap/badge.svg
[docs.rs]: https://docs.rs/rscap/
[Latest Version]: https://img.shields.io/crates/v/rscap.svg
[crates.io]: https://crates.io/crates/rscap
[v1.66+]: https://img.shields.io/badge/MSRV-rustc_1.66+-blue.svg
[Rust 1.66]: https://blog.rust-lang.org/2022/12/15/Rust-1.66.0.html

**rscap - Rust packet capture and manipulation utilities**

---

`rscap` is a multi-purpose library for network packet capture/transmission and packet building. Its aims are twofold:

1. To provide Rust-native platform tools for packet capture and transmission (comparable to `libpcap`, but written from the ground up in Rust)
2. To expose a robust and ergonomic API for building packets and accessing/modifying packet data fields in various network protocols (like `scapy`, but with strong typing and significantly improved performance)

The `rscap` submodule focuses specifically on (1)--it provides safe, Rust-native APIs for capturing packets over network interfaces. 
The sibling [`pkts` crate](https://github.com/pkts-rs/pkts) handles (2).

## Development Status

Supported:
- Linux link/network/transport-layer sockets (RX + TX)
- Linux memory-mapped socket I/O (RX + TX)
- *BSD/MacOS link-layer `/dev/bpf` packet capture/transmission interfaces (RX + TX)
- `/dev/bpf` memory-mapped packet capture (RX only)
- Windows `npcap` driver packet capture/transmission (RX + TX)

In Progress:
- Unifying interface to provide common features in a cross-platform manner
- Attaching filter programs (BPF) to sockets
- Solaris/IllumOS support via DLPI implementation (RX + TX)
- Native Windows 10/11 capture support via reverse-engineered ioctl calls from `pktmon` (RX only)

## Features

- **Platform-independent interface for packet capture/transmission:** `rscap` aims to provide a single unified interface for capturing and transmitting packets across any supported platform. Additionally, the library exposes safe abstractions of platform-specific packet capture tools (such as `AF_PACKET`/`PACKET_MMAP` sockets in Linux) to support cases where fine-grained control or platform-specific features are desired.
- **Robust APIs for building/modifying packets:** the `pkts` submodule provides simple operations to combine various layers into a single packet, and to index into a different layers of a packet to retrieve or modify fields. Users of [`scapy`](https://github.com/ecdev/scapy) may find the API surprisingly familiar, especially for layer composition and indexing operations:

```rust
use layers::{ip::Ipv4, tcp::Tcp};

let pkt = Ip::new() / Tcp::new();
pkt[Tcp].set_sport(80);
pkt[Tcp].set_dport(12345);
```

- **Packet defragmentation/reordering:** In some protocols, packets may be fragmented (such as IPv4) or arrive out-of-order (TCP, SCTP, etc.). `rscap` overcomes both of these issues through `Sequence` types that transparently handle defragmentation and reordering. `Sequence` types can even be stacked so that application-layer data can easily be reassembled from captured packets. They even work in `no-std` environments with or without `alloc`.
- **Stateful packet support:** Many network protocols are stateful, and interpreting packets from such protocols can be difficult (if not impossible) to accomplish unless information about the protocol session is stored. `rscap` provides `Session` types that handle these kinds of packets--Sessions ensure that packets are validated based on the current expected state of the protocol. Just like `Sequence`, `Session` types are compatible with `no-std` environments and do not require `alloc`.

## License

This project is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-MIT))

at your option.

## Contributing

`rscap` is open to contribution--feel free to submit an Issue or Pull Request if there's
something you'd like to add to this library.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`rscap` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
