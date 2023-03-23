# pktspec

[![Latest Version]][crates.io] [![Documentation]][docs.rs] [![pktspec: rustc 1.65+]][Rust 1.65]

[Latest Version]: https://img.shields.io/crates/v/pktspec.svg
[crates.io]: https://crates.io/crates/pktspec
[pktspec: rustc 1.65+]: https://img.shields.io/badge/MSRV-rustc_1.65+-blue.svg
[Rust 1.65]: https://blog.rust-lang.org/2022/11/03/Rust-1.65.0.html
[Documentation]: https://docs.rs/pktspec/badge.svg
[docs.rs]: https://docs.rs/pktspec/


### **pktspec - an [rscap](https://crates.io/crates/rscap) submodule for speculatively inferring packet types**

---

Rscap is a multi-purpose library for network packet capture/transmission and packet building. Its aims are twofold:

1. To provide Rust-native platform tools for packet capture and transmission (comparable to `libpcap`, but written from the ground up in Rust)
2. To expose a robust and ergonomic API for building packets and accessing/modifying packet data fields in various network protocols (like `scapy`, but with strong typing and significantly improved performance)

The `pkts` submodule focuses solely on (2)--it provides a packet-building API for a wide variety of network protocol layers.
This library isn't meant to only cover Physical through Transport layers or stateless protocols--thanks to `Sequence` and `Session` types (which defragment/reorder packets and track packet state, respectively), any application-layer protocol can be easily captured and decoded.

The `pktspec` submodule provides additional functionality to the `pkts` library. By default, packet decoding in `pkts` is limited to layers that can be deduced with certainty by the layers above it. As an example, `Ipv4` packets contain a field that describe what transport layer payload it contains, so `pkts` is able to decode payloads up to that layer. However, no application layer protocols are deduced automatically by `pkts`. The `pktspec` library provides this missing functionality, using fields from various layers (port numbers, protocol types, etc.) as well as previous packets decoded by the same context to infer the appropriate sublayers for a given packet.

**NOTE: this library is in very early conceptual/developmental stage.** For now, most development efforts are being focused on `rscap` and `pkts`; as these libraries mature, more effort will be put into `pktspec`.

## License

The source code of this project is licensed under either the MIT License or the Apache 2.0 License, at your option.

