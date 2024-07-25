# pkts

[![Latest Version]][crates.io] [![Documentation]][docs.rs] [![pkts: rustc 1.65+]][Rust 1.65]

[Latest Version]: https://img.shields.io/crates/v/pkts.svg
[crates.io]: https://crates.io/crates/pkts
[pkts: rustc 1.65+]: https://img.shields.io/badge/MSRV-rustc_1.65+-blue.svg
[Rust 1.65]: https://blog.rust-lang.org/2022/11/03/Rust-1.65.0.html
[Documentation]: https://docs.rs/pkts/badge.svg
[docs.rs]: https://docs.rs/pkts/


### **pkts - an [rscap](https://crates.io/crates/rscap) submodule for creating, decoding and modifying packet layers**

---

`rscap` is a multi-purpose library for network packet capture/transmission and packet building. Its aims are twofold:

1. To provide Rust-native platform tools for packet capture and transmission (comparable to `libpcap`, but written from the ground up in Rust)
2. To expose a robust and ergonomic API for building packets and accessing/modifying packet data fields in various network protocols (like `scapy`, but with strong typing and significantly improved performance)

The `pkts` submodule focuses solely on (2)--it provides a packet-building API for a wide variety of network protocol layers.
This library isn't meant to only cover Physical through Transport layers or stateless protocols--thanks to `Sequence` and `Session` types (which defragment/reorder packets and track packet state, respectively), any application-layer protocol can potentially be captured and decoded.

## Features

- **Robust APIs for building/modifying packets:** rscap provides simple operations to combine various layers into a single packet, and to index into a different layers of a packet to retrieve or modify fields. Users of [`scapy`](https://github.com/ecdev/scapy) may find the API surprisingly familiar, especially for layer composition and indexing operations:

```rust
use layers::{ip::Ipv4, tcp::Tcp};

let pkt = Ip::new() / Tcp::new();
pkt[Tcp].set_sport(80);
pkt[Tcp].set_dport(12345);
```
- **`no-std` Compatible:** every packet type in the `pkts` crate can be used without the standard library, and a special `LayerRef` type can be used to access raw packet bytes without any allocations. Packets can additionally be constructed from scratch in `no-std` environments using allocation-free Builder patterns.
- **Packet defragmentation/reordering:** In some protocols, packets may be fragmented (such as IPv4) or arrive out-of-order (TCP, SCTP, etc.). Rscap overcomes both of these issues through `Sequence` types that transparently handle defragmentation and reordering. `Sequence` types can even be stacked so that application-layer data can easily be reassembled from captured packets. They even work in `no-std` environments with or without `alloc`.
- **Stateful packet support:** Many network protocols are stateful, and interpreting packets from such protocols can be difficult (if not impossible) to accomplish unless information about the protocol session is stored. Rscap provides `Session` types that handle these kinds of packets--Sessions ensure that packets are validated based on the current expected state of the protocol. Just like `Sequence`, `Session` types are compatible with `no-std` environments and do not require `alloc`.

## License

The source code of this project is licensed under either the MIT License or the Apache 2.0 License, at your option.


