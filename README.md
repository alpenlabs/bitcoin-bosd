# Bitcoin Output Script Descriptor (BOSD)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/bitcoin-bosd/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/bitcoin-bosd/actions)
[![docs](https://img.shields.io/badge/docs-bosd-orange)](https://docs.rs/bitcoin-bosd)

## Features

- Compact binary representation of standard Bitcoin output types.
- Zero-copy parsing and validation.
- Support for P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and `OP_RETURN` outputs.
- Implements [`serde`](https://serde.rs) and [`borsh`](https://borsh.io) serialization.
- Strict validation of Bitcoin addresses and output formats.
- Direct conversion to `bitcoin::ScriptBuf`.

## Specification

BOSD uses a simple binary format consisting of
a 1-byte type tag followed by a cryptographic payload.
The format is designed to be compact
and efficiently represent standard Bitcoin output types:

| Type | Payload Len | Payload Interpretation |
| ---- | ----------- | ---------------------- |
| 0    | 0..=80      | `OP_RETURN` payload    |
| 1    | 20          | P2PKH hash             |
| 2    | 20          | P2SH hash              |
| 3    | 20          | P2WPKH hash            |
| 3    | 32          | P2WSH hash             |
| 4    | 32          | P2TR X-only PubKey     |

## Examples

- SegWit V0 (P2WPKH) bech32 mainnet address given a 20-byte public key hash:
  `034d6151263d87371392bb1b60405392c5ba2e3297` $\iff$ `bc1qf4s4zf3asum38y4mrdsyq5ujckazuv5hczg979`
- SegWit V1 (P2TR) bech32m mainnet address given a 32-byte X-only public key:
  `041234123412341234123412341234123412341234123412341234123412341234`
  $\iff$ `bc1pzg6pydqjxsfrgy35zg6pydqjxsfrgy35zg6pydqjxsfrgy35zg6qf6d5se`
- `OP_RETURN` payload given a hex string that is less than 80 bytes:
  `00deadbeefcafebabe` $\iff$ `RETURN PUSHDATA(deadbeefcafebabe)`

## Usage

```rust
use bitcoin::Network;
use bitcoin_bosd::Descriptor;

// Parse from binary
let desc = Descriptor::from_bytes(&[0x04, /* 32 bytes of pubkey */])?;

// Convert to Address
let address = desc.to_address(Network::Bitcoin)?;

// Convert to ScriptBuf
let script = desc.to_script()?;

// Serialize/deserialize
let json = serde_json::to_string(&desc)?;
let serde_bytes = serde_json::to_vec(&desc)?;
let borsh_bytes = borsh::to_vec(&desc)?;
```

## Features

| Feature | Default? | Description |
| :--- | :---: | :--- |
| `address` | ✓ | Adds Bitcoin [`Address`](https://docs.rs/bitcoin/latest/bitcoin/struct.Address.html) and [`ScriptBuf`](https://docs.rs/bitcoin/latest/bitcoin/struct.ScriptBuf.html) functionality |
| `borsh` | | Adds descriptor serialization and deserialization via [`borsh`](https://borsh.io) |
| `serde` | ✓ | Adds descriptor serialization and deserialization via [`serde`](https://serde.rs) |

## Rationale

There doesn't exist any general standard way to encode arbitrary relay-safe
outputs. But we want to support creating a wide range of output types
(any address and also `OP_RETURN`s) in withdrawal outputs.

While we can solve this using
(note that we're referring to
[`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin/)
types)

- `Address` + something extra for `OP_RETURN`:
  The main issue with this is that it's inefficient since it involves linear
  overhead for the error correction, plus some constant overhead for the network
  tag and other framing bytes (like `1` in bech32). There's also some debate that
  could be had over how `OP_RETURN` ought to work here.

  `Address` is a user-facing type that represents a decoded form of what's
  represented by _addresses_ specifically, but we're looking for something that
  represents that gets included in transactions.

  We would _like_ to use something like `AddressData`, but this is more of an
  internal type and doesn't have any serializable representation.

- Use `ScriptBuf` directly:
  This permits non-standard outputs which aren't relay-safe. We want to constrain
  ourselves to standard outputs as that could result in users having a hard
  time getting a non-standard transaction included. This could be seen as a griefing
  attack.

  We could constrain ourselves to only permit a subset of `ScriptBuf`s, but this
  is messy and feels like it runs afoul of the "parse don't validate" principle
  that Rust and other strong-typed languages encourages.

  It can also be a very serious footgun to easily lose funds by sending them
  into the unrecoverable void.

### Design Requirements

So looking at these constraints we can say that we have these requirements:

- must not involve error correction/detection overheads;
- must not include network-related data that's redundant based on context; and
- is a bijection with some sane "relay safe subset" of `ScriptBuf`s,
  corresponding to both textual addresses and including `OP_RETURN`s.

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
