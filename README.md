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

> [!NOTE]
> The full specification is available in
> the [BOSD Specification](SPECIFICATION.md) document.

BOSD uses a simple binary format consisting of
a 1-byte type tag followed by a cryptographic payload.
The format is designed to be compact
and efficiently represent standard Bitcoin output types:

| Type | Payload Length(s) | Payload Interpretation | Spend Type    | Mainnet Address Prefix |
| ---- | ----------------- | ---------------------- | ------------- | ---------------------- |
| 0    | ..=80             | `OP_RETURN` payload    | (N/A)         | (N/A)                  |
| 1    | 20                | pubkey hash            | P2PKH         | `1...`                 |
| 2    | 20                | script hash            | P2SH          | `3...`                 |
| 3    | 20, 32            | SegWit v0 hash         | P2WPKH, P2WSH | `bc1q...`              |
| 4    | 32                | SegWit v1 public key   | P2TR          | `bc1p...`              |

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

| Feature     | Default? |   standalone    | Description                                                                                                                                                                        |
| :---------- | :------: | :-------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address`   |    ✓     |        ✓        | Adds Bitcoin [`Address`](https://docs.rs/bitcoin/latest/bitcoin/struct.Address.html) and [`ScriptBuf`](https://docs.rs/bitcoin/latest/bitcoin/struct.ScriptBuf.html) functionality |
| `arbitrary` |          | needs `address` | Adds [`Arbitrary`](https://docs.rs/arbitrary/) to generate random descriptors for fuzzing and property testing                                                                     |
| `borsh`     |          |        ✓        | Adds descriptor serialization and deserialization via [`borsh`](https://borsh.io)                                                                                                  |
| `serde`     |    ✓     |        ✓        | Adds descriptor serialization and deserialization via [`serde`](https://serde.rs)                                                                                                  |

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
