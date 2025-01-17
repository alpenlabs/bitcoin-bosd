//! # Bitcoin Binary Output Script Descriptor (BOSD)
//!
//! BOSD uses a simple binary format consisting of
//! a 1-byte type tag followed by a cryptographic payload.
//! The format is designed to be compact
//! and efficiently represent standard Bitcoin output types:
//!
//! | Type | Payload Length(s) | Payload Interpretation | Spend Type    | Mainnet Address Prefix |
//! | ---- | ----------------- | ---------------------- | ------------- | ---------------------- |
//! | 0    | ..=80             | `OP_RETURN` payload    | (N/A)         | (N/A)                  |
//! | 1    | 20                | pubkey hash            | P2PKH         | `1...`                 |
//! | 2    | 20                | script hash            | P2SH          | `3...`                 |
//! | 3    | 20, 32            | SegWit v0 hash         | P2WPKH, P2WSH | `bc1q...`              |
//! | 4    | 32                | SegWit v1 public key   | P2TR          | `bc1p...`              |

#[cfg(feature = "address")]
pub mod address;
#[cfg(all(feature = "arbitrary", feature = "address"))]
pub mod arbitrary;
#[cfg(feature = "borsh")]
pub mod borsh;
pub mod descriptor;
pub mod error;
#[cfg(feature = "serde")]
pub mod serde;

pub use descriptor::{Descriptor, DescriptorType};
pub use error::DescriptorError;
