//! # Bitcoin Binary Output Script Descriptor (BOSD)
//!
//! BOSD uses a simple binary format consisting of
//! a 1-byte type tag followed by a cryptographic payload.
//! The format is designed to be compact
//! and efficiently represent standard Bitcoin output types:
//!
//! | Type | Payload Len | Payload Interpretation |
//! | ---- | ----------- | ---------------------- |
//! | 0    | 0..=80      | `OP_RETURN` payload    |
//! | 1    | 20          | P2PKH hash             |
//! | 2    | 20          | P2SH hash              |
//! | 3    | 20          | P2WPKH hash            |
//! | 3    | 32          | P2WSH hash             |
//! | 4    | 32          | P2TR X-only PubKey     |

#[cfg(feature = "address")]
pub mod address;
#[cfg(feature = "borsh")]
pub mod borsh;
pub mod descriptor;
pub mod error;
#[cfg(feature = "serde")]
pub mod serde;

pub use descriptor::{Descriptor, DescriptorType};
pub use error::DescriptorError;
