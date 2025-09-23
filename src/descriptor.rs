//! # Bitcoin Output Script Descriptor (BOSD)
//!
//! This module implements a BOSD parser and validator.
//!
//! The main type is [`Descriptor`].
//! Check this crate's top-level documentation for the
//! specification and rationale.

use core::fmt;

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use hex::{DisplayHex, FromHex};

#[cfg(feature = "address")]
use bitcoin::XOnlyPublicKey;

use crate::error::DescriptorError;

/// `OP_RETURN` type tag.
pub(crate) const OP_RETURN_TYPE_TAG: u8 = 0;

/// Maximum length of `OP_RETURN` payload.
pub const MAX_OP_RETURN_LEN: usize = 100_000;

/// `P2PKH` type tag.
pub(crate) const P2PKH_TYPE_TAG: u8 = 1;

/// Exact length of P2PKH payload.
pub const P2PKH_LEN: usize = 20;

/// `P2SH` type tag.
pub(crate) const P2SH_TYPE_TAG: u8 = 2;

/// Exact length of P2SH payload.
pub const P2SH_LEN: usize = 20;

/// `P2WPKH`/`P2WSH` type tag.
pub(crate) const P2WPKH_P2WSH_TYPE_TAG: u8 = 3;

/// Exact length of P2WPKH payload.
pub const P2WPKH_LEN: usize = 20;

/// Exact length of P2WSH payload.
pub const P2WSH_LEN: usize = 32;

/// `P2TR` type tag.
pub(crate) const P2TR_TYPE_TAG: u8 = 4;

/// Exact length of P2TR payload.
pub const P2TR_LEN: usize = 32;

/// A Bitcoin Output Script Descriptor (BOSD).
///
/// This is a compact binary format consisting of
/// a `type_tag` that represents a ScriptPubKey that can be
/// relayed by any node in the Bitcoin network,
/// due to standardness requirements.
///
/// See [the Bitcoin developer guide on Transactions](https://developer.bitcoin.org/devguide/transactions.html)
/// for more information on standardness.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Descriptor {
    /// The type of the descriptor.
    type_tag: DescriptorType,

    /// The actual underlying data.
    payload: Vec<u8>,
}

impl Descriptor {
    /// Constructs a new [`Descriptor`] from a byte slice.
    ///
    /// Users are advised to use the `new_*` methods whenever possible.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DescriptorError> {
        // Extract the type tag (which must exist) and the payload
        let (&type_tag, payload) = bytes.split_first().ok_or(DescriptorError::MissingTypeTag)?;

        // Validate the payload length against the type
        match type_tag {
            // OP_RETURN must be at most 100KB.
            OP_RETURN_TYPE_TAG => {
                let payload_len = payload.len();
                if payload_len > MAX_OP_RETURN_LEN {
                    Err(DescriptorError::InvalidPayloadLength(payload_len))
                } else {
                    Ok(Self {
                        type_tag: DescriptorType::OpReturn,
                        payload: payload.to_vec(),
                    })
                }
            }
            // P2PKH and P2SH must be exactly 20 bytes.
            P2PKH_TYPE_TAG => {
                let payload_len = payload.len();
                if payload_len != P2PKH_LEN {
                    Err(DescriptorError::InvalidPayloadLength(payload_len))
                } else {
                    Ok(Self {
                        type_tag: DescriptorType::P2pkh,
                        payload: payload.to_vec(),
                    })
                }
            }
            P2SH_TYPE_TAG => {
                let payload_len = payload.len();
                if payload_len != P2SH_LEN {
                    Err(DescriptorError::InvalidPayloadLength(payload_len))
                } else {
                    Ok(Self {
                        type_tag: DescriptorType::P2sh,
                        payload: payload.to_vec(),
                    })
                }
            }
            // P2WPKH must be exactly 20 bytes, and P2SH must be exactly 32 bytes.
            P2WPKH_P2WSH_TYPE_TAG => {
                let payload_len = payload.len();
                match payload_len {
                    P2WPKH_LEN => Ok(Self {
                        type_tag: DescriptorType::P2wpkh,
                        payload: payload.to_vec(),
                    }),
                    P2WSH_LEN => Ok(Self {
                        type_tag: DescriptorType::P2wsh,
                        payload: payload.to_vec(),
                    }),
                    _ => Err(DescriptorError::InvalidPayloadLength(payload_len)),
                }
            }
            // P2TR must be exactly 32 bytes.
            P2TR_TYPE_TAG => {
                let payload_len = payload.len();
                if payload_len != P2TR_LEN {
                    Err(DescriptorError::InvalidPayloadLength(payload_len))
                } else {
                    Ok(Self {
                        type_tag: DescriptorType::P2tr,
                        payload: payload.to_vec(),
                    })
                }
            }
            _ => Err(DescriptorError::InvalidDescriptorType(type_tag)),
        }
    }

    /// Constructs a new [`Descriptor`] from a byte [`Vec`].
    ///
    /// Users are advised to use the `new_*` methods whenever possible.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, DescriptorError> {
        Self::from_bytes(&bytes)
    }

    /// Constructs a new [`Descriptor`] from an `OP_RETURN` payload.
    ///
    /// The payload is expected to be at most 100KB.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType};
    /// let payload = b"hello world";
    /// let desc = Descriptor::new_op_return(payload).expect("valid payload that is at most 100KB");
    /// # assert_eq!(desc.type_tag(), DescriptorType::OpReturn);
    /// # assert_eq!(desc.payload(), b"hello world");
    /// ```
    pub fn new_op_return(payload: &[u8]) -> Result<Self, DescriptorError> {
        let type_tag = DescriptorType::OpReturn;
        let payload_len = payload.len();
        if payload_len > MAX_OP_RETURN_LEN {
            Err(DescriptorError::InvalidPayloadLength(payload_len))
        } else {
            Ok(Self {
                type_tag,
                payload: payload.to_vec(),
            })
        }
    }

    /// Constructs a new [`Descriptor`] from a P2PKH payload.
    ///
    /// The payload is expected to be a valid 20-byte hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2PKH_LEN};
    /// let payload = [0u8; P2PKH_LEN]; // all zeros, don't use in production
    /// let desc = Descriptor::new_p2pkh(&payload);
    /// # assert_eq!(desc.type_tag(), DescriptorType::P2pkh);
    /// # assert_eq!(desc.payload(), [0u8; P2PKH_LEN]);
    /// ```
    pub fn new_p2pkh(payload: &[u8; P2PKH_LEN]) -> Self {
        let type_tag = DescriptorType::P2pkh;
        Self {
            type_tag,
            payload: payload.to_vec(),
        }
    }

    /// Constructs a new [`Descriptor`] from a P2SH payload.
    ///
    /// The payload is expected to be a valid 20-byte hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2SH_LEN};
    /// let payload = [0u8; P2SH_LEN]; // all zeros, don't use in production
    /// let desc = Descriptor::new_p2sh(&payload);
    /// # assert_eq!(desc.type_tag(), DescriptorType::P2sh);
    /// # assert_eq!(desc.payload(), [0u8; P2SH_LEN]);
    /// ```
    pub fn new_p2sh(payload: &[u8; P2SH_LEN]) -> Self {
        let type_tag = DescriptorType::P2sh;
        Self {
            type_tag,
            payload: payload.to_vec(),
        }
    }

    /// Constructs a new [`Descriptor`] from a P2WPKH payload.
    ///
    /// The payload is expected to be a valid 20-byte hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2WPKH_LEN};
    /// let payload = [0u8; P2WPKH_LEN]; // all zeros, don't use in production
    /// let desc = Descriptor::new_p2wpkh(&payload);
    /// # assert_eq!(desc.type_tag(), DescriptorType::P2wpkh);
    /// # assert_eq!(desc.payload(), [0u8; P2WPKH_LEN]);
    /// ```
    pub fn new_p2wpkh(payload: &[u8; P2WPKH_LEN]) -> Self {
        let type_tag = DescriptorType::P2wpkh;
        Self {
            type_tag,
            payload: payload.to_vec(),
        }
    }

    /// Constructs a new [`Descriptor`] from a P2WSH payload.
    ///
    /// The payload is expected to be a valid 32-byte hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2WSH_LEN};
    /// let payload = [0u8; P2WSH_LEN]; // all zeros, don't use in production
    /// let desc = Descriptor::new_p2wsh(&payload);
    /// # assert_eq!(desc.type_tag(), DescriptorType::P2wsh);
    /// # assert_eq!(desc.payload(), [0u8; P2WSH_LEN]);
    /// ```
    pub fn new_p2wsh(payload: &[u8; P2WSH_LEN]) -> Self {
        let type_tag = DescriptorType::P2wsh;
        Self {
            type_tag,
            payload: payload.to_vec(),
        }
    }

    /// Constructs a new [`Descriptor`] from an _unchecked_ P2TR payload.
    ///
    /// The payload is expected to be a valid 32-byte X-only public key.
    /// You _must_ validate this key on your own; this function will not do it for you.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2TR_LEN};
    /// let payload = [2u8; P2TR_LEN]; // valid X-only public key, but don't use in production
    /// let desc = Descriptor::new_p2tr_unchecked(&payload);
    /// # assert_eq!(desc.type_tag(), DescriptorType::P2tr);
    /// # assert_eq!(desc.payload(), [2u8; P2TR_LEN]);
    /// ```
    pub fn new_p2tr_unchecked(payload: &[u8; P2TR_LEN]) -> Self {
        let type_tag = DescriptorType::P2tr;

        Self {
            type_tag,
            payload: payload.to_vec(),
        }
    }

    /// Constructs a new [`Descriptor`] from a P2TR payload.
    ///
    /// The payload is expected to be a valid 32-byte X-only public key.A
    /// This function will validate this key for you, and return an error if validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2TR_LEN};
    /// let payload = [2u8; P2TR_LEN]; // valid X-only public key, but don't use in production
    /// let desc = Descriptor::new_p2tr(&payload).expect("valid X-only public key");
    /// # assert_eq!(desc.type_tag(), DescriptorType::P2tr);
    /// # assert_eq!(desc.payload(), [2u8; P2TR_LEN]);
    /// ```
    #[cfg(feature = "address")]
    pub fn new_p2tr(payload: &[u8; P2TR_LEN]) -> Result<Self, DescriptorError> {
        let type_tag = DescriptorType::P2tr;

        if XOnlyPublicKey::from_slice(payload).is_err() {
            Err(DescriptorError::InvalidXOnlyPublicKey)
        } else {
            Ok(Self {
                type_tag,
                payload: payload.to_vec(),
            })
        }
    }

    /// Returns the bytes representation of the descriptor.
    ///
    /// That is:
    ///
    /// - 1-byte type tag.
    /// - arbitrary-sized payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.payload.len());
        bytes.push(self.type_tag.to_u8());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Generates fixed bytes of payload of length specified by the generic parameter.
    ///
    /// # Notes
    ///
    /// - This method is intended for internal use and relies on the caller
    ///   ensuring that the payload's length matches the size `B`.
    pub(crate) fn to_fixed_payload_bytes<const B: usize>(&self) -> [u8; B] {
        debug_assert_eq!(self.payload().len(), B);
        let mut bytes = [0u8; B];
        bytes[..].copy_from_slice(self.payload());
        bytes
    }

    /// Returns the type tag of the descriptor.
    pub fn type_tag(&self) -> DescriptorType {
        self.type_tag
    }

    /// Returns the payload of the descriptor.
    ///
    /// # Warning
    ///
    /// It is not advisable to use this method.
    /// Instead, try to parse it either as a Bitcoin address
    /// by using [`Descriptor::to_address`] in the case of an address,
    /// or as a Bitcoin script by using [`Descriptor::to_script`] in
    /// the case of an `OP_RETURN` payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }
}

impl Display for Descriptor {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let type_tag = self.type_tag().to_u8();
        write!(f, "{}{}", &[type_tag].as_hex(), self.payload.as_hex())
    }
}

impl FromStr for Descriptor {
    type Err = DescriptorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        Self::from_bytes(&bytes)
    }
}

/// The type tag of a [`Descriptor`].
///
/// This is the first byte of the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive] // Might need more in the future.
pub enum DescriptorType {
    /// `OP_RETURN` payload.
    OpReturn,

    /// P2PKH hash.
    ///
    /// It is a 20-byte hash of a public key,
    /// that is first hashed with SHA-256,
    /// followed by RIPEMD-160.
    P2pkh,

    /// P2SH hash.
    ///
    /// It is a 20-byte hash of a custom locking script,
    /// that is first hashed with SHA-256,
    /// followed by RIPEMD-160.
    P2sh,

    /// P2WPKH hash.
    ///
    /// It is a 20-byte hash of a public key,
    /// that is first hashed with SHA-256,
    /// followed by RIPEMD-160.
    P2wpkh,

    /// P2WSH hash.
    ///
    /// It is a 32-byte hash of a custom locking script
    /// hashed with SHA-256.
    P2wsh,

    /// P2TR X-only public key.
    ///
    /// It is a 32-byte public key.
    /// The key might be tweaked by a Merkle root hash
    /// that represents the underlying taptree of script
    /// spending conditions.
    P2tr,
}

impl DescriptorType {
    /// Returns the type tag as a byte.
    pub fn to_u8(self) -> u8 {
        match self {
            DescriptorType::OpReturn => 0,
            DescriptorType::P2pkh => 1,
            DescriptorType::P2sh => 2,
            DescriptorType::P2wpkh => 3,
            DescriptorType::P2wsh => 3,
            DescriptorType::P2tr => 4,
        }
    }
}

impl Display for DescriptorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorType::OpReturn => write!(f, "OP_RETURN"),
            DescriptorType::P2pkh => write!(f, "P2PKH"),
            DescriptorType::P2sh => write!(f, "P2SH"),
            DescriptorType::P2wpkh => write!(f, "P2WPKH"),
            DescriptorType::P2wsh => write!(f, "P2WSH"),
            DescriptorType::P2tr => write!(f, "P2TR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Test that any valid `OP_RETURN` payload (0-100KB) roundtrips correctly.
            #[test]
            fn op_return_roundtrip_property(data in prop::collection::vec(any::<u8>(), 0..=MAX_OP_RETURN_LEN)) {
                if data.len() <= MAX_OP_RETURN_LEN {
                    let mut bytes = vec![0u8; data.len() + 1];
                    bytes[0] = 0; // OP_RETURN type tag
                    bytes[1..].copy_from_slice(&data);

                    let descriptor = Descriptor::from_bytes(&bytes).expect("valid OP_RETURN should parse");
                    assert_eq!(descriptor.type_tag(), DescriptorType::OpReturn);
                    assert_eq!(descriptor.payload(), &data);
                    assert_eq!(&descriptor.to_bytes(), &bytes);
                }
            }

            /// Test that `OP_RETURN` payloads larger than 100KB are rejected.
            #[test]
            fn op_return_invalid_size_property(data in prop::collection::vec(any::<u8>(), (MAX_OP_RETURN_LEN + 1)..=(MAX_OP_RETURN_LEN * 2))) {
                let mut bytes = vec![0u8; data.len() + 1];
                bytes[0] = 0; // OP_RETURN type tag
                bytes[1..].copy_from_slice(&data);

                assert!(Descriptor::from_bytes(&bytes).is_err(),
                    "OP_RETURN payload of {} bytes should be rejected", data.len());
            }

            /// Test that exactly 100KB `OP_RETURN` payloads are accepted.
            #[test]
            fn op_return_max_size_property(data in prop::collection::vec(any::<u8>(), MAX_OP_RETURN_LEN..=MAX_OP_RETURN_LEN)) {
                let mut bytes = vec![0u8; data.len() + 1];
                bytes[0] = 0; // OP_RETURN type tag
                bytes[1..].copy_from_slice(&data);

                let descriptor = Descriptor::from_bytes(&bytes).expect("100KB OP_RETURN should be valid");
                assert_eq!(descriptor.type_tag(), DescriptorType::OpReturn);
                assert_eq!(descriptor.payload(), &data);
                assert_eq!(&descriptor.to_bytes(), &bytes);
            }

            /// Test that any valid descriptor roundtrips correctly.
            #[test]
            fn descriptor_roundtrip_property(data in prop::collection::vec(any::<u8>(), 1..=(MAX_OP_RETURN_LEN + 1))) {
                if let Ok(descriptor) = Descriptor::from_bytes(&data) {
                    assert_eq!(&descriptor.to_bytes(), &data);
                }
            }
        }
    }

    #[test]
    fn descriptor_from_bytes() {
        let bytes = [0, 1, 2, 3, 4, 5];
        let descriptor = Descriptor::from_bytes(&bytes).unwrap();
        assert_eq!(descriptor.type_tag(), DescriptorType::OpReturn);
        assert_eq!(descriptor.payload(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn descriptor_from_bytes_invalid() {
        // Empty byte slice
        let bytes = [];
        assert!(Descriptor::from_bytes(&bytes).is_err());

        // Only tag type byte
        for tag in 0..=u8::MAX {
            let bytes = [tag];

            // An empty payload is currently invalid for all types except `OP_RETURN`
            match tag {
                OP_RETURN_TYPE_TAG => assert!(Descriptor::from_bytes(&bytes).is_ok()),
                _ => assert!(Descriptor::from_bytes(&bytes).is_err()),
            }
        }

        // Invalid type tag
        let bytes = [5, 1, 2, 3, 4, 5, 6];
        assert!(Descriptor::from_bytes(&bytes).is_err());

        // Invalid payload length
        // OP_RETURN with 100001 bytes (MAX_OP_RETURN_LEN + 1)
        let mut bytes = vec![0; MAX_OP_RETURN_LEN + 2]; // 1 byte type tag + (MAX_OP_RETURN_LEN + 1) bytes payload
        bytes[0] = 0; // OP_RETURN type tag
        assert!(Descriptor::from_bytes(&bytes).is_err());

        // P2PKH with 19 bytes
        let bytes = [1; 20];
        assert!(Descriptor::from_bytes(&bytes).is_err());

        // P2TR with 33 bytes
        let bytes = [4; 34];
        assert!(Descriptor::from_bytes(&bytes).is_err());
    }

    #[test]
    fn descriptor_to_bytes() {
        let original: &[u8; 20] = &[
            0, 99, 104, 97, 114, 108, 101, 121, 32, 108, 111, 118, 101, 115, 32, 104, 101, 105,
            100, 105,
        ];
        let desc = Descriptor::from_str("00636861726c6579206c6f766573206865696469").unwrap();
        let bytes = desc.to_bytes();
        assert_eq!(bytes, original);
    }

    #[test]
    fn descriptor_type() {
        assert_eq!(DescriptorType::OpReturn.to_u8(), 0);
        assert_eq!(DescriptorType::P2pkh.to_u8(), 1);
        assert_eq!(DescriptorType::P2sh.to_u8(), 2);
        assert_eq!(DescriptorType::P2wpkh.to_u8(), 3);
        assert_eq!(DescriptorType::P2wsh.to_u8(), 3);
        assert_eq!(DescriptorType::P2tr.to_u8(), 4);
    }

    #[test]
    fn from_str() {
        // OP_RETURN in hex string replacing the 6a (`OP_RETURN`)
        // for a 0x00 (type_tag) byte for `OP_RETURN`.
        // Source: https://bitcoin.stackexchange.com/a/29555
        //         and transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        let s = "00636861726c6579206c6f766573206865696469";
        let desc = Descriptor::from_str(s).unwrap();
        assert_eq!(desc.type_tag(), DescriptorType::OpReturn);
        assert_eq!(desc.payload(), b"charley loves heidi");

        // P2PKH
        // Using 0x01 (type_tag) and a 20-byte hash
        // Source: transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        // Corresponds to address `1HnhWpkMHMjgt167kvgcPyurMmsCQ2WPgg`
        let s = "01b8268ce4d481413c4e848ff353cd16104291c45b";
        let desc = Descriptor::from_str(s).unwrap();
        assert_eq!(desc.type_tag(), DescriptorType::P2pkh);
        assert_eq!(
            desc.payload(),
            Vec::from_hex("b8268ce4d481413c4e848ff353cd16104291c45b").unwrap()
        );

        // P2SH
        // Using 0x02 (type_tag) and a 20-byte hash
        // Source: transaction a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f
        // Corresponds to address `3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V`
        let s = "02748284390f9e263a4b766a75d0633c50426eb875";
        let desc = Descriptor::from_str(s).unwrap();
        assert_eq!(desc.type_tag(), DescriptorType::P2sh);
        assert_eq!(
            desc.payload(),
            Vec::from_hex("748284390f9e263a4b766a75d0633c50426eb875").unwrap()
        );

        // P2WPKH
        // Using 0x03 (type_tag) and a 20-byte hash
        // Source: transaction 7c53ba0f1fc65f021749cac6a9c163e499fcb2e539b08c040802be55c33d32fe
        // Corresponds to address `bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40`
        let s = "03671041727b982843f7e3db4669c2f542e05096fb";
        let desc = Descriptor::from_str(s).unwrap();
        assert_eq!(desc.type_tag(), DescriptorType::P2wpkh);
        assert_eq!(
            desc.payload(),
            Vec::from_hex("671041727b982843f7e3db4669c2f542e05096fb").unwrap()
        );

        // P2WSH
        // Using 0x03 (type_tag) and a 32-byte hash
        // Source: transaction fbf3517516ebdf03358a9ef8eb3569f96ac561c162524e37e9088eb13b228849
        // Corresponds to address `bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65`
        let s = "0365f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3";
        let desc = Descriptor::from_str(s).unwrap();
        assert_eq!(desc.type_tag(), DescriptorType::P2wsh);
        assert_eq!(
            desc.payload(),
            Vec::from_hex("65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3")
                .unwrap()
        );

        // P2TR
        // Using 0x04 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let s = "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667";
        let desc = Descriptor::from_str(s).unwrap();
        assert_eq!(desc.type_tag(), DescriptorType::P2tr);
        assert_eq!(
            desc.payload(),
            Vec::from_hex("0f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667")
                .unwrap()
        );
    }

    #[test]
    fn to_string() {
        let original = "00636861726c6579206c6f766573206865696469";
        let desc = Descriptor::from_bytes(&[
            0, 99, 104, 97, 114, 108, 101, 121, 32, 108, 111, 118, 101, 115, 32, 104, 101, 105,
            100, 105,
        ])
        .unwrap();
        let s = desc.to_string();
        assert_eq!(s, original);
    }

    #[test]
    fn invalid_from_str() {
        // Invalid type tag
        let s = "050000000000000000000000000000000000000000000000000000000000000000";
        assert!(Descriptor::from_str(s).is_err());

        // Invalid payload length
        // OP_RETURN with 100001 bytes (create a hex string with (MAX_OP_RETURN_LEN + 1)*2 hex chars)
        let s = "00".to_string() + &"00".repeat(MAX_OP_RETURN_LEN + 1);
        assert!(Descriptor::from_str(&s).is_err());

        // P2PKH with 19 bytes
        let s = "0100000000000000000000000000000000000000";
        assert!(Descriptor::from_str(s).is_err());

        // P2TR with 33 bytes
        let s = "04000000000000000000000000000000000000000000000000000000000000000000";
        assert!(Descriptor::from_str(s).is_err());
    }

    #[test]
    fn test_p2tr_fixed_bytes() {
        let desc = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();
        let bytes = desc.to_fixed_payload_bytes::<P2TR_LEN>();
        assert_eq!(bytes.len(), P2TR_LEN);
    }

    #[test]
    fn test_p2pkh_fixed_bytes() {
        let desc = Descriptor::from_str("01b8268ce4d481413c4e848ff353cd16104291c45b").unwrap();
        let bytes = desc.to_fixed_payload_bytes::<P2PKH_LEN>();
        assert_eq!(bytes.len(), P2PKH_LEN);
    }

    #[cfg(feature = "address")]
    #[test]
    fn invalid_new_p2tr() {
        let invalid_payload = [0; P2TR_LEN];
        let result = Descriptor::new_p2tr(&invalid_payload);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            DescriptorError::InvalidXOnlyPublicKey
        );
    }
}
