//! # Bitcoin Output Script Descriptor (BOSD)
//!
//! This module implements a BOSD parser and validator.
//!
//! The main type is [`Descriptor`].

use crate::error::DescriptorError;

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
pub struct Descriptor<'a> {
    /// The type of the descriptor.
    type_tag: DescriptorType,

    /// The actual underlying data.
    payload: &'a [u8],
}

impl<'a> Descriptor<'a> {
    /// Constructs a new [`Descriptor`] from a byte slice.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, DescriptorError> {
        let type_tag = DescriptorType::from_u8(bytes[0])?;
        let payload = &bytes[1..];
        Ok(Self { type_tag, payload })
    }

    /// Returns the type tag of the descriptor.
    pub fn type_tag(&self) -> DescriptorType {
        self.type_tag
    }

    /// Returns the payload of the descriptor.
    ///
    /// # Warning
    ///
    /// It is not advisabled to use this method.
    /// Instead, try to parse it as either as a Bitcoin address
    /// by using [`Descriptor::to_address`] in the case of a address,
    /// or as a Bitcoin script by using [`Descriptor::to_script_pubkey`] in
    /// the case of an `OP_RETURN` payload.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// The type tag of a [`Descriptor`].
///
/// This is the first byte of the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            DescriptorType::P2wsh => 4,
            DescriptorType::P2tr => 5,
        }
    }

    fn from_u8(byte: u8) -> Result<Self, DescriptorError> {
        match byte {
            0 => Ok(DescriptorType::OpReturn),
            1 => Ok(DescriptorType::P2pkh),
            2 => Ok(DescriptorType::P2sh),
            3 => Ok(DescriptorType::P2wpkh),
            4 => Ok(DescriptorType::P2wsh),
            5 => Ok(DescriptorType::P2tr),
            _ => Err(DescriptorError::InvalidDescriptorType(byte)),
        }
    }
}
