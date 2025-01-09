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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_from_bytes() {
        let bytes = [0, 1, 2, 3, 4, 5];
        let descriptor = Descriptor::from_bytes(&bytes).unwrap();
        assert_eq!(descriptor.type_tag(), DescriptorType::OpReturn);
        assert_eq!(descriptor.payload(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn descriptor_from_bytes_invalid() {
        let bytes = [6, 1, 2, 3, 4, 5, 6];
        assert!(Descriptor::from_bytes(&bytes).is_err());
    }

    #[test]
    fn descriptor_type() {
        assert_eq!(DescriptorType::OpReturn.to_u8(), 0);
        assert_eq!(DescriptorType::P2pkh.to_u8(), 1);
        assert_eq!(DescriptorType::P2sh.to_u8(), 2);
        assert_eq!(DescriptorType::P2wpkh.to_u8(), 3);
        assert_eq!(DescriptorType::P2wsh.to_u8(), 4);
        assert_eq!(DescriptorType::P2tr.to_u8(), 5);

        assert_eq!(
            DescriptorType::from_u8(0).unwrap(),
            DescriptorType::OpReturn
        );
        assert_eq!(DescriptorType::from_u8(1).unwrap(), DescriptorType::P2pkh);
        assert_eq!(DescriptorType::from_u8(2).unwrap(), DescriptorType::P2sh);
        assert_eq!(DescriptorType::from_u8(3).unwrap(), DescriptorType::P2wpkh);
        assert_eq!(
            DescriptorType::from_u8(4).unwrap(), // P2WSH
            DescriptorType::P2wsh
        );
        assert_eq!(
            DescriptorType::from_u8(5).unwrap(), // P2TR
            DescriptorType::P2tr
        );
    }

    #[test]
    fn invalid_descriptor_type() {
        assert!(DescriptorType::from_u8(6).is_err());
        assert!(DescriptorType::from_u8(7).is_err());
    }
}
