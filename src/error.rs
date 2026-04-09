//! Error types for the Bitcoin BOSD library.

use core::fmt;

#[cfg(feature = "address")]
use bitcoin::script::witness_program::Error as WitnessProgramError;
#[cfg(feature = "address")]
use bitcoin::secp256k1::Error as Secp256k1Error;
use hex::error::HexToBytesError;

use crate::DescriptorType;

/// Errors related to [`Descriptor`](crate::Descriptor).
#[derive(Debug, PartialEq, Eq)]
pub enum DescriptorError {
    /// Missing type tag.
    MissingTypeTag,

    /// Invalid descriptor type tag.
    InvalidDescriptorType(u8),

    /// Invalid payload length.
    InvalidPayloadLength(usize),

    /// Invalid X-only public key.
    InvalidXOnlyPublicKey,

    /// Hex decoding error.
    HexDecodingError(HexToBytesError),

    /// Invalid [`Address`](bitcoin::Address) conversion.
    ///
    /// Currently only susceptible for `OP_RETURN` descriptors
    /// being converted to a bitcoin address.
    #[cfg(feature = "address")]
    InvalidAddressConversion(DescriptorType),

    /// [`secp256k1`] errors.
    #[cfg(feature = "address")]
    Secp256k1Error(Secp256k1Error),

    /// [`WitnessProgram`](bitcoin::WitnessProgram) errors.
    #[cfg(feature = "address")]
    WitnessProgramError(WitnessProgramError),

    /// Unsupported witness program.
    ///
    /// The witness program is consensus-valid but not representable
    /// as a standard descriptor (e.g., non-standard v0/v1 lengths,
    /// future witness versions v2+, or non-P2A 2-byte v1 programs).
    #[cfg(feature = "address")]
    UnsupportedWitnessProgram(String),
}

impl core::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTypeTag => write!(f, "missing type tag"),
            Self::InvalidDescriptorType(tag) => write!(f, "invalid descriptor type tag: {tag}"),
            Self::InvalidPayloadLength(len) => write!(f, "invalid payload length: {len}"),
            Self::InvalidXOnlyPublicKey => write!(f, "invalid X-only public key"),
            Self::HexDecodingError(err) => write!(f, "hex decoding error: {err}"),
            #[cfg(feature = "address")]
            Self::InvalidAddressConversion(desc_type) => write!(
                f,
                "{desc_type} locking script cannot be converted into a bitcoin address"
            ),
            #[cfg(feature = "address")]
            Self::Secp256k1Error(err) => write!(f, "secp256k1 error: {err}"),
            #[cfg(feature = "address")]
            Self::WitnessProgramError(err) => write!(f, "witness program error: {err}"),
            #[cfg(feature = "address")]
            Self::UnsupportedWitnessProgram(msg) => write!(f, "unsupported witness program: {msg}"),
        }
    }
}

// TODO: uncomment feature flag when no-std is supported
//#[cfg(feature = "std")]
impl std::error::Error for DescriptorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HexDecodingError(err) => Some(err),
            #[cfg(feature = "address")]
            Self::Secp256k1Error(err) => Some(err),
            #[cfg(feature = "address")]
            Self::WitnessProgramError(err) => Some(err),
            #[cfg(feature = "address")]
            Self::UnsupportedWitnessProgram(_) => None,
            _ => None,
        }
    }
}

impl From<HexToBytesError> for DescriptorError {
    fn from(err: HexToBytesError) -> Self {
        Self::HexDecodingError(err)
    }
}

#[cfg(feature = "address")]
impl From<Secp256k1Error> for DescriptorError {
    fn from(err: Secp256k1Error) -> Self {
        Self::Secp256k1Error(err)
    }
}

#[cfg(feature = "address")]
impl From<WitnessProgramError> for DescriptorError {
    fn from(err: WitnessProgramError) -> Self {
        Self::WitnessProgramError(err)
    }
}
