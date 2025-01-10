//! Error types for the Bitcoin BOSD library.

use hex::error::HexToBytesError;
use thiserror::Error;

use crate::DescriptorType;

#[cfg(feature = "address")]
use bitcoin::script::witness_program::Error as WitnessProgramError;
#[cfg(feature = "address")]
use bitcoin::secp256k1::Error as Secp256k1Error;

/// Errors related to [`Descriptor`](crate::Descriptor).
#[derive(Error, Debug)]
pub enum DescriptorError {
    /// Missing type tag
    #[error("missing type tag")]
    MissingTypeTag,

    /// Invalid descriptor type tag.
    #[error("invalid descriptor type tag: {0}")]
    InvalidDescriptorType(u8),

    /// Invalid payload length.
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(usize),

    /// Hex decoding error.
    #[error("hex decoding error: {0}")]
    HexDecodingError(#[from] HexToBytesError),

    /// Invalid [`Address`](bitcoin::Address) conversion.
    ///
    /// Currently only suscetible for `OP_RETURN` descriptors
    /// being converted to a bitcoin address.
    #[cfg(feature = "address")]
    #[error("{0:?} cannot be converted to a bitcoin address")]
    InvalidAddressConversion(DescriptorType),

    /// [`secp256k1`](bitcoin::secp256k1) errors.
    #[cfg(feature = "address")]
    #[error("secp256k1 error: {0}")]
    Secp256k1Error(#[from] Secp256k1Error),

    /// [`WitnessProgram`](bitcoin::WitnessProgram) errors.
    #[cfg(feature = "address")]
    #[error("witness program error: {0}")]
    WitnessProgramError(#[from] WitnessProgramError),
}
