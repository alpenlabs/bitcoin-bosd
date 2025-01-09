//! Error types for the Bitcoin BOSD library.

use hex::error::HexToBytesError;
use thiserror::Error;

/// Errors related to [`Descriptor`](crate::Descriptor).
#[derive(Error, Debug)]
pub enum DescriptorError {
    /// Invalid descriptor type tag.
    #[error("invalid descriptor type tag: {0}")]
    InvalidDescriptorType(u8),

    /// Invalid payload length.
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(usize),

    /// Invalid descriptor type tag length.
    #[error("invalid descriptor type tag length: {0}")]
    InvalidDescriptorTypeLength(usize),

    /// Hex decoding error.
    #[error("hex decoding error: {0}")]
    HexDecodingError(#[from] HexToBytesError),
}
