//! Error types for the Bitcoin BOSD library.

use thiserror::Error;

/// Errors related to [`Descriptor`](crate::Descriptor).
#[derive(Error, Debug)]
pub enum DescriptorError {
    /// Invalid descriptor type tag.
    #[error("invalid descriptor type tag: {0}")]
    InvalidDescriptorType(u8),
}
