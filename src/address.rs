//! # Address to Descriptor safe conversions.
//!
//! This module implements conversions between [`Address`] and [`Descriptor`].
//!
//! Note you need to use the `address` feature.
use bitcoin::{Address, ScriptBuf};

use crate::{Descriptor, DescriptorError};

impl Descriptor {
    pub fn to_address(&self) -> Result<Address, DescriptorError> {
        todo!()
    }

    pub fn to_script_pubkey(&self) -> Result<ScriptBuf, DescriptorError> {
        todo!()
    }
}
