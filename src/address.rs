//! # Address to Descriptor safe conversions.
//!
//! This module implements conversions between [`Address`] and [`Descriptor`].
//!
//! Note you need to use the `address` feature.
use bitcoin::{
    address::AddressData,
    hashes::{hash160::Hash, Hash as _},
    key::{TapTweak, TweakedPublicKey},
    Address, Network, ScriptBuf, ScriptHash, WitnessProgram, WitnessVersion, XOnlyPublicKey,
};

use crate::{fixed_bytes, Descriptor, DescriptorError, DescriptorType::*};

impl Descriptor {
    /// Converts the [`Descriptor`] to a Bitcoin [`Address`]
    /// given a [`Network`].
    pub fn to_address(&self, network: Network) -> Result<Address, DescriptorError> {
        match self.type_tag() {
            OpReturn => Err(DescriptorError::InvalidAddressConversion(OpReturn)),
            P2pkh => {
                fixed_bytes!(20);
                let bytes = to_fixed_bytes(self);
                let hash = Hash::from_bytes_ref(&bytes);
                let address = Address::p2pkh(*hash, network);
                Ok(address)
            }
            P2sh => {
                fixed_bytes!(20);
                let bytes = to_fixed_bytes(self);
                let hash = Hash::from_bytes_ref(&bytes);
                let script_hash = ScriptHash::from_raw_hash(*hash);
                let address = Address::p2sh_from_hash(script_hash, network);
                Ok(address)
            }
            P2wpkh => {
                fixed_bytes!(20);
                let bytes = to_fixed_bytes(self);
                // V0 is SegWit 20-bytes P2WPKH
                let witness_program = WitnessProgram::new(WitnessVersion::V0, &bytes)?;
                let address = Address::from_witness_program(witness_program, network);
                Ok(address)
            }
            P2wsh => {
                fixed_bytes!(32);
                let bytes = to_fixed_bytes(self);
                // V0 is SegWit 32-bytes P2WSH
                let witness_program = WitnessProgram::new(WitnessVersion::V0, &bytes)?;
                let address = Address::from_witness_program(witness_program, network);
                Ok(address)
            }
            P2tr => {
                fixed_bytes!(32);
                let bytes = to_fixed_bytes(self);
                let xonly_pubkey = XOnlyPublicKey::from_slice(&bytes)?;
                // WARN: we are assuming that the X-only public key is already tweaked
                //       and not the internal key.
                //       See [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
                //       for more details.
                let address =
                    Address::p2tr_tweaked(xonly_pubkey.dangerous_assume_tweaked(), network);
                Ok(address)
            }
        }
    }

    pub fn to_script_pubkey(&self) -> ScriptBuf {
        todo!()
    }
}

impl From<Address> for Descriptor {
    fn from(value: Address) -> Self {
        let address_data = value.to_address_data();
        match address_data {
            // P2PKH
            AddressData::P2pkh { pubkey_hash } => {
                let type_tag = [1u8];
                let payload = pubkey_hash.as_raw_hash().to_byte_array();
                let mut bytes = [0u8; 21];
                bytes[0] = type_tag[0];
                bytes[1..].copy_from_slice(&payload);
                Descriptor::from_bytes(&bytes).expect("infallible")
            }
            // P2SH
            AddressData::P2sh { script_hash } => {
                let type_tag = [2u8];
                let payload = script_hash.as_raw_hash().to_byte_array();
                let mut bytes = [0u8; 21];
                bytes[0] = type_tag[0];
                bytes[1..].copy_from_slice(&payload);
                Descriptor::from_bytes(&bytes).expect("infallible")
            }
            // SegWit V0/V1
            AddressData::Segwit { witness_program } => match witness_program.version() {
                WitnessVersion::V0 => {
                    let payload = witness_program.program().as_bytes();
                    let payload_len = payload.len();
                    match payload_len {
                        // P2WPKH: 20 bytes
                        20 => {
                            let type_tag = [3u8];
                            let mut bytes = [0u8; 21];
                            bytes[0] = type_tag[0];
                            bytes[1..].copy_from_slice(payload);
                            Descriptor::from_bytes(&bytes).expect("infallible")
                        }
                        // P2WSH: 32 bytes
                        32 => {
                            let type_tag = [3u8];
                            let mut bytes = [0u8; 33];
                            bytes[0] = type_tag[0];
                            bytes[1..].copy_from_slice(payload);
                            Descriptor::from_bytes(&bytes).expect("infallible")
                        }
                        // NOTE: cannot be anything else.
                        _ => unreachable!(),
                    }
                }
                // P2TR: 32 bytes
                WitnessVersion::V1 => {
                    let x_only_pk = witness_program.program().as_bytes();
                    let type_tag = [4u8];
                    let mut bytes = [0u8; 33];
                    bytes[0] = type_tag[0];
                    bytes[1..].copy_from_slice(x_only_pk);
                    Descriptor::from_bytes(&bytes).expect("infallible")
                }
                // NOTE: We don't have versions higher than V2 yet.
                _ => unreachable!(),
            },
            // NOTE: `AddressData` is a `#[non_exhaustive]` enum.
            _ => unreachable!(),
        }
    }
}

impl From<ScriptHash> for Descriptor {
    fn from(script_hash: ScriptHash) -> Self {
        let payload: &[u8; 20] = script_hash.as_ref();
        let mut bytes = [0u8; 21];
        bytes[0] = 0x02;
        bytes[1..].copy_from_slice(payload);
        Descriptor::from_bytes(&bytes).expect("infallible")
    }
}

impl From<WitnessProgram> for Descriptor {
    fn from(witness_program: WitnessProgram) -> Self {
        let payload: &[u8] = witness_program.program().as_bytes();
        match witness_program.version() {
            // V0 is SegWit 20-bytes P2WPKH or 32-bytes P2WSH
            WitnessVersion::V0 => {
                let mut bytes = [0u8; 21];
                bytes[0] = 0x03;
                bytes[1..].copy_from_slice(payload);
                Descriptor::from_bytes(&bytes).expect("infallible")
            }
            // V1 is SegWit 32-bytes P2TR
            WitnessVersion::V1 => {
                let mut bytes = [0u8; 22];
                bytes[0] = 0x04;
                bytes[1..].copy_from_slice(payload);
                Descriptor::from_bytes(&bytes).expect("infallible")
            }
            // NOTE: We don't have versions higher than V2 yet.
            _ => unreachable!(),
        }
    }
}

impl From<TweakedPublicKey> for Descriptor {
    fn from(tweaked_pubkey: TweakedPublicKey) -> Self {
        // NOTE: Guaranteed to have 32 bytes.
        let payload = tweaked_pubkey.serialize();
        let mut bytes = [0u8; 33];
        bytes[0] = 0x04;
        bytes[1..].copy_from_slice(&payload);
        Descriptor::from_bytes(&bytes).expect("infallible")
    }
}

impl From<XOnlyPublicKey> for Descriptor {
    fn from(x_only_pubkey: XOnlyPublicKey) -> Self {
        // NOTE: Guaranteed to have 32 bytes.
        let payload = x_only_pubkey.serialize();
        let mut bytes = [0u8; 33];
        bytes[0] = 0x04;
        bytes[1..].copy_from_slice(&payload);
        Descriptor::from_bytes(&bytes).expect("infallible")
    }
}
