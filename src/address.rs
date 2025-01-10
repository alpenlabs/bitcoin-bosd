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
                let payload_len = payload.len();
                match payload_len {
                    // P2WPKH: 20-bytes
                    20 => {
                        let mut bytes = [0u8; 21];
                        bytes[0] = 0x03;
                        bytes[1..].copy_from_slice(payload);
                        Descriptor::from_bytes(&bytes).expect("infallible")
                    }
                    // P2WSH: 32-bytes
                    32 => {
                        let mut bytes = [0u8; 33];
                        bytes[0] = 0x03;
                        bytes[1..].copy_from_slice(payload);
                        Descriptor::from_bytes(&bytes).expect("infallible")
                    }
                    // NOTE: cannot be anything else.
                    _ => unreachable!(),
                }
            }
            // V1 is SegWit 32-bytes P2TR
            WitnessVersion::V1 => {
                let mut bytes = [0u8; 33];
                bytes[0] = 0x04;
                bytes[1..].copy_from_slice(payload);
                Descriptor::from_bytes(&bytes).expect("infallible")
            }
            // NOTE: We don't have versions higher than V2 yet.
            _ => unreachable!(),
        }
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

#[cfg(test)]
mod tests {
    use bitcoin::address::NetworkUnchecked;

    use super::*;

    #[test]
    fn p2pkh() {
        // P2PKH
        // Using 0x01 (type_tag) and a 20-byte hash
        // Source: transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        // Corresponds to address `1HnhWpkMHMjgt167kvgcPyurMmsCQ2WPgg`
        let address = "1HnhWpkMHMjgt167kvgcPyurMmsCQ2WPgg";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let desc = Descriptor::from(address.clone());
        assert_eq!(desc.type_tag(), P2pkh);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn p2sh() {
        // P2SH
        // Using 0x02 (type_tag) and a 20-byte hash
        // Source: transaction a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f
        // Corresponds to address `3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V`
        let address = "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let desc = Descriptor::from(address.clone());
        assert_eq!(desc.type_tag(), P2sh);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn p2wpkh() {
        // P2WPKH
        // Using 0x03 (type_tag) and a 20-byte hash
        // Source: transaction 7c53ba0f1fc65f021749cac6a9c163e499fcb2e539b08c040802be55c33d32fe
        // Corresponds to address `bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40`
        let address = "bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let desc = Descriptor::from(address.clone());
        assert_eq!(desc.type_tag(), P2wpkh);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn p2wsh() {
        // P2WSH
        // Using 0x3 (type_tag) and a 32-byte hash
        // Source: transaction fbf3517516ebdf03358a9ef8eb3569f96ac561c162524e37e9088eb13b228849
        // Corresponds to address `bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65`
        let address = "bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let desc = Descriptor::from(address.clone());
        assert_eq!(desc.type_tag(), P2wsh);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn p2tr() {
        // Using 0x4 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let address = "bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let desc = Descriptor::from(address.clone());
        assert_eq!(desc.type_tag(), P2tr);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn from_script_hash() {
        // P2SH
        // Using 0x02 (type_tag) and a 20-byte hash
        // Source: transaction a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f
        // Corresponds to address `3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V`
        let hash = "748284390f9e263a4b766a75d0633c50426eb875";
        let hash = hash.parse::<ScriptHash>().unwrap();
        let desc = Descriptor::from(hash);
        assert_eq!(desc.type_tag(), P2sh);

        let address = Address::p2sh_from_hash(hash, Network::Bitcoin);
        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn from_witness_program() {
        // P2WPKH
        // Using 0x03 (type_tag) and a 20-byte hash
        // Source: transaction 7c53ba0f1fc65f021749cac6a9c163e499fcb2e539b08c040802be55c33d32fe
        // Corresponds to address `bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40`
        let address = "bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let witness_program = address.witness_program().unwrap();
        let desc = Descriptor::from(witness_program);
        assert_eq!(desc.type_tag(), P2wpkh);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);

        // P2WSH
        // Using 0x3 (type_tag) and a 32-byte hash
        // Source: transaction fbf3517516ebdf03358a9ef8eb3569f96ac561c162524e37e9088eb13b228849
        // Corresponds to address `bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65`
        let address = "bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let witness_program = address.witness_program().unwrap();
        let desc = Descriptor::from(witness_program);
        assert_eq!(desc.type_tag(), P2wsh);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);

        // P2TR
        // Using 0x4 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let address = "bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let witness_program = address.witness_program().unwrap();
        let desc = Descriptor::from(witness_program);
        assert_eq!(desc.type_tag(), P2tr);

        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn xonly_pubkey() {
        // P2TR
        // Using 0x4 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let xonly_pk = "0f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667";
        let xonly_pk = xonly_pk.parse::<XOnlyPublicKey>().unwrap();
        let desc = Descriptor::from(xonly_pk);
        assert_eq!(desc.type_tag(), P2tr);

        let address = "bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }

    #[test]
    fn tweaked_pubkey() {
        // P2TR
        // Using 0x4 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let xonly_pk = "0f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667";
        let xonly_pk = xonly_pk.parse::<XOnlyPublicKey>().unwrap();
        let tweaked_pk = xonly_pk.dangerous_assume_tweaked();
        let desc = Descriptor::from(tweaked_pk);
        assert_eq!(desc.type_tag(), P2tr);

        let address = "bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf";
        let address = address
            .parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked();
        let address_translated = desc.to_address(Network::Bitcoin).unwrap();
        assert_eq!(address, address_translated);
    }
}
