//! Custom serialization and deserialization for [`Descriptor`] using
//! [`borsh`](https://borsh.io/).

use std::io;

use borsh::{de::BorshDeserialize, ser::BorshSerialize};

use crate::Descriptor;

impl BorshSerialize for Descriptor {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        // Convert to bytes and write them
        let bytes = self.to_bytes();
        // Write the length first (borsh prefix arrays with length)
        (bytes.len() as u32).serialize(writer)?;
        // Write the actual bytes
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for Descriptor {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        // Read length
        let len = u32::deserialize_reader(reader)?;
        // Read bytes
        let mut bytes = vec![0u8; len as usize];
        reader.read_exact(&mut bytes)?;
        // Convert to Descriptor
        Descriptor::from_vec(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid descriptor: {e}"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::DescriptorType;

    use super::*;
    use borsh::{to_vec, BorshDeserialize};

    #[test]
    fn invalid_borsh_deserialization() {
        // Create invalid data
        let invalid_bytes: Vec<u8> = vec![5; 33]; // invalid type tag

        let result = Descriptor::try_from_slice(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn borsh_op_return() {
        // OP_RETURN in hex string replacing the 6a (`OP_RETURN`)
        // for a 0x00 (type_tag) byte for `OP_RETURN`.
        // Source: https://bitcoin.stackexchange.com/a/29555
        //         and transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        let original = Descriptor::from_str("00636861726c6579206c6f766573206865696469").unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::OpReturn);
        assert_eq!(deserialized.payload(), b"charley loves heidi");
    }

    #[test]
    fn borsh_p2pkh() {
        // P2PKH
        // Using 0x01 (type_tag) and a 20-byte hash
        // Source: transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        // Corresponds to address `1HnhWpkMHMjgt167kvgcPyurMmsCQ2WPgg`
        let original = Descriptor::from_str("01b8268ce4d481413c4e848ff353cd16104291c45b").unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::P2pkh);
    }

    #[test]
    fn borsh_p2sh() {
        // P2SH
        // Using 0x02 (type_tag) and a 20-byte hash
        // Source: transaction a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f
        // Corresponds to address `3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V`
        let original = Descriptor::from_str("02748284390f9e263a4b766a75d0633c50426eb875").unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::P2sh);
    }

    #[test]
    fn borsh_p2wpkh() {
        // Using 0x03 (type_tag) and a 20-byte hash
        // Source: transaction 7c53ba0f1fc65f021749cac6a9c163e499fcb2e539b08c040802be55c33d32fe
        // Corresponds to address `bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40`
        let original = Descriptor::from_str("03671041727b982843f7e3db4669c2f542e05096fb").unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::P2wpkh);
    }

    #[test]
    fn borsh_p2wsh() {
        // P2WSH
        // Using 0x03 (type_tag) and a 32-byte hash
        // Source: transaction fbf3517516ebdf03358a9ef8eb3569f96ac561c162524e37e9088eb13b228849
        // Corresponds to address `bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65`
        let original = Descriptor::from_str(
            "0365f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3",
        )
        .unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::P2wsh);
    }

    #[test]
    fn borsh_p2a() {
        // P2A
        // Using 0x04 (type_tag) and a 0-byte payload
        // Source: transaction c054743f0f3ecfac2cf08c40c7dd36fcb38928cf8e07d179693ca2692d041848
        // Corresponds to address `bc1pfeessrawgf`
        let original = Descriptor::from_str("04").unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::P2a);
    }

    #[test]
    fn borsh_p2tr() {
        // P2TR
        // Using 0x04 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let original = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();

        let serialized = to_vec(&original).unwrap();
        let deserialized = Descriptor::try_from_slice(&serialized).unwrap();

        assert_eq!(original, deserialized);
        assert_eq!(deserialized.type_tag(), DescriptorType::P2tr);
    }
}
