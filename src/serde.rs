//! Custom serialization and deserialization for [`Descriptor`] using
//! [`serde`](https://serde.rs).

use hex::{DisplayHex, FromHex};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::Descriptor;

impl Serialize for Descriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the descriptor to bytes
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            // For human-readable formats, convert to hex string
            bytes.to_lower_hex_string().serialize(serializer)
        } else {
            // For non-human-readable formats, use bytes directly
            bytes.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Descriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // For human-readable formats, expect hex string
            let hex_str = String::deserialize(deserializer)?;
            let bytes = Vec::from_hex(&hex_str).map_err(Error::custom)?;
            if bytes.is_empty() {
                return Err(Error::custom("empty input"));
            }
            Descriptor::from_vec(bytes).map_err(Error::custom)
        } else {
            // For non-human-readable formats, expect bytes directly
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            if bytes.is_empty() {
                return Err(Error::custom("empty input"));
            }
            Descriptor::from_vec(bytes).map_err(Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DescriptorType;
    use std::str::FromStr;

    #[cfg(test)]
    mod proptest_tests {
        use super::*;
        use crate::descriptor::MAX_OP_RETURN_LEN;
        use proptest::prelude::*;

        proptest! {
            /// Test that `OP_RETURN` descriptors serialize/deserialize correctly.
            #[test]
            fn op_return_serialization_roundtrip_property(data in prop::collection::vec(any::<u8>(), 0..=MAX_OP_RETURN_LEN)) {
                if data.len() <= MAX_OP_RETURN_LEN {
                    let mut bytes = vec![0u8; data.len() + 1];
                    bytes[0] = 0; // OP_RETURN type tag
                    bytes[1..].copy_from_slice(&data);

                    let descriptor = Descriptor::from_bytes(&bytes).expect("valid OP_RETURN should parse");

                    // Test JSON serialization
                    let json_serialized = serde_json::to_string(&descriptor).unwrap();
                    let json_deserialized: Descriptor = serde_json::from_str(&json_serialized).unwrap();
                    assert_eq!(descriptor, json_deserialized);

                    // Test bincode serialization
                    let bincode_serialized = bincode::serialize(&descriptor).unwrap();
                    let bincode_deserialized: Descriptor = bincode::deserialize(&bincode_serialized).unwrap();
                    assert_eq!(descriptor, bincode_deserialized);
                }
            }
        }
    }

    /// Helper function to test both JSON and bincode serialization.
    fn test_roundtrip(descriptor: &Descriptor) {
        // JSON (human-readable) serialization
        let json_serialized = serde_json::to_string(&descriptor).unwrap();
        let json_deserialized: Descriptor = serde_json::from_str(&json_serialized).unwrap();
        assert_eq!(*descriptor, json_deserialized);

        // Bincode (non-human-readable) serialization
        let bincode_serialized = bincode::serialize(&descriptor).unwrap();
        let bincode_deserialized: Descriptor = bincode::deserialize(&bincode_serialized).unwrap();
        assert_eq!(*descriptor, bincode_deserialized);

        // Verify different serialization formats produce different results
        let json_bytes = serde_json::to_vec(&descriptor).unwrap();
        assert_ne!(bincode_serialized, json_bytes);
    }

    #[test]
    fn invalid_deserialization() {
        // Test invalid JSON (hex string)
        let invalid_json = "\"0500000000000000000000000000000000000000000000000000000000000000\"";
        let json_result: Result<Descriptor, _> = serde_json::from_str(invalid_json);
        assert!(json_result.is_err());

        // Test invalid bincode (raw bytes)
        let invalid_bytes: Vec<u8> = vec![5; 33]; // invalid type tag
        let bincode_result: Result<Descriptor, _> = bincode::deserialize(&invalid_bytes);
        assert!(bincode_result.is_err());

        // Test empty input
        let empty_json_result: Result<Descriptor, _> = serde_json::from_str("\"\"");
        let empty_bincode_result: Result<Descriptor, _> = bincode::deserialize::<Descriptor>(&[]);
        assert!(empty_json_result.is_err());
        assert!(empty_bincode_result.is_err());
    }

    #[test]
    fn serde_op_return() {
        // OP_RETURN in hex string replacing the 6a (`OP_RETURN`)
        // for a 0x00 (type_tag) byte for `OP_RETURN`.
        // Source: https://bitcoin.stackexchange.com/a/29555
        //         and transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        let descriptor = Descriptor::from_str("00636861726c6579206c6f766573206865696469").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::OpReturn);
        assert_eq!(descriptor.payload(), b"charley loves heidi");
    }

    #[test]
    fn serde_p2pkh() {
        // P2PKH
        // Using 0x01 (type_tag) and a 20-byte hash
        // Source: transaction 8bae12b5f4c088d940733dcd1455efc6a3a69cf9340e17a981286d3778615684
        // Corresponds to address `1HnhWpkMHMjgt167kvgcPyurMmsCQ2WPgg`
        let descriptor =
            Descriptor::from_str("01b8268ce4d481413c4e848ff353cd16104291c45b").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2pkh);
    }

    #[test]
    fn serde_p2sh() {
        // P2SH
        // Using 0x02 (type_tag) and a 20-byte hash
        // Source: transaction a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f
        // Corresponds to address `3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V`
        let descriptor =
            Descriptor::from_str("02748284390f9e263a4b766a75d0633c50426eb875").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2sh);
    }

    #[test]
    fn serde_p2wpkh() {
        // Using 0x03 (type_tag) and a 20-byte hash
        // Source: transaction 7c53ba0f1fc65f021749cac6a9c163e499fcb2e539b08c040802be55c33d32fe
        // Corresponds to address `bc1qvugyzunmnq5y8alrmdrxnsh4gts9p9hmvhyd40`
        let descriptor =
            Descriptor::from_str("03671041727b982843f7e3db4669c2f542e05096fb").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2wpkh);
    }

    #[test]
    fn serde_p2wsh() {
        // P2WSH
        // Using 0x03 (type_tag) and a 32-byte hash
        // Source: transaction fbf3517516ebdf03358a9ef8eb3569f96ac561c162524e37e9088eb13b228849
        // Corresponds to address `bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65`
        let descriptor = Descriptor::from_str(
            "0365f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3",
        )
        .unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2wsh);
    }

    #[test]
    fn serde_p2tr() {
        // P2TR
        // Using 0x04 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let descriptor = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2tr);
    }

    #[test]
    fn compare_serialization_formats() {
        // P2TR
        // Using 0x04 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let descriptor = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();

        // Get serialized data in different formats
        let json_bytes = serde_json::to_vec(&descriptor).unwrap();
        let bincode_bytes = bincode::serialize(&descriptor).unwrap();

        // Verify they're different
        assert_ne!(json_bytes, bincode_bytes);

        // Verify both can be deserialized correctly
        let json_deserialized: Descriptor = serde_json::from_slice(&json_bytes).unwrap();
        let bincode_deserialized: Descriptor = bincode::deserialize(&bincode_bytes).unwrap();

        assert_eq!(descriptor, json_deserialized);
        assert_eq!(descriptor, bincode_deserialized);
    }

    #[test]
    fn test_human_readable_format() {
        // P2TR
        // Using 0x04 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let descriptor = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();

        // Serialize to string (human-readable)
        let json_string = serde_json::to_string(&descriptor).unwrap();

        // Verify it's actually readable (contains hex characters)
        assert!(json_string
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '"'));

        // Deserialize and verify
        let deserialized: Descriptor = serde_json::from_str(&json_string).unwrap();
        assert_eq!(descriptor, deserialized);
    }
}
