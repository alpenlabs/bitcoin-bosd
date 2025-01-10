//! Custom serialization and deserialization for [`Descriptor`] using
//! [`serde`](https://serde.rs).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Descriptor;

impl Serialize for Descriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the descriptor to bytes and serialize them
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Descriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as bytes and convert to Descriptor
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Descriptor::from_vec(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn serde_roundtrip() {
        // P2TR
        // Using 0x4 (type_tag) and a 32-byte hash
        // Source: transaction a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec
        // Corresponds to address `bc1ppuxgmd6n4j73wdp688p08a8rte97dkn5n70r2ym6kgsw0v3c5ensrytduf`
        let original = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();

        // Serialize
        let serialized = serde_json::to_vec(&original).unwrap();

        // Deserialize
        let deserialized: Descriptor = serde_json::from_slice(&serialized).unwrap();

        // Compare
        assert_eq!(original, deserialized);
    }

    #[test]
    fn invalid_deserialization() {
        // Try to deserialize invalid data
        let invalid_bytes = vec![5u8; 33]; // Invalid type tag
        let result: Result<Descriptor, _> = serde_json::from_slice(&invalid_bytes);
        assert!(result.is_err());
    }
}
