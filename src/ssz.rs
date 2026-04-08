//! Custom serialization and deserialization for [`Descriptor`] using
//! Alpen Labs' SimpleSerialize (SSZ) flavour.

use ssz_types::VariableList;

use crate::{descriptor::MAX_OP_RETURN_LEN, Descriptor};

/// Maximum allowed descriptor length for SSZ decoding.
///
/// This is the maximum valid BOSD byte length: one type tag byte plus the largest permitted
/// `OP_RETURN` payload.
pub const MAX_DESCRIPTOR_SSZ_LEN: usize = MAX_OP_RETURN_LEN + 1;

/// The SSZ representation used for BOSD descriptors.
///
/// BOSD is encoded as an opaque `VariableList<u8, MAX_DESCRIPTOR_SSZ_LEN>` rather than as a
/// structured SSZ container.
type DescriptorByteList = VariableList<u8, MAX_DESCRIPTOR_SSZ_LEN>;

/// Converts a descriptor into the SSZ list type used by this module.
///
/// This keeps the SSZ implementation delegated to `VariableList` instead of hand-rolling
/// BOSD-specific SSZ pointer handling.
fn descriptor_to_ssz_bytes(descriptor: &Descriptor) -> DescriptorByteList {
    DescriptorByteList::try_from(descriptor.to_bytes())
        .expect("descriptor bytes are always within the SSZ maximum bound")
}

impl ::ssz::Encode for Descriptor {
    fn is_ssz_fixed_len() -> bool {
        <DescriptorByteList as ::ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <DescriptorByteList as ::ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        descriptor_to_ssz_bytes(self).ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        descriptor_to_ssz_bytes(self).ssz_append(buf);
    }
}

impl ::ssz::Decode for Descriptor {
    fn is_ssz_fixed_len() -> bool {
        <DescriptorByteList as ::ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <DescriptorByteList as ::ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ::ssz::DecodeError> {
        let descriptor_bytes = <DescriptorByteList as ::ssz::Decode>::from_ssz_bytes(bytes)?;

        Descriptor::from_vec(descriptor_bytes.into()).map_err(|err| {
            ::ssz::DecodeError::BytesInvalid(format!("invalid BOSD descriptor: {err}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ::ssz::{Decode, Encode};
    use proptest::prelude::*;

    use super::*;
    use crate::{descriptor::MAX_OP_RETURN_LEN, DescriptorType};

    fn test_roundtrip(descriptor: &Descriptor) {
        let encoded = descriptor.as_ssz_bytes();
        let decoded = Descriptor::from_ssz_bytes(&encoded).unwrap();

        assert_eq!(encoded, descriptor.to_bytes());
        assert_eq!(descriptor.ssz_bytes_len(), encoded.len());
        assert_eq!(*descriptor, decoded);
    }

    #[test]
    fn ssz_op_return() {
        let descriptor = Descriptor::from_str("00636861726c6579206c6f766573206865696469").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::OpReturn);
        assert_eq!(descriptor.payload(), b"charley loves heidi");
    }

    #[test]
    fn ssz_p2pkh() {
        let descriptor =
            Descriptor::from_str("01b8268ce4d481413c4e848ff353cd16104291c45b").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2pkh);
    }

    #[test]
    fn ssz_p2sh() {
        let descriptor =
            Descriptor::from_str("02748284390f9e263a4b766a75d0633c50426eb875").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2sh);
    }

    #[test]
    fn ssz_p2wpkh() {
        let descriptor =
            Descriptor::from_str("03671041727b982843f7e3db4669c2f542e05096fb").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2wpkh);
    }

    #[test]
    fn ssz_p2wsh() {
        let descriptor = Descriptor::from_str(
            "0365f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3",
        )
        .unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2wsh);
    }

    #[test]
    fn ssz_p2a() {
        let descriptor = Descriptor::from_str("04").unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2a);
    }

    #[test]
    fn ssz_p2tr() {
        let descriptor = Descriptor::from_str(
            "040f0c8db753acbd17343a39c2f3f4e35e4be6da749f9e35137ab220e7b238a667",
        )
        .unwrap();

        test_roundtrip(&descriptor);
        assert_eq!(descriptor.type_tag(), DescriptorType::P2tr);
    }

    #[test]
    fn invalid_ssz_deserialization() {
        let invalid_bytes: Vec<u8> = vec![5; 33];
        let result = Descriptor::from_ssz_bytes(&invalid_bytes);

        assert!(result.is_err());
    }

    #[test]
    fn ssz_empty_input_rejected() {
        let result = Descriptor::from_ssz_bytes(&[]);

        assert!(result.is_err());
    }

    #[test]
    fn ssz_oversized_length_rejected() {
        let oversized = vec![0u8; MAX_DESCRIPTOR_SSZ_LEN + 1];
        let result = Descriptor::from_ssz_bytes(&oversized);

        assert!(matches!(result, Err(::ssz::DecodeError::BytesInvalid(_))));
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn ssz_in_range_invalid_bosd_rejected() {
        let invalid = vec![0x03, 0x01];
        let result = Descriptor::from_ssz_bytes(&invalid);

        assert!(matches!(result, Err(::ssz::DecodeError::BytesInvalid(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid BOSD descriptor"));
    }

    proptest! {
        #[test]
        fn ssz_roundtrip_property(data in prop::collection::vec(any::<u8>(), 1..=(MAX_OP_RETURN_LEN + 1))) {
            if let Ok(descriptor) = Descriptor::from_bytes(&data) {
                let encoded = descriptor.as_ssz_bytes();
                let decoded = Descriptor::from_ssz_bytes(&encoded).unwrap();

                prop_assert_eq!(encoded, data);
                prop_assert_eq!(descriptor, decoded);
            }
        }
    }
}
