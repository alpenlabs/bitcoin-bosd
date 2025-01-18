use arbitrary::{Arbitrary, Error, Result, Unstructured};
use bitcoin::{key::Keypair, secp256k1::SecretKey};
use secp256k1::SECP256K1; // Global context

use crate::descriptor::{
    Descriptor, MAX_OP_RETURN_LEN, P2PKH_LEN, P2SH_LEN, P2TR_LEN, P2WPKH_LEN, P2WSH_LEN,
};

impl<'a> Arbitrary<'a> for Descriptor {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        // First generate a random type tag (0-4)
        let type_tag: u8 = u.int_in_range(0..=4)?;

        // Generate appropriate payload based on type
        let payload = match type_tag {
            0 => {
                // OP_RETURN: Random length up to MAX_OP_RETURN_LEN
                let len = u.int_in_range(0..=MAX_OP_RETURN_LEN)?;
                let mut bytes = vec![0u8; len];
                u.fill_buffer(&mut bytes)?;
                bytes
            }
            1 => {
                // P2PKH: Exactly P2PKH_LEN bytes
                let mut bytes = vec![0u8; P2PKH_LEN];
                u.fill_buffer(&mut bytes)?;
                bytes
            }
            2 => {
                // P2SH: Exactly P2SH_LEN bytes
                let mut bytes = vec![0u8; P2SH_LEN];
                u.fill_buffer(&mut bytes)?;
                bytes
            }
            3 => {
                // P2WPKH/P2WSH: Either P2WPKH_LEN or P2WSH_LEN bytes
                if u.arbitrary::<bool>()? {
                    let mut bytes = vec![0u8; P2WPKH_LEN];
                    u.fill_buffer(&mut bytes)?;
                    bytes
                } else {
                    let mut bytes = vec![0u8; P2WSH_LEN];
                    u.fill_buffer(&mut bytes)?;
                    bytes
                }
            }
            4 => {
                // P2TR: Generate a valid X-only public key
                let mut secret_bytes = [0u8; 32];
                u.fill_buffer(&mut secret_bytes)?;
                // Keep trying until we get a valid key
                while SecretKey::from_slice(&secret_bytes).is_err() {
                    u.fill_buffer(&mut secret_bytes)?;
                }
                let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
                let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
                let (x_only_pub_key, _parity) = keypair.x_only_public_key();
                let bytes = x_only_pub_key.serialize().to_vec();
                assert_eq!(bytes.len(), P2TR_LEN);
                bytes
            }
            _ => unreachable!(),
        };

        // Construct the descriptor
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(type_tag);
        bytes.extend_from_slice(&payload);

        Descriptor::from_bytes(&bytes).map_err(|_| Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Arbitrary;
    use bitcoin::Network;
    use rand_core::{OsRng, RngCore};

    use crate::DescriptorType;

    #[test]
    fn test_arbitrary_descriptor() {
        // Number of iterations
        const N: usize = 1_000;

        // Create a buffer of random bytes
        // 128 bytes would be enough since it is above MAX_OP_RETURN_LEN
        let mut data = vec![0u8; N * 128];
        OsRng.fill_bytes(&mut data);
        let mut u = Unstructured::new(&data);

        // Generate several random descriptors
        for _ in 0..N {
            if let Ok(desc) = Descriptor::arbitrary(&mut u) {
                // Verify type tag is valid
                match desc.type_tag() {
                    DescriptorType::OpReturn => assert!(desc.payload().len() <= MAX_OP_RETURN_LEN),
                    DescriptorType::P2pkh => assert_eq!(desc.payload().len(), P2PKH_LEN),
                    DescriptorType::P2sh => assert_eq!(desc.payload().len(), P2SH_LEN),
                    DescriptorType::P2wpkh => assert_eq!(desc.payload().len(), P2WPKH_LEN),
                    DescriptorType::P2wsh => assert_eq!(desc.payload().len(), P2WSH_LEN),
                    DescriptorType::P2tr => assert_eq!(desc.payload().len(), P2TR_LEN),
                }
            }
        }
    }

    #[test]
    fn test_arbitrary_descriptor_to_address() {
        // Number of iterations
        const N: usize = 1_000;

        // Create a buffer of random bytes
        // 128 bytes would be enough since it is above MAX_OP_RETURN_LEN
        let mut data = vec![0u8; N * 128];
        OsRng.fill_bytes(&mut data);
        let mut u = Unstructured::new(&data);

        // Generate several random descriptors
        for _ in 0..N {
            if let Ok(desc) = Descriptor::arbitrary(&mut u) {
                // Verify type tag is valid
                match desc.type_tag() {
                    // not testing address conversion for OP_RETURN
                    DescriptorType::OpReturn => {}
                    // anything else should be convertible to an address
                    _ => {
                        let address = desc.to_address(Network::Bitcoin);
                        assert!(address.is_ok())
                    }
                }
            }
        }
    }
}
