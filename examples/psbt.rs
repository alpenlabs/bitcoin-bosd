//! Implements an example PSBT workflow.
//!
//! The workflow we simulate is that of a setup using BOSDs to create a PSBT with a P2WPKH and a
//! OP_return outputs.
//!
//! ## How to check:
//!
//! 1. Start Bitcoin Core in Regtest mode, for example:
//!
//!    `bitcoind -regtest -server -daemon -fallbackfee=0.0002 -rpcuser=admin -rpcpassword=pass
//! -rpcallowip=127.0.0.1/0 -rpcbind=127.0.0.1 -blockfilterindex=1 -peerblockfilters=1`
//!
//! 2. Define a shell alias to `bitcoin-cli`, for example:
//!
//!    `alias bt="bitcoin-cli -rpcuser=admin -rpcpassword=pass -rpcport=18443"`
//!
//! 3. Run this example to get the Base64 encoded PSBT with:
//!
//!    `cargo run --features examples --example payload_with_rust-bitcoin`
//!
//! 4. Now that you have with the Base64 encoded PSBT:
//!
//!    `bt analyzepsbt
//! cHNidP8BAEACAAAAAAIAAAAAAAAAABYAFJf1yVh7sF47WTYWjYsqsoGUbuOsAAAAAAAAAAAOagxCaXRjb2luIEJPU0QAAAAAAAAA`

use bitcoin::{
    absolute::LockTime,
    bip32::{IntoDerivationPath, Xpriv},
    key::Secp256k1,
    secp256k1::All,
    transaction::Version,
    Amount, Network, Psbt, Transaction, TxOut,
};
use bitcoin_bosd::Descriptor;

fn main() {
    // This example shows the basic usage of the BOSD `Descriptor`
    // for parsing and transmuting into Bitcoin `ScriptBuf` and `Address`.

    // Example of a OP_RETURN payload.
    let message = String::from("Bitcoin BOSD");

    // BOSD is simply the type tag followed by the cryptographic payload.
    let bytes = [&[0u8; 1], message.as_bytes()].concat();
    let opreturn_desc = Descriptor::from_bytes(bytes.as_slice()).unwrap();
    let op_return_payload_script = opreturn_desc.to_script();

    // Here we use the is_op_return() method from rust-bitcoin to check if the script is indeed an
    // op_return.
    assert!(op_return_payload_script.is_op_return());

    // This will result in a error since this specific one is an OP_RETURN.
    let op_return_address_error = opreturn_desc.to_address(Network::Bitcoin);
    assert_eq!(
        op_return_address_error.err().unwrap(),
        bitcoin_bosd::DescriptorError::InvalidAddressConversion(
            bitcoin_bosd::DescriptorType::OpReturn
        )
    );

    // `Descriptor`s can be derived to a Bitcoin `Address`.
    //  Example of a 20-byte P2WPKH payload.
    let payload: [u8; 20] = [
        // random hash160
        0x97, 0xf5, 0xc9, 0x58, 0x7b, 0xb0, 0x5e, 0x3b, 0x59, 0x36, 0x16, 0x8d, 0x8b, 0x2a, 0xb2,
        0x81, 0x94, 0x6e, 0xe3, 0xac,
    ];
    //  First byte is 3 to indicate a SegWit V0 type tag.
    let bytes = [&[3u8; 1], &payload[..]].concat();
    let descriptor = Descriptor::from_bytes(bytes.as_slice()).unwrap();

    // An anyone-can-pay transaction using the scriptPubKeys.
    let unsigned_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::from_consensus(0),
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: descriptor.to_script(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return_payload_script,
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.sign(&get_mock_key().0, &get_mock_key().1).unwrap();

    // Prints the signed PSBT as a hex-encoded string.
    println!("PSBT: {}", &psbt.serialize_hex());
    println!("NOTE: You need to convert it to base64 in order to check with analyzepsbt bitcoin-cli command.");
}

/// Returns a derived key from a random master key.
pub fn get_mock_key() -> (Xpriv, Secp256k1<All>) {
    // Taken from rust-bitcoin's codebase.
    const RANDOM_MASTER_KEY: &str =  "tprv8ZgxMBicQKsPeSHZFZWT8zxie2dXWcwemnTkf4grVzMvP2UABUxqbPTCHzZ4ztwhBghpfFw27sJqEgW6y1ZTZcfvCUdtXE1L6qMF7TBdbqQ";
    let key = RANDOM_MASTER_KEY
        .parse::<Xpriv>()
        .expect("valid master key");
    let secp = Secp256k1::new();
    let path = "84h/0h/0h".into_derivation_path().expect("valid path");
    (key.derive_priv(&secp, &path).unwrap(), secp)
}
