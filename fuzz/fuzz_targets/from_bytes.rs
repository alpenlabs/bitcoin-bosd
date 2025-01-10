#![no_main]

use bitcoin_bosd::Descriptor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Descriptor parsing should either fail or serialize canonically
    if let Ok(descriptor) = Descriptor::from_bytes(data) {
        assert_eq!(&descriptor.to_bytes(), data);
    }
});
