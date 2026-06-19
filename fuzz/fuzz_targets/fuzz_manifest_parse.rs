#![no_main]
use libfuzzer_sys::fuzz_target;
use siros_integrity_guard::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    // Exercise manifest JSON parsing — must not panic on arbitrary input.
    let _ = Manifest::signed_payload(data);
});
