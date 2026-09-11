use crate::mgf1::mgf1_sha256;

use sha256;

#[test]
fn test_mgf1_sha256() {
    let seed: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let expected_mask: [u8; 32] = [
        106, 93, 232, 46, 236, 203, 51, 228, 103, 104, 145, 29, 197, 74, 26, 194, 135, 200, 40, 232,
        179, 172, 220, 135, 51, 185, 209, 35, 194, 131, 176, 190,
    ];
    let mask: [u8; 32] = mgf1_sha256(seed);
    assert(mask == expected_mask);
}
