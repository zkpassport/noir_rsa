use num_bigint::BigUint;
use rsa::pkcs1v15::Signature;
use rsa::pkcs1v15::VerifyingKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::Keypair;
use signature::RandomizedSignerMut;
use std::env;
use toml::Value;

use rand;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use clap::{App, Arg};

use noir_bignum_paramgen::{
    bn_limbs, compute_barrett_reduction_parameter, split_into_120_bit_limbs,
};

fn format_limbs_as_hex(limbs: &Vec<BigUint>) -> String {
    limbs
        .iter()
        .map(|a| format!("0x{:x}", a))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_limbs_as_toml_value(limbs: &Vec<BigUint>) -> Vec<Value> {
    limbs
        .iter()
        .map(|a| Value::String(format!("0x{:x}", a)))
        .collect()
}

fn generate_2048_bit_signature_parameters(msg: &str, as_toml: bool, pss: bool) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 1025;
    let priv_key: RsaPrivateKey =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    let sig_bytes = if pss {
        let mut signing_key = rsa::pss::BlindedSigningKey::<Sha256>::new(priv_key);
        let sig = signing_key.sign_with_rng(&mut rng, msg.as_bytes());
        sig.to_vec()
    } else {
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        signing_key.sign(msg.as_bytes()).to_vec()
    };

    let sig_uint: BigUint = BigUint::from_bytes_be(&sig_bytes);

    let sig_str = bn_limbs(sig_uint.clone(), 1025);

    let modulus_limbs: Vec<BigUint> = split_into_120_bit_limbs(&pub_key.n().clone(), 1025);
    let redc_param = split_into_120_bit_limbs(
        &compute_barrett_reduction_parameter(&pub_key.n().clone()),
        1025,
    );

    if as_toml {
        let hash_toml = toml::to_vec(&hashed_as_bytes).unwrap();

        let sig_limbs = split_into_120_bit_limbs(&sig_uint.clone(), 1025);
        let signature_toml = Value::Array(format_limbs_as_toml_value(&sig_limbs));

        let bn = Value::Array(vec![
            Value::Array(format_limbs_as_toml_value(&modulus_limbs)),
            Value::Array(format_limbs_as_toml_value(&redc_param)),
        ]);
        let bn_toml = toml::to_string_pretty(&bn).unwrap();
        println!("bn = {}", bn_toml);
        println!("hash = [{}]", hashed_as_bytes);
        println!("[signature]");
        println!("limbs = {}", signature_toml);
    } else {
        println!("let hash: [u8; 32] = [{}];", hashed_as_bytes);
        println!(
            "let signature: BN2048 = BigNum::from_array({});",
            sig_str.as_str()
        );
        println!(
            "let bn = [\n    [{}],\n    [{}]\n];",
            format_limbs_as_hex(&modulus_limbs),
            format_limbs_as_hex(&redc_param)
        );
    }
}

fn main() {
    let matches = App::new("RSA Signature Generator")
        .arg(
            Arg::with_name("msg")
                .short("m")
                .long("msg")
                .takes_value(true)
                .help("Message to sign")
                .required(true),
        )
        .arg(
            Arg::with_name("toml")
                .short("t")
                .long("toml")
                .help("Print output in TOML format"),
        )
        .arg(
            Arg::with_name("pss")
                .short("p")
                .long("pss")
                .help("Use RSA PSS"),
        )
        .get_matches();

    let msg = matches.value_of("msg").unwrap();
    let as_toml = matches.is_present("toml");
    let pss = matches.is_present("pss");
    
    generate_2048_bit_signature_parameters(msg, as_toml, pss);
}

fn test_signature_generation_impl() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();
    let text: &str = "hello world";
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

    let result = verifying_key.verify(
        text.as_bytes(),
        &Signature::try_from(sig.as_slice()).unwrap(),
    );
    result.expect("failed to verify");
}

#[test]
fn test_signature_generation() {
    test_signature_generation_impl();
}
