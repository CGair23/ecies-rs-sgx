use std::prelude::v1::*;

use secp256k1::{util::FULL_PUBLIC_KEY_SIZE, Error as SecpError, PublicKey, SecretKey};
use rand::{thread_rng, Rng};
use ring::hkdf::{HKDF_SHA256, Salt};

pub use crate::pure_aes::{aes_decrypt, aes_encrypt};

use crate::types::AesKey;
use crate::consts::SECRET_KEY_SIZE;

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    let arr: [u8; SECRET_KEY_SIZE] = rng.gen();
    let sk = SecretKey::parse(&arr).expect("parse");   // TODO error_handling

    (sk.clone(), PublicKey::from_secret_key(&sk))
}

/// Calculate a shared AES key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<AesKey, SecpError> {
    let mut shared_point = peer_pk.clone();
    shared_point.tweak_mul_assign(&sk)?;

    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);  // FULL_PUBLIC_KEY_SIZE = 65
    master.extend(PublicKey::from_secret_key(&sk).serialize().iter());
    master.extend(shared_point.serialize().iter());

    hkdf_sha256(master.as_slice())
}

/// Calculate a shared AES key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<AesKey, SecpError> {
    let mut shared_point = pk.clone();
    shared_point.tweak_mul_assign(&peer_sk)?;

    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
    master.extend(pk.serialize().iter());
    master.extend(shared_point.serialize().iter());

    hkdf_sha256(master.as_slice())
}

// private below
fn hkdf_sha256(master: &[u8]) -> Result<AesKey, SecpError> {
    let value = [0u8; 32];
    let s = Salt::new(HKDF_SHA256, &value);
    let prk = s.extract(master);
    let okm = prk.expand(&[&[0u8; 0]], HKDF_SHA256).unwrap();    // Unspecified

    let mut out = [0u8; 32];
    okm.fill(&mut out).unwrap();    // Unspecified
    Ok(out)
}