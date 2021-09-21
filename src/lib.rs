#![no_std]

#[macro_use]
extern crate sgx_tstd as std;
use std::prelude::v1::*;

pub use secp256k1::{util::FULL_PUBLIC_KEY_SIZE, Error as SecpError, PublicKey, SecretKey};

/// Constant variables
pub mod consts;

/// Type aliases
pub mod types;

/// Utility functions for ecies
pub mod utils;

// mod pure_aes;
pub mod pure_aes;

use utils::{aes_decrypt, aes_encrypt, encapsulate, decapsulate, generate_keypair};

/// Encrypt a message by a public key
///
/// # Arguments
///
/// * `receiver_pub` - The u8 array reference of a receiver's public key, which is 520 | 264 | 512 bit
/// * `msg` - The u8 array reference of the message to encrypt
pub fn encrypt(receiver_pub: &[u8], msg: &mut Vec<u8>) -> Result<Vec<u8>, SecpError> {
    let receiver_pk = PublicKey::parse_slice(receiver_pub, None)?;
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let aes_key = encapsulate(&ephemeral_sk, &receiver_pk)?;
    let encrypted = aes_encrypt(&aes_key, msg).expect("invalid message");   // TODO error_handling

    let mut cipher_text = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE + encrypted.len());
    cipher_text.extend(ephemeral_pk.serialize().iter());
    cipher_text.extend(&encrypted);

    Ok(cipher_text)
}

/// Decrypt a message by a secret key
///
/// # Arguments
///
/// * `receiver_sec` - The u8 array reference of a receiver's secret key
/// * `msg` - The u8 array reference of the encrypted message
pub fn decrypt(receiver_sec: &[u8], msg: &mut Vec<u8>) -> Result<Vec<u8>, SecpError> {
    let receiver_sk = SecretKey::parse_slice(receiver_sec)?;

    if msg.len() < FULL_PUBLIC_KEY_SIZE {
        return Err(SecpError::InvalidMessage);
    }

    let ephemeral_pk = PublicKey::parse_slice(&msg[..FULL_PUBLIC_KEY_SIZE], None)?;
    let encrypted = &msg[FULL_PUBLIC_KEY_SIZE..];

    let aes_key = decapsulate(&ephemeral_pk, &receiver_sk)?;

    let ret = aes_decrypt(&aes_key, &mut encrypted.to_vec()).expect("invalid message");   // TODO error_handling
    Ok(ret)
}
