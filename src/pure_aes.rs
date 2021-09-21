use std::prelude::v1::*;

use anyhow::{anyhow, Result};

use ring::aead;

// use crate::types::CMac;  // TODO CMac
use crate::consts::{CMAC_LENGTH, AES_IV_LENGTH};

pub fn aes_decrypt(key: &[u8], in_out: &mut Vec<u8>) -> Result<Vec<u8>> {
    let iv = [0u8; AES_IV_LENGTH];
    // let plaintext_len = aead_decrypt(&aead::AES_256_GCM, in_out, key, &iv)?.len();
    // let mut cmac: CMac = [0u8; CMAC_LENGTH];
    // cmac.copy_from_slice(&in_out[plaintext_len..]);
    // in_out.truncate(plaintext_len);
    let plaintext = aead_decrypt(&aead::AES_256_GCM, in_out, key, &iv)?.to_vec();
    Ok(plaintext)
}

pub fn aes_encrypt(key: &[u8], in_out: &mut Vec<u8>) -> Result<Vec<u8>> {
    let iv = [0u8; AES_IV_LENGTH];
    aead_encrypt(&aead::AES_256_GCM, in_out, key, &iv)?;
    Ok(in_out.to_vec())
}

pub fn aead_decrypt<'a>(
    alg: &'static aead::Algorithm,
    in_out: &'a mut [u8],
    key: &[u8],
    iv: &[u8],
) -> Result<&'a mut [u8]> {
    let key =
        aead::UnboundKey::new(alg, key).map_err(|_| anyhow!("Aead unbound key init error"))?;
    let nonce =
        aead::Nonce::try_assume_unique_for_key(iv).map_err(|_| anyhow!("Aead iv init error"))?;
    let aad = aead::Aad::from([0u8; 8]);

    let dec_key = aead::LessSafeKey::new(key);
    let slice = dec_key
        .open_in_place(nonce, aad, in_out)
        .map_err(|_| anyhow!("Aead open_in_place error"))?;
    Ok(slice)
}

pub fn aead_encrypt(
    alg: &'static aead::Algorithm,
    in_out: &mut Vec<u8>,
    key: &[u8],
    iv: &[u8],
) -> Result<()> {
    let key =
        aead::UnboundKey::new(alg, key).map_err(|_| anyhow!("Aead unbound key init error"))?;
    let nonce =
        aead::Nonce::try_assume_unique_for_key(iv).map_err(|_| anyhow!("Aead iv init error"))?;
    let aad = aead::Aad::from([0u8; 8]);

    let enc_key = aead::LessSafeKey::new(key);
    enc_key
        .seal_in_place_append_tag(nonce, aad, in_out)
        .map_err(|_| anyhow!("Aead seal_in_place_append_tag error"))?;
    Ok(())
}