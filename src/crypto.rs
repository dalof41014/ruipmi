use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use sha2::Sha256;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::cipher::block_padding::NoPadding;

use crate::cipher::{AuthAlg, CipherSuite, CryptAlg, IntegrityAlg};
use crate::constants::AES_BLOCK;
use crate::error::{IpmiError, Result};

/// Compute HMAC using the authentication algorithm.
pub fn hmac_auth(cipher: &CipherSuite, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match cipher.authentication {
        AuthAlg::HmacSha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        AuthAlg::HmacSha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        AuthAlg::HmacMd5 => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        AuthAlg::None => vec![],
    }
}

/// Compute HMAC using the integrity algorithm.
pub fn hmac_integrity(cipher: &CipherSuite, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match cipher.integrity {
        IntegrityAlg::HmacSha1_96 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        IntegrityAlg::HmacSha256_128 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        IntegrityAlg::HmacMd5_128 | IntegrityAlg::Md5_128 => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).unwrap();
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        IntegrityAlg::None => vec![],
    }
}

/// Encrypt payload according to the confidentiality algorithm.
pub fn encrypt(cipher: &CipherSuite, plain: &[u8], k2: &[u8; 16]) -> Result<Vec<u8>> {
    match cipher.confidentiality {
        CryptAlg::None => Ok(plain.to_vec()),
        CryptAlg::AesCbc128 => encrypt_aes_cbc(plain, k2),
        _ => Err(IpmiError::InvalidState("RC4 not implemented")),
    }
}

/// Decrypt payload according to the confidentiality algorithm.
pub fn decrypt(cipher: &CipherSuite, enc: &[u8], k2: &[u8; 16]) -> Result<Vec<u8>> {
    match cipher.confidentiality {
        CryptAlg::None => Ok(enc.to_vec()),
        CryptAlg::AesCbc128 => decrypt_aes_cbc(enc, k2),
        _ => Err(IpmiError::InvalidState("RC4 not implemented")),
    }
}

fn encrypt_aes_cbc(plain: &[u8], k2: &[u8; 16]) -> Result<Vec<u8>> {
    let pad_len = {
        let m = (plain.len() + 1) % AES_BLOCK;
        if m == 0 { 0 } else { AES_BLOCK - m }
    };
    let mut buf = plain.to_vec();
    for i in 0..pad_len {
        buf.push((i + 1) as u8);
    }
    buf.push(pad_len as u8);

    let iv = rand_bytes_16();
    let mut enc = buf;

    let c = Encryptor::<Aes128>::new_from_slices(k2, &iv)
        .map_err(|_| IpmiError::InvalidState("AES init"))?;
    let len = enc.len();
    c.encrypt_padded_mut::<NoPadding>(&mut enc, len).unwrap();

    let mut out = iv.to_vec();
    out.extend_from_slice(&enc);
    Ok(out)
}

fn decrypt_aes_cbc(enc: &[u8], k2: &[u8; 16]) -> Result<Vec<u8>> {
    if enc.len() < AES_BLOCK {
        return Err(IpmiError::DecryptFailed);
    }
    let iv = &enc[..AES_BLOCK];
    let mut data = enc[AES_BLOCK..].to_vec();
    let c = Decryptor::<Aes128>::new_from_slices(k2, iv)
        .map_err(|_| IpmiError::InvalidState("AES init"))?;
    c.decrypt_padded_mut::<NoPadding>(&mut data).unwrap();
    Ok(data)
}

pub fn rand_bytes_16() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub fn rand_bytes_4() -> [u8; 4] {
    let mut b = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut b);
    b
}
