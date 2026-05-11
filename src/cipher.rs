/// Cipher suite algorithm options.
#[derive(Clone, Copy)]
pub enum AuthAlg {
    None,
    HmacSha1,
    HmacMd5,
    HmacSha256,
}

#[derive(Clone, Copy)]
pub enum IntegrityAlg {
    None,
    HmacSha1_96,
    HmacMd5_128,
    Md5_128,
    HmacSha256_128,
}

#[derive(Clone, Copy)]
pub enum CryptAlg {
    None,
    AesCbc128,
    Xrc4_128,
    Xrc4_40,
}

#[derive(Clone, Copy)]
pub struct CipherSuite {
    pub authentication: AuthAlg,
    pub integrity: IntegrityAlg,
    pub confidentiality: CryptAlg,
}

/// Default Cipher Suite ID 17:
/// authentication = HMAC-SHA256, integrity = HMAC-SHA256-128, confidentiality = AES-CBC-128
pub const DEFAULT_CIPHER_SUITE: CipherSuite = CipherSuite {
    authentication: AuthAlg::HmacSha256,
    integrity: IntegrityAlg::HmacSha256_128,
    confidentiality: CryptAlg::AesCbc128,
};

impl CipherSuite {
    pub fn auth_byte(&self) -> u8 {
        match self.authentication {
            AuthAlg::None => 0x00,
            AuthAlg::HmacSha1 => 0x01,
            AuthAlg::HmacMd5 => 0x02,
            AuthAlg::HmacSha256 => 0x03,
        }
    }

    pub fn integrity_byte(&self) -> u8 {
        match self.integrity {
            IntegrityAlg::None => 0x00,
            IntegrityAlg::HmacSha1_96 => 0x01,
            IntegrityAlg::HmacMd5_128 => 0x02,
            IntegrityAlg::Md5_128 => 0x03,
            IntegrityAlg::HmacSha256_128 => 0x04,
        }
    }

    pub fn conf_byte(&self) -> u8 {
        match self.confidentiality {
            CryptAlg::None => 0x00,
            CryptAlg::AesCbc128 => 0x01,
            CryptAlg::Xrc4_128 => 0x02,
            CryptAlg::Xrc4_40 => 0x03,
        }
    }

    pub fn auth_digest_len(&self) -> usize {
        match self.authentication {
            AuthAlg::HmacSha1 => 20,
            AuthAlg::HmacSha256 => 32,
            AuthAlg::HmacMd5 => 16,
            AuthAlg::None => 0,
        }
    }

    pub fn integrity_truncate_len(&self) -> usize {
        match self.integrity {
            IntegrityAlg::HmacSha1_96 => 12,
            IntegrityAlg::HmacSha256_128 => 16,
            IntegrityAlg::HmacMd5_128 => 16,
            IntegrityAlg::Md5_128 => 16,
            IntegrityAlg::None => 0,
        }
    }
}
