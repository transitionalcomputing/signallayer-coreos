use argon2::{
    password_hash::{PasswordHash, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

pub const SALT_BYTES: usize = 16;
pub const OUTPUT_BYTES: usize = 32;
pub const MEMORY_KIB: u32 = 65536;
pub const ITERATIONS: u32 = 3;
pub const PARALLELISM: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct HashFailed;

pub trait Hasher: Send {
    /// Returns a PHC string.
    fn hash(&self, secret: &[u8], salt: &[u8; SALT_BYTES]) -> Result<String, HashFailed>;
    /// Constant-time comparison of the derived output, with the parameters
    /// recorded in the PHC string.
    fn verify(&self, secret: &[u8], phc: &str) -> Result<bool, HashFailed>;
}

pub struct Argon2id {
    params: Params,
}

impl Argon2id {
    /// The frozen parameters: m = 65536 KiB, t = 3, p = 1, 32-byte output.
    pub fn production() -> Self {
        Self::with_cost(MEMORY_KIB, ITERATIONS, PARALLELISM)
    }

    pub fn with_cost(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        let params = Params::new(memory_kib, iterations, parallelism, Some(OUTPUT_BYTES))
            .expect("fixed Argon2id parameters are valid");
        Self { params }
    }

    fn engine(&self) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }
}

/// A stored hash must be an Argon2id v19 PHC string with a 16-byte salt and a
/// 32-byte output.
pub fn is_valid_phc(phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    let mut salt = [0u8; 64];
    parsed.algorithm == Algorithm::Argon2id.ident()
        && parsed.version == Some(Version::V0x13.into())
        && parsed
            .hash
            .is_some_and(|output| output.len() == OUTPUT_BYTES)
        && parsed
            .salt
            .and_then(|salt_value| salt_value.decode_b64(&mut salt).ok().map(<[u8]>::len))
            == Some(SALT_BYTES)
        && Params::try_from(&parsed).is_ok()
}

impl Hasher for Argon2id {
    fn hash(&self, secret: &[u8], salt: &[u8; SALT_BYTES]) -> Result<String, HashFailed> {
        let salt = SaltString::encode_b64(salt).map_err(|_| HashFailed)?;
        use argon2::password_hash::PasswordHasher;
        self.engine()
            .hash_password(secret, &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| HashFailed)
    }

    fn verify(&self, secret: &[u8], phc: &str) -> Result<bool, HashFailed> {
        if !is_valid_phc(phc) {
            return Err(HashFailed);
        }
        let parsed = PasswordHash::new(phc).map_err(|_| HashFailed)?;
        match self.engine().verify_password(secret, &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(HashFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_hash_records_frozen_parameters() {
        let hasher = Argon2id::production();
        let phc = hasher
            .hash(b"correct horse battery", &[7u8; SALT_BYTES])
            .unwrap();
        let parsed = PasswordHash::new(&phc).unwrap();
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert_eq!(parsed.version, Some(19));
        assert_eq!(parsed.params.get_decimal("m"), Some(65536));
        assert_eq!(parsed.params.get_decimal("t"), Some(3));
        assert_eq!(parsed.params.get_decimal("p"), Some(1));
        assert_eq!(parsed.hash.unwrap().len(), 32);
        assert!(is_valid_phc(&phc));
        assert!(hasher.verify(b"correct horse battery", &phc).unwrap());
        assert!(!hasher.verify(b"correct horse batterz", &phc).unwrap());
    }

    #[test]
    fn stored_hashes_must_be_argon2id_with_frozen_salt_and_output() {
        let hasher = Argon2id::with_cost(8, 1, 1);
        let phc = hasher.hash(b"secret", &[1u8; SALT_BYTES]).unwrap();
        assert!(is_valid_phc(&phc));
        for invalid in [
            phc.replacen("argon2id", "argon2i", 1),
            phc.replacen("v=19", "v=16", 1),
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
            "not a hash".into(),
            String::new(),
        ] {
            assert!(!is_valid_phc(&invalid), "{invalid}");
            assert_eq!(hasher.verify(b"secret", &invalid), Err(HashFailed));
        }
    }
}
