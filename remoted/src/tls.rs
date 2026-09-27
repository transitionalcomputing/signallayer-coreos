//! The TLS identity: `tls/current` is resolved once, and the key and
//! certificate are read from that same generation directory.
use rustls::ServerConfig;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use sl_remote_state::{CERT_FILE, KEY_FILE, TLS_DIR};
use std::{path::Path, sync::Arc};

pub fn load(state_dir: &Path) -> Result<Arc<ServerConfig>, ()> {
    let generation = sl_remote_state::current_generation(state_dir)
        .map_err(|_| ())?
        .ok_or(())?;
    let directory = state_dir.join(TLS_DIR).join(generation);
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(directory.join(CERT_FILE))
            .map_err(|_| ())?
            .collect::<Result<_, _>>()
            .map_err(|_| ())?;
    if certificates.len() != 1 {
        return Err(());
    }
    let key = PrivateKeyDer::from_pem_file(directory.join(KEY_FILE)).map_err(|_| ())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ())?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| ())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const FIXTURE: &str = include_str!("tls_fixture.pem");

    fn section(index: usize) -> String {
        let starts: Vec<usize> = FIXTURE
            .match_indices("-----BEGIN")
            .map(|(at, _)| at)
            .collect();
        let end = starts.get(index + 1).copied().unwrap_or(FIXTURE.len());
        FIXTURE[starts[index]..end].to_owned()
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sl-remoted-tls-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn identity(&self, generation: &str, cert: &str, key: &str) {
            let directory = self.0.join(TLS_DIR).join(generation);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join(CERT_FILE), cert).unwrap();
            fs::write(directory.join(KEY_FILE), key).unwrap();
        }

        fn point_current(&self, generation: &str) {
            let link = self.0.join(TLS_DIR).join("current");
            let _ = fs::remove_file(&link);
            symlink(generation, link).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn loads_the_current_generation_with_http1_alpn() {
        let directory = TempDir::new();
        directory.identity("gen-0000000000000001", &section(0), &section(1));
        directory.point_current("gen-0000000000000001");
        let config = load(&directory.0).unwrap();
        assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
    }

    #[test]
    fn key_and_certificate_come_from_the_same_generation() {
        let directory = TempDir::new();
        // The current generation's key does not match its certificate; the
        // matching key sits in another generation and must not be used.
        directory.identity("gen-0000000000000001", &section(0), &section(2));
        directory.identity("gen-0000000000000002", &section(0), &section(1));
        directory.point_current("gen-0000000000000001");
        assert!(load(&directory.0).is_err());
        directory.point_current("gen-0000000000000002");
        assert!(load(&directory.0).is_ok());
    }

    #[test]
    fn a_missing_or_invalid_identity_fails() {
        let directory = TempDir::new();
        assert!(load(&directory.0).is_err(), "no identity");
        directory.identity("gen-0000000000000001", &section(0), &section(1));
        directory.point_current("gen-0000000000000009");
        assert!(load(&directory.0).is_err(), "dangling current");
        directory.identity("gen-0000000000000003", "not pem", &section(1));
        directory.point_current("gen-0000000000000003");
        assert!(load(&directory.0).is_err(), "no certificate");
        directory.identity(
            "gen-0000000000000004",
            &format!("{}{}", section(0), section(0)),
            &section(1),
        );
        directory.point_current("gen-0000000000000004");
        assert!(load(&directory.0).is_err(), "more than one certificate");
    }
}
