//! The remote-management state layout frozen in docs/platform-api-0.3.md.
//! sl-remote-worker is its only writer; sl-platformd only reads it.
use std::{fs, io, path::Path};

pub const STATE_DIR: &str = "/var/lib/sl-remote-management";
pub const ENABLED: &str = "enabled";
pub const RESET_PENDING: &str = "reset-pending";
pub const TLS_DIR: &str = "tls";
pub const CURRENT: &str = "current";
pub const KEY_FILE: &str = "key.pem";
pub const CERT_FILE: &str = "cert.pem";
pub const FINGERPRINT_FILE: &str = "fingerprint";
const GENERATION_PREFIX: &str = "gen-";
const OPENSSL_FINGERPRINT_PREFIX: &str = "sha256 Fingerprint=";

/// `gen-` followed by exactly 16 lowercase hexadecimal digits.
pub fn is_generation_name(name: &str) -> bool {
    name.strip_prefix(GENERATION_PREFIX).is_some_and(|hex| {
        hex.len() == 16
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub fn generation_name(bytes: [u8; 8]) -> String {
    let mut name = String::from(GENERATION_PREFIX);
    for byte in bytes {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// The canonical fingerprint text: 32 bytes as uppercase hexadecimal pairs
/// separated by `:` (95 characters).
pub fn is_canonical_fingerprint(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 95
        && bytes.iter().enumerate().all(|(index, &byte)| {
            if index % 3 == 2 {
                byte == b':'
            } else {
                byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
            }
        })
}

/// Parses the complete stdout of `openssl x509 -noout -fingerprint -sha256`:
/// exactly one line, `sha256 Fingerprint=<canonical>` and a newline.
pub fn parse_openssl_fingerprint(stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?;
    let line = text.strip_suffix('\n')?;
    let fingerprint = line.strip_prefix(OPENSSL_FINGERPRINT_PREFIX)?;
    is_canonical_fingerprint(fingerprint).then(|| fingerprint.to_owned())
}

/// The fingerprint file holds the canonical text and one newline.
pub fn fingerprint_file_contents(fingerprint: &str) -> String {
    format!("{fingerprint}\n")
}

pub fn parse_fingerprint_file(contents: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(contents).ok()?;
    let fingerprint = text.strip_suffix('\n')?;
    is_canonical_fingerprint(fingerprint).then(|| fingerprint.to_owned())
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidIdentity;

/// The generation `tls/current` names. `Ok(None)` means no identity exists;
/// anything other than a symlink to a generation name is invalid.
pub fn current_generation(state_dir: &Path) -> Result<Option<String>, InvalidIdentity> {
    match fs::read_link(state_dir.join(TLS_DIR).join(CURRENT)) {
        Ok(target) => target
            .to_str()
            .filter(|name| is_generation_name(name))
            .map(|name| Some(name.to_owned()))
            .ok_or(InvalidIdentity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(InvalidIdentity),
    }
}

/// What sl-platformd reads: the current identity's validated fingerprint,
/// without touching the key.
pub fn current_fingerprint(state_dir: &Path) -> Result<Option<String>, InvalidIdentity> {
    let Some(generation) = current_generation(state_dir)? else {
        return Ok(None);
    };
    let path = state_dir
        .join(TLS_DIR)
        .join(generation)
        .join(FINGERPRINT_FILE);
    let contents = fs::read(path).map_err(|_| InvalidIdentity)?;
    parse_fingerprint_file(&contents)
        .map(Some)
        .ok_or(InvalidIdentity)
}

/// What the worker requires of an existing identity: a generation directory
/// holding a regular key and certificate, and a valid fingerprint.
pub fn current_identity(state_dir: &Path) -> Result<Option<String>, InvalidIdentity> {
    let Some(generation) = current_generation(state_dir)? else {
        return Ok(None);
    };
    let directory = state_dir.join(TLS_DIR).join(&generation);
    let is = |path: &Path, directory: bool| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            }
        })
    };
    if !is(&directory, true)
        || !is(&directory.join(KEY_FILE), false)
        || !is(&directory.join(CERT_FILE), false)
    {
        return Err(InvalidIdentity);
    }
    current_fingerprint(state_dir)?;
    Ok(Some(generation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const FINGERPRINT: &str = "20:E5:0B:A7:F0:9C:9E:C6:4C:02:2C:81:EE:01:1C:5C:A5:1C:60:12:0C:39:BD:43:D0:CB:50:C4:DD:5E:78:00";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sl-remote-state-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity(root: &Path, generation: &str, fingerprint: &[u8]) {
        let tls = root.join(TLS_DIR);
        fs::create_dir_all(tls.join(generation)).unwrap();
        fs::write(tls.join(generation).join(KEY_FILE), b"key").unwrap();
        fs::write(tls.join(generation).join(CERT_FILE), b"cert").unwrap();
        fs::write(tls.join(generation).join(FINGERPRINT_FILE), fingerprint).unwrap();
        symlink(generation, tls.join(CURRENT)).unwrap();
    }

    #[test]
    fn generation_names_are_gen_and_sixteen_lowercase_hex() {
        assert_eq!(
            generation_name([0, 1, 0xab, 0xff, 2, 3, 4, 5]),
            "gen-0001abff02030405"
        );
        assert!(is_generation_name("gen-0001abff02030405"));
        for invalid in [
            "gen-0001ABFF02030405",
            "gen-0001abff0203040",
            "gen-0001abff020304055",
            "gen-0001abff0203040g",
            "gen0001abff02030405",
            "../gen-0001abff02030405",
            "gen-0001abff02030405/",
            "",
        ] {
            assert!(!is_generation_name(invalid), "{invalid}");
        }
    }

    #[test]
    fn fingerprints_are_canonical_uppercase_colon_pairs() {
        assert!(is_canonical_fingerprint(FINGERPRINT));
        for invalid in [
            FINGERPRINT.to_ascii_lowercase(),
            FINGERPRINT.replace(':', ""),
            FINGERPRINT[..92].to_owned(),
            format!("{FINGERPRINT}:00"),
            FINGERPRINT.replacen('2', "G", 1),
            FINGERPRINT.replacen(':', "-", 1),
            format!(" {}", &FINGERPRINT[1..]),
        ] {
            assert!(!is_canonical_fingerprint(&invalid), "{invalid}");
        }
    }

    #[test]
    fn openssl_output_is_parsed_strictly() {
        let valid = format!("sha256 Fingerprint={FINGERPRINT}\n");
        assert_eq!(
            parse_openssl_fingerprint(valid.as_bytes()).as_deref(),
            Some(FINGERPRINT)
        );
        for invalid in [
            format!("sha256 Fingerprint={FINGERPRINT}"),
            format!("sha256 Fingerprint={FINGERPRINT}\n\n"),
            format!("SHA256 Fingerprint={FINGERPRINT}\n"),
            format!("sha1 Fingerprint={FINGERPRINT}\n"),
            format!("sha256 Fingerprint= {FINGERPRINT}\n"),
            format!("sha256 Fingerprint={FINGERPRINT} \n"),
            format!("sha256 Fingerprint={}\n", FINGERPRINT.to_ascii_lowercase()),
            format!("warning\nsha256 Fingerprint={FINGERPRINT}\n"),
            format!("sha256 Fingerprint={FINGERPRINT}\r\n"),
            String::new(),
        ] {
            assert_eq!(
                parse_openssl_fingerprint(invalid.as_bytes()),
                None,
                "{invalid:?}"
            );
        }
        assert_eq!(parse_openssl_fingerprint(&[0xff, b'\n']), None);
    }

    #[test]
    fn fingerprint_file_round_trips_and_is_strict() {
        let contents = fingerprint_file_contents(FINGERPRINT);
        assert_eq!(
            parse_fingerprint_file(contents.as_bytes()).as_deref(),
            Some(FINGERPRINT)
        );
        assert_eq!(parse_fingerprint_file(FINGERPRINT.as_bytes()), None);
        assert_eq!(
            parse_fingerprint_file(format!("{contents}\n").as_bytes()),
            None
        );
    }

    #[test]
    fn a_missing_current_or_tls_directory_is_no_identity() {
        let root = TempDir::new();
        assert_eq!(current_fingerprint(&root.0), Ok(None));
        assert_eq!(current_identity(&root.0), Ok(None));
        fs::create_dir(root.0.join(TLS_DIR)).unwrap();
        assert_eq!(current_fingerprint(&root.0), Ok(None));
    }

    #[test]
    fn a_valid_identity_is_read() {
        let root = TempDir::new();
        let contents = fingerprint_file_contents(FINGERPRINT);
        identity(&root.0, "gen-0000000000000001", contents.as_bytes());
        assert_eq!(
            current_fingerprint(&root.0),
            Ok(Some(FINGERPRINT.to_owned()))
        );
        assert_eq!(
            current_identity(&root.0),
            Ok(Some("gen-0000000000000001".to_owned()))
        );
    }

    #[test]
    fn invalid_identities_are_rejected() {
        let contents = fingerprint_file_contents(FINGERPRINT);
        type Setup = fn(&Path, &[u8]);
        let cases: [(&str, Setup); 7] = [
            ("dangling current", |root, _| {
                fs::create_dir(root.join(TLS_DIR)).unwrap();
                symlink("gen-0000000000000001", root.join(TLS_DIR).join(CURRENT)).unwrap();
            }),
            ("current is a file", |root, _| {
                fs::create_dir(root.join(TLS_DIR)).unwrap();
                fs::write(root.join(TLS_DIR).join(CURRENT), b"gen-0000000000000001").unwrap();
            }),
            ("current names a non-generation", |root, fingerprint| {
                identity(root, "gen-0000000000000001", fingerprint);
                fs::remove_file(root.join(TLS_DIR).join(CURRENT)).unwrap();
                symlink(
                    "../tls/gen-0000000000000001",
                    root.join(TLS_DIR).join(CURRENT),
                )
                .unwrap();
            }),
            ("missing fingerprint", |root, fingerprint| {
                identity(root, "gen-0000000000000001", fingerprint);
                fs::remove_file(
                    root.join(TLS_DIR)
                        .join("gen-0000000000000001")
                        .join(FINGERPRINT_FILE),
                )
                .unwrap();
            }),
            ("malformed fingerprint", |root, _| {
                identity(root, "gen-0000000000000001", b"not a fingerprint\n");
            }),
            ("missing key", |root, fingerprint| {
                identity(root, "gen-0000000000000001", fingerprint);
                fs::remove_file(
                    root.join(TLS_DIR)
                        .join("gen-0000000000000001")
                        .join(KEY_FILE),
                )
                .unwrap();
            }),
            ("key is a symlink", |root, fingerprint| {
                identity(root, "gen-0000000000000001", fingerprint);
                let key = root
                    .join(TLS_DIR)
                    .join("gen-0000000000000001")
                    .join(KEY_FILE);
                fs::remove_file(&key).unwrap();
                symlink("/etc/hostname", key).unwrap();
            }),
        ];
        for (name, setup) in cases {
            let root = TempDir::new();
            setup(&root.0, contents.as_bytes());
            assert_eq!(current_identity(&root.0), Err(InvalidIdentity), "{name}");
        }
        // Platform's read needs only the link and the fingerprint.
        let root = TempDir::new();
        identity(&root.0, "gen-0000000000000001", contents.as_bytes());
        fs::remove_file(
            root.0
                .join(TLS_DIR)
                .join("gen-0000000000000001")
                .join(KEY_FILE),
        )
        .unwrap();
        assert_eq!(
            current_fingerprint(&root.0),
            Ok(Some(FINGERPRINT.to_owned()))
        );
    }
}
