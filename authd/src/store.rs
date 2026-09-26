use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const STATE_FILE: &str = "state.json";
const TEMP_FILE: &str = "state.json.tmp";
const FORMAT_VERSION: u32 = 1;

/// The persisted authentication state. PendingPairing, the pairing code and
/// backoff counters are never persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Persisted {
    Unenrolled,
    EnrolledUnconfirmed {
        password_hash: String,
        recovery_key_hash: String,
        confirmation_deadline: u64,
    },
    Enrolled {
        password_hash: String,
        recovery_key_hash: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmation_deadline: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    Unreadable,
    Invalid,
}

/// Write steps, in order, for fault injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Create,
    Write,
    FileSync,
    Rename,
    DirectorySync,
}

/// A failed write. `after_rename` means the new state may already be visible
/// on disk, so the in-memory state can no longer be trusted to match it.
#[derive(Debug, PartialEq, Eq)]
pub struct WriteFailed {
    pub after_rename: bool,
}

type Faults = Box<dyn FnMut(Step) -> io::Result<()> + Send>;

pub struct Store {
    directory: PathBuf,
    faults: Faults,
}

impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            faults: Box::new(|_| Ok(())),
        }
    }

    #[cfg(test)]
    pub fn with_faults(
        directory: impl Into<PathBuf>,
        faults: impl FnMut(Step) -> io::Result<()> + Send + 'static,
    ) -> Self {
        Self {
            directory: directory.into(),
            faults: Box::new(faults),
        }
    }

    /// Removes a temporary file left by an interrupted write.
    pub fn remove_stale_temporary(&self) -> io::Result<()> {
        match fs::remove_file(self.directory.join(TEMP_FILE)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// A missing state file is the initial Unenrolled state.
    pub fn load(&self) -> Result<Persisted, LoadError> {
        let bytes = match fs::read(self.directory.join(STATE_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Persisted::Unenrolled)
            }
            Err(_) => return Err(LoadError::Unreadable),
        };
        let file: StateFile = serde_json::from_slice(&bytes).map_err(|_| LoadError::Invalid)?;
        if file.version != FORMAT_VERSION {
            return Err(LoadError::Invalid);
        }
        let valid_hash =
            |hash: &Option<String>| hash.as_deref().is_some_and(crate::hash::is_valid_phc);
        match (
            file.state.as_str(),
            &file.password_hash,
            &file.recovery_key_hash,
            file.confirmation_deadline,
        ) {
            ("unenrolled", None, None, None) => Ok(Persisted::Unenrolled),
            ("enrolled_unconfirmed", password, recovery, Some(deadline))
                if valid_hash(password) && valid_hash(recovery) =>
            {
                Ok(Persisted::EnrolledUnconfirmed {
                    password_hash: file.password_hash.unwrap(),
                    recovery_key_hash: file.recovery_key_hash.unwrap(),
                    confirmation_deadline: deadline,
                })
            }
            ("enrolled", password, recovery, None)
                if valid_hash(password) && valid_hash(recovery) =>
            {
                Ok(Persisted::Enrolled {
                    password_hash: file.password_hash.unwrap(),
                    recovery_key_hash: file.recovery_key_hash.unwrap(),
                })
            }
            _ => Err(LoadError::Invalid),
        }
    }

    /// Temporary file (O_CREAT|O_EXCL, 0600), fsync, rename over state.json,
    /// fsync the directory. Success means the new state is durable.
    pub fn write(&mut self, state: &Persisted) -> Result<(), WriteFailed> {
        let file = match state {
            Persisted::Unenrolled => StateFile {
                version: FORMAT_VERSION,
                state: "unenrolled".into(),
                password_hash: None,
                recovery_key_hash: None,
                confirmation_deadline: None,
            },
            Persisted::EnrolledUnconfirmed {
                password_hash,
                recovery_key_hash,
                confirmation_deadline,
            } => StateFile {
                version: FORMAT_VERSION,
                state: "enrolled_unconfirmed".into(),
                password_hash: Some(password_hash.clone()),
                recovery_key_hash: Some(recovery_key_hash.clone()),
                confirmation_deadline: Some(*confirmation_deadline),
            },
            Persisted::Enrolled {
                password_hash,
                recovery_key_hash,
            } => StateFile {
                version: FORMAT_VERSION,
                state: "enrolled".into(),
                password_hash: Some(password_hash.clone()),
                recovery_key_hash: Some(recovery_key_hash.clone()),
                confirmation_deadline: None,
            },
        };
        let bytes = serde_json::to_vec(&file).map_err(|_| WriteFailed {
            after_rename: false,
        })?;
        let temporary = self.directory.join(TEMP_FILE);
        if self.write_temporary(&temporary, &bytes).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(WriteFailed {
                after_rename: false,
            });
        }
        let renamed = (self.faults)(Step::Rename)
            .and_then(|()| fs::rename(&temporary, self.directory.join(STATE_FILE)));
        if renamed.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(WriteFailed {
                after_rename: false,
            });
        }
        (self.faults)(Step::DirectorySync)
            .and_then(|()| File::open(&self.directory)?.sync_all())
            .map_err(|_| WriteFailed { after_rename: true })
    }

    fn write_temporary(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        (self.faults)(Step::Create)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        (self.faults)(Step::Write)?;
        file.write_all(bytes)?;
        (self.faults)(Step::FileSync)?;
        file.sync_all()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sl-authd-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub fn test_hash(secret: &[u8]) -> String {
        use crate::hash::Hasher;
        crate::hash::Argon2id::with_cost(8, 1, 1)
            .hash(secret, &[3u8; 16])
            .unwrap()
    }

    fn enrolled() -> Persisted {
        Persisted::Enrolled {
            password_hash: test_hash(b"password"),
            recovery_key_hash: test_hash(b"key"),
        }
    }

    fn unconfirmed() -> Persisted {
        Persisted::EnrolledUnconfirmed {
            password_hash: test_hash(b"password"),
            recovery_key_hash: test_hash(b"key"),
            confirmation_deadline: 1_000,
        }
    }

    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn missing_state_is_unenrolled_and_states_round_trip() {
        let directory = TempDir::new();
        let mut store = Store::new(&directory.0);
        assert_eq!(store.load(), Ok(Persisted::Unenrolled));
        for state in [unconfirmed(), enrolled(), Persisted::Unenrolled] {
            store.write(&state).unwrap();
            assert_eq!(Store::new(&directory.0).load(), Ok(state));
            assert_eq!(entries(&directory.0), [STATE_FILE]);
        }
    }

    #[test]
    fn state_file_has_mode_0600_and_only_the_documented_fields() {
        let directory = TempDir::new();
        let mut store = Store::new(&directory.0);
        store.write(&unconfirmed()).unwrap();
        let path = directory.0.join(STATE_FILE);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "confirmation_deadline",
                "password_hash",
                "recovery_key_hash",
                "state",
                "version"
            ]
        );
    }

    #[test]
    fn failures_before_rename_leave_the_old_state_and_no_temporary() {
        for failing in [Step::Create, Step::Write, Step::FileSync, Step::Rename] {
            let directory = TempDir::new();
            Store::new(&directory.0).write(&enrolled()).unwrap();
            let before = fs::read(directory.0.join(STATE_FILE)).unwrap();
            let mut store = Store::with_faults(&directory.0, move |step| {
                if step == failing {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                store.write(&Persisted::Unenrolled),
                Err(WriteFailed {
                    after_rename: false
                })
            );
            assert_eq!(fs::read(directory.0.join(STATE_FILE)).unwrap(), before);
            assert_eq!(entries(&directory.0), [STATE_FILE]);
            assert_eq!(store.load(), Ok(enrolled()));
        }
    }

    #[test]
    fn a_failed_directory_sync_is_reported_as_after_rename() {
        let directory = TempDir::new();
        let mut store = Store::with_faults(&directory.0, |step| {
            if step == Step::DirectorySync {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            store.write(&enrolled()),
            Err(WriteFailed { after_rename: true })
        );
    }

    #[test]
    fn a_stale_temporary_is_removed_and_blocks_nothing_afterwards() {
        let directory = TempDir::new();
        fs::write(directory.0.join(TEMP_FILE), b"partial").unwrap();
        let mut store = Store::new(&directory.0);
        store.remove_stale_temporary().unwrap();
        assert_eq!(entries(&directory.0), Vec::<String>::new());
        store.write(&enrolled()).unwrap();
        assert_eq!(store.load(), Ok(enrolled()));
    }

    #[test]
    fn corrupt_unknown_or_inconsistent_files_are_invalid() {
        let hash = test_hash(b"x");
        let cases = [
            "".to_string(),
            "{".to_string(),
            "null".to_string(),
            r#"{"version":2,"state":"unenrolled"}"#.to_string(),
            r#"{"version":1,"state":"pending_pairing"}"#.to_string(),
            r#"{"version":1,"state":"unenrolled","extra":1}"#.to_string(),
            format!(r#"{{"version":1,"state":"unenrolled","password_hash":"{hash}"}}"#),
            format!(r#"{{"version":1,"state":"enrolled","password_hash":"{hash}"}}"#),
            format!(
                r#"{{"version":1,"state":"enrolled","password_hash":"{hash}","recovery_key_hash":"{hash}","confirmation_deadline":5}}"#
            ),
            format!(
                r#"{{"version":1,"state":"enrolled_unconfirmed","password_hash":"{hash}","recovery_key_hash":"{hash}"}}"#
            ),
            format!(
                r#"{{"version":1,"state":"enrolled","password_hash":"plain","recovery_key_hash":"{hash}"}}"#
            ),
        ];
        for case in cases {
            let directory = TempDir::new();
            fs::write(directory.0.join(STATE_FILE), &case).unwrap();
            assert_eq!(
                Store::new(&directory.0).load(),
                Err(LoadError::Invalid),
                "{case}"
            );
        }
    }
}
