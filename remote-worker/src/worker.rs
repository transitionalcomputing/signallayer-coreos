use sl_remote_state::{
    self as layout, CERT_FILE, CURRENT, ENABLED, FINGERPRINT_FILE, KEY_FILE, RESET_PENDING, TLS_DIR,
};
use std::{
    ffi::OsString,
    fs::{self, DirBuilder, File, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// The package-owned openssl path in the pinned base (5C-b step 2 gate:
/// `/usr/sbin` is a symlink to `bin`, and `rpm -ql openssl` lists only this).
pub const OPENSSL: &str = "/usr/bin/openssl";
const CERT_SUBJECT: &str = "/CN=SignalLayer CoreOS remote management";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enable,
    Disable,
    RotateTls,
    BootReset,
    ClearResetPending,
}

impl Mode {
    pub fn parse(argument: &str) -> Option<Self> {
        Some(match argument {
            "enable" => Self::Enable,
            "disable" => Self::Disable,
            "rotate-tls" => Self::RotateTls,
            "boot-reset" => Self::BootReset,
            "clear-reset-pending" => Self::ClearResetPending,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::RotateTls => "rotate-tls",
            Self::BootReset => "boot-reset",
            Self::ClearResetPending => "clear-reset-pending",
        }
    }

    /// Modes that may create TLS files owned by the sl-remoted group.
    pub fn writes_identity(self) -> bool {
        matches!(self, Self::Enable | Self::RotateTls)
    }
}

/// A failure with a fixed message; it never includes tool output.
#[derive(Debug, PartialEq, Eq)]
pub struct Failed(pub &'static str);

/// External effects, injected so tests need no openssl, bus or kernel RNG.
pub trait Tools {
    /// Runs [`OPENSSL`] with exactly these arguments by execve, with no shell,
    /// and returns its stdout only if it exits successfully.
    fn openssl(&mut self, arguments: &[OsString]) -> Result<Vec<u8>, ()>;
    /// `org.signallayer.Auth1.ResetEnrollment`.
    fn reset_enrollment(&mut self) -> Result<(), ()>;
    fn random(&mut self, buffer: &mut [u8]) -> Result<(), ()>;
}

/// Group ownership for the TLS files. Production applies the sl-remoted
/// group; unit tests cannot chown and skip it.
#[derive(Debug, Clone, Copy)]
pub enum Ownership {
    RemotedGroup(u32),
    /// For modes that create no group-owned files; setting ownership fails.
    Unavailable,
    #[cfg(test)]
    Skip,
}

/// Durable steps where tests inject failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    CreateMarker(&'static str),
    RemoveMarker(&'static str),
    RemoveCurrent,
    RemoveGenerations,
    SwapCurrent,
}

type Faults = Box<dyn FnMut(Point) -> bool>;

pub struct Worker<T> {
    root: PathBuf,
    tools: T,
    ownership: Ownership,
    faults: Faults,
}

pub fn req_arguments(generation: &Path) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = [
        "req",
        "-x509",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-pkeyopt",
        "ec_param_enc:named_curve",
        "-noenc",
        "-keyout",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    arguments.push(generation.join(KEY_FILE).into());
    arguments.push("-out".into());
    arguments.push(generation.join(CERT_FILE).into());
    for argument in [
        "-subj",
        CERT_SUBJECT,
        "-not_after",
        "99991231235959Z",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature",
        "-addext",
        "extendedKeyUsage=serverAuth",
    ] {
        arguments.push(argument.into());
    }
    arguments
}

pub fn fingerprint_arguments(generation: &Path) -> Vec<OsString> {
    vec![
        "x509".into(),
        "-in".into(),
        generation.join(CERT_FILE).into(),
        "-noout".into(),
        "-fingerprint".into(),
        "-sha256".into(),
    ]
}

fn fsync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn io_failure<T>(result: io::Result<T>, message: &'static str) -> Result<T, Failed> {
    result.map_err(|_| Failed(message))
}

impl<T: Tools> Worker<T> {
    pub fn new(root: impl Into<PathBuf>, tools: T, ownership: Ownership) -> Self {
        Self {
            root: root.into(),
            tools,
            ownership,
            faults: Box::new(|_| false),
        }
    }

    #[cfg(test)]
    pub fn with_faults(mut self, faults: impl FnMut(Point) -> bool + 'static) -> Self {
        self.faults = Box::new(faults);
        self
    }

    #[cfg(test)]
    pub fn tools(&mut self) -> &mut T {
        &mut self.tools
    }

    fn fault(&mut self, point: Point) -> Result<(), Failed> {
        if (self.faults)(point) {
            Err(Failed("injected failure"))
        } else {
            Ok(())
        }
    }

    fn tls(&self) -> PathBuf {
        self.root.join(TLS_DIR)
    }

    pub fn run(&mut self, mode: Mode) -> Result<(), Failed> {
        self.remove_stale_temporaries()?;
        match mode {
            Mode::Enable => self.enable(),
            Mode::Disable => self.remove_marker(ENABLED),
            Mode::RotateTls => self.rotate(),
            Mode::BootReset => self.boot_reset(),
            Mode::ClearResetPending => self.remove_marker(RESET_PENDING),
        }
    }

    /// Stale temporaries from an interrupted run are removed by the next run.
    fn remove_stale_temporaries(&self) -> Result<(), Failed> {
        for path in [
            self.root.join(format!("{ENABLED}.tmp")),
            self.root.join(format!("{RESET_PENDING}.tmp")),
            self.tls().join(format!("{CURRENT}.tmp")),
        ] {
            match fs::remove_file(path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(Failed("a stale temporary file could not be removed"))
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn enable(&mut self) -> Result<(), Failed> {
        // Defense in depth: Platform already refuses Enable while a reset is
        // pending.
        if self.marker_exists(RESET_PENDING)? {
            return Err(Failed("a remote-management reset is pending"));
        }
        match layout::current_identity(&self.root) {
            Ok(Some(_)) => {}
            Ok(None) => {
                let generation = self.generate_identity()?;
                self.swap_current(&generation)?;
                self.remove_unreferenced_generations()?;
            }
            // Never replace an existing identity here; Reenroll repairs it.
            Err(_) => return Err(Failed("the existing TLS identity is invalid")),
        }
        self.create_marker(ENABLED)
    }

    fn rotate(&mut self) -> Result<(), Failed> {
        let generation = self.generate_identity()?;
        self.swap_current(&generation)?;
        self.remove_unreferenced_generations()
    }

    /// Frozen order: commit reset-pending, remove `current`, reset sl-authd,
    /// remove the generations, then clear reset-pending.
    fn boot_reset(&mut self) -> Result<(), Failed> {
        self.create_marker(RESET_PENDING)?;
        self.remove_current()?;
        self.tools
            .reset_enrollment()
            .map_err(|_| Failed("sl-authd could not reset enrollment"))?;
        self.remove_unreferenced_generations()?;
        self.remove_marker(RESET_PENDING)
    }

    fn marker_exists(&self, name: &str) -> Result<bool, Failed> {
        match fs::symlink_metadata(self.root.join(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(Failed("a remote-management marker could not be checked")),
        }
    }

    fn ensure_directory(&self, path: &Path, mode: u32, group: bool) -> Result<(), Failed> {
        match DirBuilder::new().mode(mode).create(path) {
            Ok(()) => {
                io_failure(
                    fs::set_permissions(path, Permissions::from_mode(mode)),
                    "a state directory could not be created",
                )?;
                if group {
                    self.apply_group(path)?;
                }
                io_failure(
                    fsync_directory(path.parent().unwrap_or(Path::new("/"))),
                    "a state directory could not be created",
                )
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.is_dir() => Ok(()),
                    _ => Err(Failed("a state path is not a directory")),
                }
            }
            Err(_) => Err(Failed("a state directory could not be created")),
        }
    }

    fn apply_group(&self, path: &Path) -> Result<(), Failed> {
        match self.ownership {
            Ownership::RemotedGroup(gid) => io_failure(
                std::os::unix::fs::lchown(path, Some(0), Some(gid)),
                "TLS file ownership could not be set",
            ),
            Ownership::Unavailable => Err(Failed("the sl-remoted group is unavailable")),
            #[cfg(test)]
            Ownership::Skip => Ok(()),
        }
    }

    /// O_CREAT|O_EXCL temporary, fsync, rename, then fsync the directory. An
    /// existing marker is left as it is.
    fn create_marker(&mut self, name: &'static str) -> Result<(), Failed> {
        self.ensure_directory(&self.root.clone(), 0o755, false)?;
        if self.marker_exists(name)? {
            return Ok(());
        }
        self.fault(Point::CreateMarker(name))?;
        let temporary = self.root.join(format!("{name}.tmp"));
        let written = (|| {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&temporary)?;
            file.set_permissions(Permissions::from_mode(0o644))?;
            file.sync_all()?;
            fs::rename(&temporary, self.root.join(name))?;
            fsync_directory(&self.root)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Failed("a remote-management marker could not be written"));
        }
        Ok(())
    }

    /// unlink, then fsync the directory. An absent marker is a no-op.
    fn remove_marker(&mut self, name: &'static str) -> Result<(), Failed> {
        if !self.marker_exists(name)? {
            return Ok(());
        }
        self.fault(Point::RemoveMarker(name))?;
        io_failure(
            fs::remove_file(self.root.join(name)).and_then(|()| fsync_directory(&self.root)),
            "a remote-management marker could not be removed",
        )
    }

    /// Writes a complete generation directory, or nothing. Leftover
    /// unreferenced generations are removed first, so a new name never
    /// collides with one.
    fn generate_identity(&mut self) -> Result<String, Failed> {
        self.ensure_directory(&self.root.clone(), 0o755, false)?;
        self.ensure_directory(&self.tls(), 0o750, true)?;
        self.remove_unreferenced_generations()?;
        let mut bytes = [0u8; 8];
        self.tools
            .random(&mut bytes)
            .map_err(|_| Failed("randomness is unavailable"))?;
        let generation = layout::generation_name(bytes);
        let directory = self.tls().join(&generation);
        io_failure(
            DirBuilder::new().mode(0o750).create(&directory),
            "a TLS generation directory could not be created",
        )?;
        let written = self.fill_generation(&directory);
        if written.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        written.map(|()| generation)
    }

    fn fill_generation(&mut self, directory: &Path) -> Result<(), Failed> {
        io_failure(
            fs::set_permissions(directory, Permissions::from_mode(0o750)),
            "a TLS generation directory could not be created",
        )?;
        self.apply_group(directory)?;
        self.tools
            .openssl(&req_arguments(directory))
            .map_err(|_| Failed("openssl could not generate the TLS identity"))?;
        let output = self
            .tools
            .openssl(&fingerprint_arguments(directory))
            .map_err(|_| Failed("openssl could not compute the fingerprint"))?;
        let fingerprint = layout::parse_openssl_fingerprint(&output)
            .ok_or(Failed("openssl returned a malformed fingerprint"))?;
        for (name, mode) in [(KEY_FILE, 0o640), (CERT_FILE, 0o644)] {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() => {}
                _ => return Err(Failed("openssl did not write the expected files")),
            }
            io_failure(
                fs::set_permissions(&path, Permissions::from_mode(mode)),
                "TLS file permissions could not be set",
            )?;
            self.apply_group(&path)?;
            io_failure(
                File::open(&path).and_then(|file| file.sync_all()),
                "a TLS file could not be synced",
            )?;
        }
        io_failure(
            (|| {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(directory.join(FINGERPRINT_FILE))?;
                file.set_permissions(Permissions::from_mode(0o644))?;
                file.write_all(layout::fingerprint_file_contents(&fingerprint).as_bytes())?;
                file.sync_all()?;
                fsync_directory(directory)
            })(),
            "the fingerprint could not be written",
        )
    }

    /// A symlink under a temporary name, renamed over `current`, then fsync.
    fn swap_current(&mut self, generation: &str) -> Result<(), Failed> {
        self.fault(Point::SwapCurrent)?;
        let temporary = self.tls().join(format!("{CURRENT}.tmp"));
        let swapped = (|| {
            symlink(generation, &temporary)?;
            fs::rename(&temporary, self.tls().join(CURRENT))?;
            fsync_directory(&self.tls())
        })();
        if swapped.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(Failed("the TLS identity could not be installed"));
        }
        Ok(())
    }

    fn remove_current(&mut self) -> Result<(), Failed> {
        self.fault(Point::RemoveCurrent)?;
        match fs::remove_file(self.tls().join(CURRENT)) {
            Ok(()) => io_failure(
                fsync_directory(&self.tls()),
                "the TLS identity could not be removed",
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Failed("the TLS identity could not be removed")),
        }
    }

    /// Removes every generation that `current` does not reference.
    fn remove_unreferenced_generations(&mut self) -> Result<(), Failed> {
        self.fault(Point::RemoveGenerations)?;
        let referenced = layout::current_generation(&self.root).ok().flatten();
        let entries = match fs::read_dir(self.tls()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Failed("TLS generations could not be listed")),
        };
        let mut removed = false;
        for entry in entries {
            let entry = io_failure(entry, "TLS generations could not be listed")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !layout::is_generation_name(name) || Some(name) == referenced.as_deref() {
                continue;
            }
            let path = entry.path();
            let result = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path),
                _ => fs::remove_file(&path),
            };
            io_failure(result, "an old TLS generation could not be removed")?;
            removed = true;
        }
        if removed {
            io_failure(
                fsync_directory(&self.tls()),
                "an old TLS generation could not be removed",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
