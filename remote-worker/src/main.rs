//! sl-remote-worker: the fixed remote-management worker. Each worker unit runs
//! it with exactly one fixed mode argument; there is no other input.
mod worker;

use std::{
    ffi::{CString, OsString},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};
use worker::{Mode, Ownership, Tools, Worker, OPENSSL};

const AUTH_BUS: &str = "org.signallayer.Auth1";
const AUTH_PATH: &str = "/org/signallayer/Auth1";
const AUTH_INTERFACE: &str = "org.signallayer.Auth1";
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTED_GROUP: &str = "sl-remoted";

struct SystemTools;

impl Tools for SystemTools {
    fn openssl(&mut self, arguments: &[OsString]) -> Result<Vec<u8>, ()> {
        let output = Command::new(OPENSSL)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ())?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(())
        }
    }

    fn reset_enrollment(&mut self) -> Result<(), ()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ())?;
        runtime.block_on(async {
            tokio::time::timeout(AUTH_TIMEOUT, async {
                let connection = zbus::Connection::system().await?;
                let proxy =
                    zbus::Proxy::new(&connection, AUTH_BUS, AUTH_PATH, AUTH_INTERFACE).await?;
                proxy.call::<_, _, ()>("ResetEnrollment", &()).await
            })
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
        })
    }

    fn random(&mut self, buffer: &mut [u8]) -> Result<(), ()> {
        let mut filled = 0;
        while filled < buffer.len() {
            let remaining = &mut buffer[filled..];
            // SAFETY: the pointer and length describe a live, writable slice.
            let result =
                unsafe { libc::getrandom(remaining.as_mut_ptr().cast(), remaining.len(), 0) };
            if result > 0 && (result as usize) <= remaining.len() {
                filled += result as usize;
            } else if result < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                buffer.fill(0);
                return Err(());
            }
        }
        Ok(())
    }
}

fn group_id(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer refers to live storage of the stated size, and the
    // result is read only when getgrnam_r reports success with a non-null entry.
    let status = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            group.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    (status == 0 && !result.is_null()).then(|| unsafe { group.assume_init() }.gr_gid)
}

fn parse_mode(arguments: &[OsString]) -> Option<Mode> {
    match arguments {
        [argument] => argument.to_str().and_then(Mode::parse),
        _ => None,
    }
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(mode) = parse_mode(&arguments) else {
        eprintln!("sl-remote-worker: expected exactly one fixed mode");
        return ExitCode::from(2);
    };
    // SAFETY: umask only changes this process's file-creation mask.
    unsafe { libc::umask(0o077) };
    let ownership = if mode.writes_identity() {
        match group_id(REMOTED_GROUP) {
            Some(gid) => Ownership::RemotedGroup(gid),
            None => {
                eprintln!(
                    "sl-remote-worker: {}: the sl-remoted group is missing",
                    mode.name()
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        Ownership::Unavailable
    };
    let mut worker = Worker::new(sl_remote_state::STATE_DIR, SystemTools, ownership);
    match worker.run(mode) {
        Ok(()) => {
            eprintln!("sl-remote-worker: {}: ok", mode.name());
            ExitCode::SUCCESS
        }
        Err(worker::Failed(message)) => {
            eprintln!("sl-remote-worker: {}: {message}", mode.name());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_fixed_mode_is_accepted() {
        let parse = |arguments: &[&str]| {
            parse_mode(&arguments.iter().map(OsString::from).collect::<Vec<_>>())
        };
        assert_eq!(parse(&["enable"]), Some(Mode::Enable));
        assert_eq!(parse(&["disable"]), Some(Mode::Disable));
        assert_eq!(parse(&["rotate-tls"]), Some(Mode::RotateTls));
        assert_eq!(parse(&["boot-reset"]), Some(Mode::BootReset));
        assert_eq!(
            parse(&["clear-reset-pending"]),
            Some(Mode::ClearResetPending)
        );
        for invalid in [
            &[][..],
            &["enable", "disable"],
            &["Enable"],
            &["enable "],
            &["--enable"],
            &["reset"],
            &[""],
        ] {
            assert_eq!(parse(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn only_identity_writing_modes_need_the_remoted_group() {
        assert!(Mode::Enable.writes_identity());
        assert!(Mode::RotateTls.writes_identity());
        for mode in [Mode::Disable, Mode::BootReset, Mode::ClearResetPending] {
            assert!(!mode.writes_identity());
        }
    }

    #[test]
    fn random_fills_the_whole_buffer() {
        let mut buffer = [0u8; 32];
        SystemTools.random(&mut buffer).unwrap();
        assert_ne!(buffer, [0u8; 32]);
    }
}
