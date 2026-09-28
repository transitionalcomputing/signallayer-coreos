use sl_console::{
    Action, AuthFailure, BusBackend, ConsoleError, Controller, PlatformFailure, View,
};
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::time::Duration;

const RETRY_DELAY: Duration = Duration::from_secs(3);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    loop {
        match BusBackend::connect().await {
            Ok(backend) => {
                if run(Controller::new(backend)).await.is_err() {
                    appliance_error("The local console could not read from its terminal.");
                }
            }
            Err(_) => appliance_error("Local services are temporarily unavailable. Retrying."),
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

async fn run(mut controller: Controller<BusBackend>) -> io::Result<()> {
    let mut message = String::new();
    loop {
        let view = match controller.refresh().await {
            Ok(view) => view,
            Err(error) => {
                clear();
                println!("SignalLayer CoreOS\n\n{}", error_message(error));
                println!("\nThe appliance console will remain here. Press Enter to retry.");
                read_line(32)?;
                continue;
            }
        };
        clear();
        print!("{}", render(&view, &message));
        io::stdout().flush()?;
        message.clear();
        let choice = read_line(32)?;
        let result = match choice.trim().to_ascii_lowercase().as_str() {
            "1" if view.remote.enabled => perform(&mut controller, &view, Action::Disable).await,
            "1" => perform(&mut controller, &view, Action::Enable).await,
            "2" => {
                print!("Type REENROLL to reset enrollment and rotate the TLS identity: ");
                io::stdout().flush()?;
                if read_line(32)?.trim() != "REENROLL" {
                    Ok("Re-enrollment cancelled.".into())
                } else {
                    perform(&mut controller, &view, Action::Reenroll).await
                }
            }
            "3" => recover(&mut controller).await,
            "4" if view.authenticated => {
                controller.logout();
                Ok("Protected console session locked.".into())
            }
            "4" if view.remote.enrolled => authenticate(&mut controller).await,
            "4" => Ok(
                "No operator is enrolled yet. Enable remote management to begin pairing.".into(),
            ),
            "r" | "" => Ok(String::new()),
            _ => Ok("Unknown selection.".into()),
        };
        message = result.unwrap_or_else(error_message);
    }
}

async fn perform(
    controller: &mut Controller<BusBackend>,
    view: &View,
    action: Action,
) -> Result<String, ConsoleError> {
    if view.remote.enrolled && !view.authenticated {
        authenticate(controller).await?;
    }
    controller.act(action).await?;
    Ok(match action {
        Action::Enable => "Remote management enabled.".into(),
        Action::Disable => "Remote management disabled.".into(),
        Action::Reenroll => "Re-enrollment prepared. Use the new pairing information below.".into(),
    })
}

async fn authenticate(controller: &mut Controller<BusBackend>) -> Result<String, ConsoleError> {
    let password =
        read_secret("Operator password: ").map_err(|_| ConsoleError::StatusUnavailable)?;
    controller.authenticate(&password).await?;
    Ok("Operator authenticated.".into())
}

async fn recover(controller: &mut Controller<BusBackend>) -> Result<String, ConsoleError> {
    let key = read_secret("Recovery key: ").map_err(|_| ConsoleError::StatusUnavailable)?;
    let first =
        read_secret("New operator password: ").map_err(|_| ConsoleError::StatusUnavailable)?;
    let second =
        read_secret("Confirm new password: ").map_err(|_| ConsoleError::StatusUnavailable)?;
    if first != second {
        return Ok("The new passwords did not match; nothing changed.".into());
    }
    controller.recover_password(&key, &first).await?;
    Ok("Operator password recovered. Authenticate with the new password.".into())
}

fn render(view: &View, message: &str) -> String {
    let mut out = format!(
        "SignalLayer CoreOS\n{} {}\nMachine: {}\n\nRemote management: {}\nHTTPS listener: {}\nOperator enrollment: {}\n",
        view.product,
        view.version,
        view.machine_id,
        if view.remote.enabled { "enabled" } else { "disabled" },
        if view.remote.listening { "active" } else { "inactive" },
        if view.remote.enrolled { "enrolled" } else { "not enrolled" },
    );
    if !view.enrollment.url.is_empty() {
        out.push_str(&format!("Connection: {}\n", view.enrollment.url));
    }
    if !view.enrollment.fingerprint.is_empty() {
        out.push_str(&format!(
            "TLS SHA-256 fingerprint: {}\n",
            view.enrollment.fingerprint
        ));
    }
    if !view.enrollment.pairing_code.is_empty() {
        out.push_str(&format!(
            "Pairing code: {}  (expires at Unix {})\n",
            pairing_code(&view.enrollment.pairing_code),
            view.enrollment.expires_at
        ));
    }
    if view.reset_incomplete {
        out.push_str("\nREPAIR REQUIRED: A reset did not finish. Choose Reenroll.\n");
    }
    if !message.is_empty() {
        out.push_str(&format!("\n{message}\n"));
    }
    out.push_str(&format!(
        "\n1) {} remote management\n2) Reenroll remote management\n3) Recover operator password\n4) {}\nR) Refresh\n\nSelection: ",
        if view.remote.enabled { "Disable" } else { "Enable" },
        if view.authenticated { "Lock console" } else { "Authenticate" },
    ));
    out
}

fn pairing_code(code: &str) -> String {
    if code.len() == 8 && code.is_ascii() {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        "unavailable".into()
    }
}

fn error_message(error: ConsoleError) -> String {
    match error {
        ConsoleError::AuthenticationRequired => "Authenticate before using that operation.",
        ConsoleError::Auth(AuthFailure::InvalidCredential) => "Authentication failed.",
        ConsoleError::Auth(AuthFailure::RateLimited) => "Too many attempts. Wait before retrying.",
        ConsoleError::Auth(AuthFailure::Busy) => "Authentication is busy. Try again shortly.",
        ConsoleError::Auth(AuthFailure::PasswordRejected) => {
            "The new password does not meet the password requirements."
        }
        ConsoleError::Auth(AuthFailure::NotEnrolled) => "No operator is enrolled.",
        ConsoleError::Auth(AuthFailure::EnrollmentUnconfirmed) => {
            "Enrollment recovery confirmation is incomplete."
        }
        ConsoleError::Auth(AuthFailure::InvalidArgument) => "The credential format is invalid.",
        ConsoleError::Auth(AuthFailure::Unavailable) => {
            "The authentication service is unavailable."
        }
        ConsoleError::Platform(PlatformFailure::ResetIncomplete) => {
            "A reset did not finish. Choose Reenroll to repair remote management."
        }
        ConsoleError::Platform(PlatformFailure::Busy) => {
            "Another remote-management operation is in progress."
        }
        ConsoleError::Platform(PlatformFailure::Unavailable) => {
            "Remote management is temporarily unavailable."
        }
        ConsoleError::StatusUnavailable => "Appliance status is temporarily unavailable.",
    }
    .into()
}

fn clear() {
    print!("\x1b[2J\x1b[H");
}

fn appliance_error(message: &str) {
    clear();
    println!("SignalLayer CoreOS\n\n{message}");
    let _ = io::stdout().flush();
}

fn read_line(max: usize) -> io::Result<String> {
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    if line.len() > max {
        line.clear();
        line.push_str("<input-too-long>");
    }
    Ok(line)
}

struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

fn read_secret(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(io::Error::other("console input is not a terminal"));
    }
    let fd = stdin.as_raw_fd();
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let original = unsafe { termios.assume_init() };
    let guard = EchoGuard { fd, original };
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let line = read_line(1025);
    drop(guard);
    println!();
    line.map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_console::Enrollment;
    use sl_protocol::RemoteManagementStatus;

    fn view() -> View {
        View {
            product: "SignalLayerIT CoreOS".into(),
            version: "0.0.3".into(),
            machine_id: "machine".into(),
            remote: RemoteManagementStatus {
                enabled: true,
                listening: true,
                enrolled: false,
            },
            enrollment: Enrollment {
                url: "https://10.0.0.2:8443/".into(),
                fingerprint: "AA:BB".into(),
                pairing_code: "01234567".into(),
                expires_at: 42,
            },
            authenticated: false,
            reset_incomplete: false,
        }
    }

    #[test]
    fn view_uses_appliance_terms_and_formats_pairing_code() {
        let text = render(&view(), "");
        assert!(text.contains("Pairing code: 0123-4567"));
        assert!(text.contains("TLS SHA-256 fingerprint: AA:BB"));
        assert!(!text.contains("shell"));
    }

    #[test]
    fn reset_incomplete_names_reenroll_as_the_repair() {
        let mut value = view();
        value.reset_incomplete = true;
        assert!(render(&value, "")
            .contains("REPAIR REQUIRED: A reset did not finish. Choose Reenroll."));
    }

    #[test]
    fn authentication_and_service_failures_are_distinct() {
        assert_ne!(
            error_message(ConsoleError::Auth(AuthFailure::InvalidCredential)),
            error_message(ConsoleError::Auth(AuthFailure::Unavailable))
        );
        assert_ne!(
            error_message(ConsoleError::Platform(PlatformFailure::ResetIncomplete)),
            error_message(ConsoleError::Platform(PlatformFailure::Unavailable))
        );
    }
}
