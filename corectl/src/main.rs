use sl_platform_client::{ClientError, PlatformClient};
use sl_protocol::{RollbackState, UpdateState};
use std::process::ExitCode;

// Exit codes: 0 success, 1 failure, 3 reboot outcome unknown.
const EXIT_FAILURE: u8 = 1;
const EXIT_OUTCOME_UNKNOWN: u8 = 3;

#[derive(Debug, PartialEq, Eq)]
struct Report {
    exit: u8,
    stdout: Option<String>,
    stderr: Option<String>,
}

impl Report {
    fn emit(self) -> ExitCode {
        if let Some(stdout) = self.stdout {
            println!("{stdout}");
        }
        if let Some(stderr) = self.stderr {
            eprintln!("{stderr}");
        }
        ExitCode::from(self.exit)
    }
}

fn error_report(json: bool, exit: u8, code: &str, message: &str) -> Report {
    if json {
        Report {
            exit,
            stdout: Some(serde_json::json!({"error":{"code":code,"message":message}}).to_string()),
            stderr: None,
        }
    } else {
        Report {
            exit,
            stdout: None,
            stderr: Some(format!("corectl: {code}: {message}")),
        }
    }
}

fn report_error(json: bool, code: &str, message: &str) -> ExitCode {
    error_report(json, EXIT_FAILURE, code, message).emit()
}

fn reboot_report(json: bool, result: &Result<(), ClientError>) -> Report {
    match result {
        Ok(()) => Report {
            exit: 0,
            stdout: Some(if json {
                serde_json::json!({"state":"accepted"}).to_string()
            } else {
                "Reboot accepted by systemd. The system is restarting.".into()
            }),
            stderr: None,
        },
        Err(error @ ClientError::RebootOutcomeUnknown) if json => {
            error_report(json, EXIT_OUTCOME_UNKNOWN, error.code(), error.message())
        }
        Err(error @ ClientError::RebootOutcomeUnknown) => Report {
            exit: EXIT_OUTCOME_UNKNOWN,
            stdout: None,
            stderr: Some(error.message().into()),
        },
        Err(error) => error_report(json, EXIT_FAILURE, error.code(), error.message()),
    }
}

fn client_error(json: bool, error: &ClientError) -> ExitCode {
    report_error(json, error.code(), error.message())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|arg| arg == "--json");
    let action = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status"] | ["status", "--json"] => "status",
        ["update"] | ["update", "--json"] => "update",
        ["rollback"] | ["rollback", "--json"] => "rollback",
        ["reboot"] | ["reboot", "--json"] => "reboot",
        _ => {
            return report_error(
                json,
                "Usage",
                "Usage: corectl status [--json] | corectl update [--json] | \
             corectl rollback [--json] | corectl reboot [--json]",
            )
        }
    };
    let client = match PlatformClient::connect().await {
        Ok(client) => client,
        Err(error) => return client_error(json, &error),
    };
    if action == "update" {
        return match client.start_update().await {
            Ok(()) => {
                if json {
                    println!("{}", serde_json::json!({"state":"running"}));
                } else {
                    println!("Update staging started. Use `corectl status` to observe it.");
                }
                ExitCode::SUCCESS
            }
            Err(error) => client_error(json, &error),
        };
    }
    if action == "reboot" {
        return reboot_report(json, &client.start_reboot().await).emit();
    }
    if action == "rollback" {
        return match client.start_rollback().await {
            Ok(()) => {
                if json {
                    println!("{}", serde_json::json!({"state":"running"}));
                } else {
                    println!("Rollback selection started. Use `corectl status` to observe it.");
                }
                ExitCode::SUCCESS
            }
            Err(error) => client_error(json, &error),
        };
    }
    let status = match client.get_status().await {
        Ok(status) => status,
        Err(error) => return client_error(json, &error),
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).expect("serializable status")
        );
    } else {
        let update = match &status.update.state {
            UpdateState::Idle => "idle".to_owned(),
            UpdateState::Running => "running".to_owned(),
            UpdateState::Staged => format!(
                "staged (reboot required; {})",
                status
                    .update
                    .staged
                    .as_ref()
                    .map(|deployment| deployment.deployment_id.as_str())
                    .unwrap_or("unknown")
            ),
            UpdateState::Failed => format!(
                "failed ({})",
                status
                    .update
                    .failure
                    .as_ref()
                    .map(|failure| failure.message.as_str())
                    .unwrap_or("unknown worker failure")
            ),
        };
        let rollback = match &status.rollback.state {
            RollbackState::Idle => "idle".to_owned(),
            RollbackState::Running => "running".to_owned(),
            RollbackState::Queued => "queued (reboot required)".to_owned(),
            RollbackState::Failed => format!(
                "failed ({})",
                status
                    .rollback
                    .failure
                    .as_ref()
                    .map(|failure| failure.message.as_str())
                    .unwrap_or("unknown worker failure")
            ),
        };
        println!("{} {}\nPlatform API: {}\nSource: {}\nBuild: {}\nDeployment: {}\nImage: {}\nDigest: {}\nRetained rollback: {}\nHealth: {:?} (systemd {}; {} failed units)",
            status.product, status.version, status.platform_api_version,
            status.source_revision.as_deref().unwrap_or("unknown"), status.build_id.as_deref().unwrap_or("unknown"),
            status.booted.deployment_id, status.booted.image_reference.as_deref().unwrap_or("unknown"),
            status.booted.image_digest.as_deref().unwrap_or("unknown"),
            status.retained_rollback.as_ref().map(|deployment| deployment.deployment_id.as_str()).unwrap_or("none"),
            status.health.state, status.health.system_state, status.health.failed_units);
        println!(
            "Machine: {} ({}; boot {})",
            status.machine.machine_id, status.machine.architecture, status.machine.boot_id
        );
        println!("Network: {:?}", status.network.state);
        if let Some(primary) = &status.network.primary_connection {
            println!(
                "Primary connection: {}\nAddresses: {}\nDefault gateways: {}",
                primary.interface,
                if primary.addresses.is_empty() {
                    "none".into()
                } else {
                    primary.addresses.join(", ")
                },
                if primary.default_gateways.is_empty() {
                    "none".into()
                } else {
                    primary.default_gateways.join(", ")
                }
            );
        } else {
            println!("Primary connection: none");
        }
        println!("Update: {update}");
        println!("Rollback: {rollback}");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_reboot_succeeds() {
        assert_eq!(
            reboot_report(false, &Ok(())),
            Report {
                exit: 0,
                stdout: Some("Reboot accepted by systemd. The system is restarting.".into()),
                stderr: None,
            }
        );
        assert_eq!(
            reboot_report(true, &Ok(())).stdout.as_deref(),
            Some(r#"{"state":"accepted"}"#)
        );
    }

    #[test]
    fn rejected_reboot_reports_mapped_error_and_fails() {
        let conflict = Err(ClientError::RemoteMethod {
            code: "Conflict".into(),
            message: "The update worker is running; reboot was not requested".into(),
        });
        assert_eq!(
            reboot_report(false, &conflict),
            Report {
                exit: EXIT_FAILURE,
                stdout: None,
                stderr: Some(
                    "corectl: Conflict: The update worker is running; reboot was not requested"
                        .into()
                ),
            }
        );
        let unsupported = reboot_report(true, &Err(ClientError::Unsupported));
        assert_eq!(unsupported.exit, EXIT_FAILURE);
        assert!(unsupported
            .stdout
            .unwrap()
            .contains(r#""code":"Unsupported""#));
    }

    #[test]
    fn indeterminate_reboot_has_distinct_exit_and_message() {
        let unknown = Err(ClientError::RebootOutcomeUnknown);
        assert_eq!(
            reboot_report(false, &unknown),
            Report {
                exit: EXIT_OUTCOME_UNKNOWN,
                stdout: None,
                stderr: Some(
                    "Reboot request outcome unknown: connection closed while awaiting \
                     confirmation; the system may be rebooting."
                        .into()
                ),
            }
        );
        let json = reboot_report(true, &unknown);
        assert_eq!(json.exit, EXIT_OUTCOME_UNKNOWN);
        assert!(json.stdout.unwrap().contains(r#""code":"OutcomeUnknown""#));
        assert_ne!(EXIT_OUTCOME_UNKNOWN, EXIT_FAILURE);
    }
}
