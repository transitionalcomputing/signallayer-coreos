use sl_platform_client::{ClientError, PlatformClient};
use sl_protocol::{RollbackState, UpdateState};
use std::process::ExitCode;

fn report_error(json: bool, code: &str, message: &str) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({"error":{"code":code,"message":message}})
        );
    } else {
        eprintln!("corectl: {code}: {message}");
    }
    ExitCode::FAILURE
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
        _ => return report_error(
            json,
            "Usage",
            "Usage: corectl status [--json] | corectl update [--json] | corectl rollback [--json]",
        ),
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
