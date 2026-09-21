use sl_protocol::{PlatformProxy, Status, UpdateState, SCHEMA_VERSION};
use std::{process::ExitCode, time::Duration};

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

fn bus_error(error: &zbus::Error) -> (&str, String) {
    if let zbus::Error::MethodError(name, message, _) = error {
        if let Some(code) = name
            .as_str()
            .strip_prefix("org.signallayer.Platform1.Error.")
        {
            return (
                code,
                message
                    .as_deref()
                    .unwrap_or("Platform status query failed")
                    .into(),
            );
        }
    }
    (
        "ServiceUnavailable",
        "The local platform status service could not be reached".into(),
    )
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
        _ => {
            return report_error(
                json,
                "Usage",
                "Usage: corectl status [--json] | corectl update [--json]",
            )
        }
    };
    let connection = match zbus::connection::Builder::system() {
        Ok(builder) => match builder
            .method_timeout(Duration::from_secs(25))
            .build()
            .await
        {
            Ok(connection) => connection,
            Err(_) => {
                return report_error(
                    json,
                    "ServiceUnavailable",
                    "The system D-Bus is unavailable",
                )
            }
        },
        Err(_) => {
            return report_error(
                json,
                "ServiceUnavailable",
                "The system D-Bus is unavailable",
            )
        }
    };
    let proxy = match PlatformProxy::builder(&connection)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
    {
        Ok(proxy) => proxy,
        Err(error) => {
            let (code, message) = bus_error(&error);
            return report_error(json, code, &message);
        }
    };
    if action == "update" {
        return match proxy.start_update().await {
            Ok(()) => {
                if json {
                    println!("{}", serde_json::json!({"state":"running"}));
                } else {
                    println!("Update staging started. Use `corectl status` to observe it.");
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                let (code, message) = bus_error(&error);
                report_error(json, code, &message)
            }
        };
    }
    let response = match proxy.get_status().await {
        Ok(response) => response,
        Err(error) => {
            let (code, message) = bus_error(&error);
            return report_error(json, code, &message);
        }
    };
    let status: Status = match serde_json::from_str(&response) {
        Ok(status) => status,
        Err(_) => {
            return report_error(
                json,
                "InvalidResponse",
                "The platform returned an invalid status response",
            )
        }
    };
    if status.schema_version != SCHEMA_VERSION {
        return report_error(
            json,
            "UnsupportedSchema",
            "The platform status schema is unsupported",
        );
    }
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
        println!("{} {}\nPlatform API: {}\nSource: {}\nBuild: {}\nDeployment: {}\nImage: {}\nDigest: {}\nRetained rollback: {}\nHealth: {:?} (systemd {}; {} failed units)",
            status.product, status.version, status.platform_api_version,
            status.source_revision.as_deref().unwrap_or("unknown"), status.build_id.as_deref().unwrap_or("unknown"),
            status.booted.deployment_id, status.booted.image_reference.as_deref().unwrap_or("unknown"),
            status.booted.image_digest.as_deref().unwrap_or("unknown"),
            status.retained_rollback.as_ref().map(|deployment| deployment.deployment_id.as_str()).unwrap_or("none"),
            status.health.state, status.health.system_state, status.health.failed_units);
        println!("Update: {update}");
    }
    ExitCode::SUCCESS
}
