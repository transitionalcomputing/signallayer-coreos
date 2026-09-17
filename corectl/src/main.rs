use sl_protocol::{PlatformProxy, Status, SCHEMA_VERSION};
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
    if args != ["status"] && args != ["status", "--json"] {
        return report_error(json, "Usage", "Usage: corectl status [--json]");
    }
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
        println!("{} {}\nPlatform API: {}\nSource: {}\nBuild: {}\nDeployment: {}\nImage: {}\nDigest: {}\nRetained rollback: {}\nHealth: {:?} (systemd {}; {} failed units)",
            status.product, status.version, status.platform_api_version,
            status.source_revision.as_deref().unwrap_or("unknown"), status.build_id.as_deref().unwrap_or("unknown"),
            status.booted.deployment_id, status.booted.image_reference.as_deref().unwrap_or("unknown"),
            status.booted.image_digest.as_deref().unwrap_or("unknown"),
            status.retained_rollback.as_ref().map(|deployment| deployment.deployment_id.as_str()).unwrap_or("none"),
            status.health.state, status.health.system_state, status.health.failed_units);
    }
    ExitCode::SUCCESS
}
