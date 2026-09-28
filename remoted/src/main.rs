//! sl-remoted: the read-only, on-link HTTPS remote-management service.
mod controller;
mod http;
mod netlink;
mod network;
mod peers;
mod server;
mod sessions;
mod tls;

use std::{path::Path, process::ExitCode, sync::Arc};

const LISTENING_MARKER: &str = "/run/sl-remoted/listening";

#[tokio::main]
async fn main() -> ExitCode {
    eprintln!("sl-remoted {}", env!("CARGO_PKG_VERSION"));
    let Ok(tls) = tls::load(Path::new(sl_remote_state::STATE_DIR)) else {
        eprintln!("sl-remoted: the TLS identity could not be loaded");
        return ExitCode::FAILURE;
    };
    // Without change notifications a stale listener could outlive a network
    // change, so there is no listening without them.
    let events = match netlink::Netlink::open() {
        Ok(events) => events,
        Err(_) => {
            eprintln!("sl-remoted: network change notifications are unavailable");
            return ExitCode::FAILURE;
        }
    };
    let Ok(connection) = zbus::Connection::system().await else {
        eprintln!("sl-remoted: the system bus is unavailable");
        return ExitCode::FAILURE;
    };
    let status: Arc<dyn peers::StatusSource> = Arc::new(peers::BusSession {
        connection: connection.clone(),
    });
    let state = http::AppState {
        auth: Arc::new(peers::BusAuth { connection }),
        status: Arc::clone(&status),
        sessions: Arc::new(sessions::Sessions::new(
            sessions::BootClock,
            sessions::KernelRandom,
        )),
    };
    let shared = controller::Shared::new();
    let server = server::Server::new(
        tokio_rustls::TlsAcceptor::from(tls),
        http::router(state),
        Arc::clone(&shared),
    );
    let controller = controller::Controller::new(
        status,
        server::TcpListeners::new(server),
        controller::Marker {
            path: LISTENING_MARKER.into(),
        },
        shared,
    );
    let error = controller.run(events).await;
    eprintln!(
        "sl-remoted: network change notifications failed: {}",
        error.kind()
    );
    ExitCode::FAILURE
}
