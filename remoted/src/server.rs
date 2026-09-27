//! Accepting and serving connections under the published generation.
use crate::{
    controller::{Listeners, Shared},
    http::ConnInfo,
    network::PORT,
};
use axum::{body::Body, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::Semaphore,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

pub const MAX_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BACKLOG: u32 = 64;

pub struct Server {
    pub tls: TlsAcceptor,
    pub router: Router,
    pub shared: Arc<Shared>,
    pub connections: Arc<Semaphore>,
}

impl Server {
    pub fn new(tls: TlsAcceptor, router: Router, shared: Arc<Shared>) -> Arc<Self> {
        Arc::new(Self {
            tls,
            router,
            shared,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }
}

/// Every accepted connection is checked before any TLS byte is exchanged: it
/// must belong to the current generation and come from an on-link source.
pub async fn accept_loop(
    listener: TcpListener,
    local: SocketAddr,
    generation: u64,
    server: Arc<Server>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !server.shared.admits(generation, peer.ip()) {
            drop(stream);
            continue;
        }
        let Ok(permit) = Arc::clone(&server.connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let _permit = permit;
            serve_connection(stream, ConnInfo { local, peer }, generation, server).await;
        });
    }
}

/// Ends as soon as the published generation changes.
async fn serve_connection(
    stream: tokio::net::TcpStream,
    conn: ConnInfo,
    generation: u64,
    server: Arc<Server>,
) {
    let mut changes = server.shared.subscribe();
    if !server.shared.is_current(generation) {
        return;
    }
    let work = async {
        let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, server.tls.accept(stream)).await else {
            return;
        };
        let router = server.router.clone();
        let service = hyper::service::service_fn(
            move |mut request: hyper::Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(conn);
                let mut router = router.clone();
                async move { router.call(request.map(Body::new)).await }
            },
        );
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .serve_connection(TokioIo::new(tls), service)
            .await;
    };
    tokio::select! {
        _ = work => {}
        _ = changes.wait_for(|current| *current != generation) => {}
    }
}

/// Real listeners: one per address on port 8443, never a wildcard.
pub struct TcpListeners {
    server: Arc<Server>,
    port: u16,
    bound: Vec<(SocketAddr, TcpListener)>,
    tasks: Vec<JoinHandle<()>>,
}

impl TcpListeners {
    pub fn new(server: Arc<Server>) -> Self {
        Self::with_port(server, PORT)
    }

    fn with_port(server: Arc<Server>, port: u16) -> Self {
        Self {
            server,
            port,
            bound: Vec::new(),
            tasks: Vec::new(),
        }
    }
}

fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = match address.ip() {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(BACKLOG)
}

impl Listeners for TcpListeners {
    fn bind(&mut self, addresses: &[IpAddr]) -> Vec<SocketAddr> {
        for address in addresses {
            if let Ok(listener) = bind(SocketAddr::new(*address, self.port)) {
                if let Ok(local) = listener.local_addr() {
                    self.bound.push((local, listener));
                }
            }
        }
        self.bound.iter().map(|(local, _)| *local).collect()
    }

    fn serve(&mut self, generation: u64) {
        for (local, listener) in self.bound.drain(..) {
            self.tasks.push(tokio::spawn(accept_loop(
                listener,
                local,
                generation,
                Arc::clone(&self.server),
            )));
        }
    }

    fn close(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        self.bound.clear();
    }
}

impl Drop for TcpListeners {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
