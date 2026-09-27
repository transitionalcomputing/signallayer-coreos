use super::*;
use crate::{
    http::{router, AppState},
    network::view_from_status,
    peers::{Auth, AuthFailure, StatusSource},
    sessions::{KernelRandom, Sessions},
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use zbus::export::async_trait::async_trait;

const FIXTURE: &str = include_str!("../tls_fixture.pem");

struct NoAuth;

#[async_trait]
impl Auth for NoAuth {
    async fn verify_password(&self, _: String) -> Result<(), AuthFailure> {
        Err(AuthFailure::InvalidCredential)
    }
    async fn consume_pairing(&self, _: String, _: String) -> Result<String, AuthFailure> {
        Err(AuthFailure::NoPendingPairing)
    }
    async fn confirm_recovery_key(&self, _: String) -> Result<(), AuthFailure> {
        Err(AuthFailure::NoProvisionalEnrollment)
    }
}

struct NoStatus;

#[async_trait]
impl StatusSource for NoStatus {
    async fn status(&self) -> Result<String, ()> {
        Err(())
    }
}

fn server_config() -> Arc<ServerConfig> {
    let cert = CertificateDer::pem_slice_iter(FIXTURE.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(FIXTURE.as_bytes()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// The client trusts any certificate: these tests are about gating, Host and
/// lifecycle, not certificate validation (fingerprint trust is the owner's).
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}

struct Fixture {
    shared: Arc<Shared>,
    listeners: TcpListeners,
    local: SocketAddr,
}

/// A loopback listener on an ephemeral port, published with the given
/// primary-connection addresses as the on-link prefixes.
fn fixture(addresses: &[&str]) -> Fixture {
    let shared = Shared::new();
    let state = AppState {
        auth: Arc::new(NoAuth),
        status: Arc::new(NoStatus),
        sessions: Arc::new(Sessions::new(
            crate::sessions::tests::TestClock::default(),
            KernelRandom,
        )),
    };
    let server = Server::new(
        TlsAcceptor::from(server_config()),
        router(state),
        Arc::clone(&shared),
    );
    let mut listeners = TcpListeners::with_port(server, 0);
    let bound = listeners.bind(&["127.0.0.1".parse().unwrap()]);
    let status = serde_json::json!({"schema_version": "0.4", "network": {
        "primary_connection": {"addresses": addresses}}})
    .to_string();
    let generation = shared.publish(view_from_status(&status).unwrap());
    listeners.serve(generation);
    Fixture {
        shared,
        listeners,
        local: bound[0],
    }
}

async fn get(local: SocketAddr, host: &str) -> std::io::Result<String> {
    let stream = tokio::net::TcpStream::connect(local).await?;
    let name = ServerName::IpAddress(local.ip().into());
    let mut tls = connector().connect(name, stream).await?;
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[tokio::test]
async fn an_on_link_source_is_served_over_tls_with_host_enforced() {
    let fixture = fixture(&["127.0.0.1/8"]);
    let host = crate::network::endpoint(fixture.local);
    let response = get(fixture.local, &host).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("SignalLayer remote management"));
    let response = get(fixture.local, "localhost").await.unwrap();
    assert!(response.starts_with("HTTP/1.1 421"), "{response}");
}

#[tokio::test]
async fn an_off_link_source_is_dropped_before_tls() {
    let fixture = fixture(&["198.51.100.10/24"]);
    let host = crate::network::endpoint(fixture.local);
    assert!(
        get(fixture.local, &host).await.is_err(),
        "no handshake for off-link sources"
    );
}

#[tokio::test]
async fn withdrawal_refuses_new_connections_and_ends_open_ones() {
    let fixture = fixture(&["127.0.0.1/8"]);
    // Hold a TLS connection open without sending a request.
    let stream = tokio::net::TcpStream::connect(fixture.local).await.unwrap();
    let mut open = connector()
        .connect(ServerName::IpAddress(fixture.local.ip().into()), stream)
        .await
        .unwrap();
    // Withdrawing eligibility ends it, while the listener still exists.
    fixture.shared.withdraw();
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), open.read(&mut buffer)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the open connection ended"
    );
    let host = crate::network::endpoint(fixture.local);
    assert!(
        get(fixture.local, &host).await.is_err(),
        "a stale generation admits nothing"
    );
    drop(fixture.listeners);
}

#[tokio::test]
async fn closing_the_listeners_stops_accepting() {
    let mut fixture = fixture(&["127.0.0.1/8"]);
    fixture.listeners.close();
    tokio::task::yield_now().await;
    let host = crate::network::endpoint(fixture.local);
    assert!(get(fixture.local, &host).await.is_err());
}
