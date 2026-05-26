use super::error::HttpProxyError;
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper::client::conn::http1::handshake;
use hyper::upgrade::on;
use hyper_util::rt::TokioIo;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub type Result<T> = std::result::Result<T, HttpProxyError>;

#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

async fn send_connect_request<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    target: &str,
) -> Result<TokioIo<hyper::upgrade::Upgraded>> {
    let io = TokioIo::new(stream);
    let (mut sender, conn) = handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .body(Empty::<bytes::Bytes>::new())?;

    let res = sender.send_request(req).await?;
    if res.status() != StatusCode::OK {
        return Err(HttpProxyError::ProxyRejected(res.status()));
    }

    Ok(TokioIo::new(on(res).await?))
}

pub async fn proxy_connect(
    proxy_url: http::Uri,
    target_host: String,
    target_port: u16,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let authority = proxy_url
        .authority()
        .ok_or(HttpProxyError::InvalidProxyUrl)?;
    let host = authority.host();
    let port = authority
        .port_u16()
        .unwrap_or(match proxy_url.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
    let target = format!("{}:{}", target_host, target_port);
    let stream = TcpStream::connect((host, port)).await?;

    if proxy_url.scheme_str() == Some("https") {
        let insecure = proxy_url.query() == Some("insecure=true");
        let config = if insecure {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            let cert_result = rustls_native_certs::load_native_certs();
            if !cert_result.errors.is_empty() {
                return Err(HttpProxyError::RootCertLoad(
                    cert_result
                        .errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
            for cert in cert_result.certs {
                roots.add(cert)?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(config));
        let domain = ServerName::try_from(host.to_string())
            .map_err(|_| HttpProxyError::InvalidProxyHostname)?;
        let tls_stream = connector.connect(domain, stream).await?;
        send_connect_request(tls_stream, &target).await
    } else {
        send_connect_request(stream, &target).await
    }
}
