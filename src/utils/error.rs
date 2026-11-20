use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpProxyError {
    #[error("Proxy returned {0}")]
    ProxyRejected(http::StatusCode),

    #[error("Failed to load system root certificates: {0}")]
    RootCertLoad(String),

    #[error("Invalid proxy hostname")]
    InvalidProxyHostname,

    #[error("Proxy URL must start with http:// or https://")]
    InvalidProxyUrl,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Http(#[from] http::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}
