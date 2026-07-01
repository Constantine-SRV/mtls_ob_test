//! Access control:
//!  - CN allowlist: enforced INSIDE the client-cert verifier during the TLS
//!    handshake (a disallowed CN never reaches a handler — the TLS connection
//!    is rejected);
//!  - IP allowlist: axum middleware based on the source address
//!    (ConnectInfo<SocketAddr>), which also logs every request.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};

// ---------------- CN allowlist (TLS layer) ----------------

/// Wraps WebPkiClientVerifier: first the standard chain check against our CA
/// (delegated to `inner`), then the end-entity CN is matched against the
/// per-server allowlist. Logs every handshake decision.
#[derive(Debug)]
pub struct CnAllowlistVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow_cn: Vec<String>,
    label: &'static str,
}

impl CnAllowlistVerifier {
    pub fn new(inner: Arc<dyn ClientCertVerifier>, allow_cn: Vec<String>, label: &'static str) -> Self {
        Self { inner, allow_cn, label }
    }
}

impl ClientCertVerifier for CnAllowlistVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // 1) chain is valid and trusted by our CA
        let verified = match self.inner.verify_client_cert(end_entity, intermediates, now) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[{}] TLS: client cert chain invalid: {e}", self.label);
                return Err(e);
            }
        };
        // 2) CN must be in this server's allowlist
        let cn = cn_from_der(end_entity.as_ref())
            .ok_or_else(|| RustlsError::General("client cert has no CN".to_string()))?;
        if self.allow_cn.iter().any(|a| a == &cn) {
            println!("[{}] TLS: client CN='{}' accepted", self.label, cn);
            Ok(verified)
        } else {
            println!("[{}] TLS: client CN='{}' REJECTED (not in allow_cn)", self.label, cn);
            Err(RustlsError::General(format!("CN '{cn}' not in allowlist")))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn cn_from_der(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());
    cn
}

// ---------------- IP allowlist + request log (HTTP middleware) ----------------

/// State passed to the guard middleware: the allowed networks and a server label
/// used in log lines ("data" / "mgmt").
#[derive(Clone)]
pub struct GuardState {
    pub nets: Arc<Vec<IpNet>>,
    pub label: &'static str,
}

/// Parse IP/CIDR strings into networks. A bare IP is treated as /32 (or /128).
pub fn parse_nets(list: &[String]) -> Vec<IpNet> {
    list.iter()
        .filter_map(|s| {
            if s.contains('/') {
                s.parse::<IpNet>().ok()
            } else {
                match s.parse::<IpAddr>() {
                    Ok(IpAddr::V4(v4)) => format!("{v4}/32").parse::<IpNet>().ok(),
                    Ok(IpAddr::V6(v6)) => format!("{v6}/128").parse::<IpNet>().ok(),
                    Err(_) => None,
                }
            }
        })
        .collect()
}

fn ip_allowed(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

/// Middleware: rejects requests from IPs outside the allowlist (403) and logs
/// every request as `[label] METHOD /path from IP -> status`.
/// An empty allowlist means "allow all".
pub async fn ip_guard(
    State(gs): State<GuardState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if !gs.nets.is_empty() && !ip_allowed(&gs.nets, ip) {
        println!("[{}] {} {} from {} -> 403 ip_not_allowed", gs.label, method, path, ip);
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "application/json")],
            "{\"error\":\"ip_not_allowed\"}",
        )
            .into_response();
    }

    let resp = next.run(req).await;
    println!(
        "[{}] {} {} from {} -> {}",
        gs.label,
        method,
        path,
        ip,
        resp.status().as_u16()
    );
    resp
}
