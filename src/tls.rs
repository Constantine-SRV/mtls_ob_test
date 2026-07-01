//! Builds the rustls ServerConfig for each server:
//!  - server identity: cert+key from memory (embedded at start, uploaded later);
//!  - client verification: WebPkiClientVerifier against our CA + CN allowlist
//!    (mTLS is mandatory).

use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::acl::CnAllowlistVerifier;

/// Build a rustls ServerConfig: given server cert/key present it to clients, and
/// require a client cert chaining to `ca_pem` whose CN is in `allow_cn`.
pub fn build_server_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    ca_pem: &[u8],
    allow_cn: Vec<String>,
    label: &'static str,
) -> Result<Arc<ServerConfig>> {
    // trusted roots for client cert verification
    let cas: Vec<CertificateDer> = CertificateDer::pem_slice_iter(ca_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("CA PEM: {e}"))?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(cas);
    if added == 0 {
        return Err(anyhow!("no valid certificates in CA"));
    }

    let webpki = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow!("build client verifier: {e}"))?;
    let verifier = Arc::new(CnAllowlistVerifier::new(webpki, allow_cn, label));

    let cert_chain: Vec<CertificateDer> = CertificateDer::pem_slice_iter(server_cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("server cert PEM: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(server_key_pem)
        .map_err(|e| anyhow!("server key PEM: {e}"))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow!("server config: {e}"))?;

    Ok(Arc::new(config))
}

/// Same as `build_server_config`, wrapped in an axum-server `RustlsConfig`
/// (holds an ArcSwap, so it can be hot-reloaded later via `reload_from_config`).
pub fn build_rustls(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    ca_pem: &[u8],
    allow_cn: Vec<String>,
    label: &'static str,
) -> Result<RustlsConfig> {
    let cfg = build_server_config(server_cert_pem, server_key_pem, ca_pem, allow_cn, label)?;
    Ok(RustlsConfig::from_config(cfg))
}