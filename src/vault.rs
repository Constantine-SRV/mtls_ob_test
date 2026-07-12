//! Fetches a certificate bundle from the (SberCA/HashiCorp Vault) HTTP API.
//! The controlling server passes the Vault token, namespace, URL and request body;
//! the agent performs the POST itself and never logs the token.

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// One issued bundle as returned by Vault: leaf cert, private key, and (optionally)
/// the root CA from the response.
pub struct VaultCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub root_pem: Option<Vec<u8>>,
}

/// POST to `url` with Vault headers and `body` (passed through verbatim), then
/// pull `data.certificate`, `data.private_key`, `data.root_cert` out of the reply.
/// `insecure = true` skips verification of Vault's own TLS cert (demo convenience).
pub async fn fetch(
    url: &str,
    token: &str,
    namespace: &str,
    body: &Value,
    insecure: bool,
) -> Result<VaultCert> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()
        .context("build http client")?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Vault-Namespace", namespace)
        .header("X-Vault-Token", token)
        .json(body)
        .send()
        .await
        .context("vault request failed")?;

    let status = resp.status();
    let v: Value = resp.json().await.context("vault response is not JSON")?;
    if !status.is_success() {
        let err = v.get("errors").cloned().unwrap_or_else(|| v.clone());
        bail!("vault returned {status}: {err}");
    }

    let d = v.get("data").context("vault response has no 'data'")?;
    let cert = d
        .get("certificate")
        .and_then(|x| x.as_str())
        .context("vault response has no 'certificate'")?
        .as_bytes()
        .to_vec();
    let key = d
        .get("private_key")
        .and_then(|x| x.as_str())
        .context("vault response has no 'private_key'")?
        .as_bytes()
        .to_vec();
    let root = d
        .get("root_cert")
        .and_then(|x| x.as_str())
        .map(|s| s.as_bytes().to_vec());

    Ok(VaultCert { cert_pem: cert, key_pem: key, root_pem: root })
}
