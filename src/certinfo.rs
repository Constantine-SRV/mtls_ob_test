//! Разбор сертификата: CN + срок действия (для GET /cert/validity и валидации заливки).

use anyhow::{anyhow, Context, Result};

pub struct CertInfo {
    pub cn: String,
    pub not_before: String,
    pub not_after: String,
}

/// Парсит PEM-серт (берёт первый блок = leaf), достаёт CN и срок.
pub fn describe(cert_pem: &[u8]) -> Result<CertInfo> {
    let block = pem::parse(cert_pem).context("не PEM-сертификат")?;
    let der = block.contents();
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow!("разбор X.509: {e:?}"))?;

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("<no CN>")
        .to_string();

    let v = cert.validity();
    Ok(CertInfo {
        cn,
        not_before: v.not_before.to_string(),
        not_after: v.not_after.to_string(),
    })
}
