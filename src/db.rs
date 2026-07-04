//! OceanBase access: mTLS connection pool + queries.

use anyhow::Result;
use mysql_async::prelude::Queryable;
use mysql_async::{ClientIdentity, OptsBuilder, Pool, SslOpts};

use crate::credentials::Identity;

#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

impl Db {
    pub fn connect(id: &Identity, host: &str, port: u16, user: &str) -> Self {
        let ssl = SslOpts::default()
            .with_root_certs(vec![id.ca_pem.clone().into()])
            .with_client_identity(Some(ClientIdentity::new(
                id.cert_pem.clone().into(),
                id.key_pem.clone().into(),
            )));
        let opts = OptsBuilder::default()
            .ip_or_hostname(host.to_string())
            .tcp_port(port)
            .user(Some(user.to_string()))
            .ssl_opts(ssl);
        Db { pool: Pool::new(opts) }
    }

    /// Returns the OceanBase version string.
    pub async fn version(&self) -> Result<String> {
        let mut conn = self.pool.get_conn().await?;
        let v: Option<String> = conn.query_first("SELECT version()").await?;
        Ok(v.unwrap_or_default())
    }
}
