//! Идентичность агента для подключения к OceanBase — целиком в памяти.

#[derive(Clone)]
pub struct Identity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}
