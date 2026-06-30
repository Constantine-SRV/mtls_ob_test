//! Идентичность агента для подключения к OceanBase — целиком в памяти.
//! Сейчас наполняется заливкой через POST /cert. Сюда же позже встанет
//! получение из Vault — структура `Identity` останется той же.

#[derive(Clone)]
pub struct Identity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}
