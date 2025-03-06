pub mod hash;
pub mod cert;
pub mod crypto;
pub mod tcbinfo;
pub mod quotes;
pub mod tdx_module;



/// A module for serializing and deserializing certificate chains.
pub mod cert_chain {
    use x509_cert::{certificate::CertificateInner, Certificate, der::EncodePem};
    use serde::{de, ser, Deserialize};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<CertificateInner>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        Certificate::load_pem_chain(s.as_bytes()).map_err(de::Error::custom)
    }

    pub fn serialize<S>(certs: &Vec<CertificateInner>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut string = String::new();
        for cert in certs {
            string.push_str(
                &cert.to_pem(p256::pkcs8::LineEnding::LF).map_err(ser::Error::custom)?,
            );
        }
        serializer.serialize_str(&string)
    }
}


/// A module for serializing and deserializing CRLs.
pub mod crl {
    use std::str::FromStr;

    use pem::Pem;
    use serde::{de, ser, Deserialize, Deserializer, Serializer};
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{Decode, Encode};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CertificateList, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let pem = Pem::from_str(&s).map_err(de::Error::custom)?;
        CertificateList::from_der(pem.contents()).map_err(de::Error::custom)
    }
    pub fn serialize<S: Serializer>(
        value: &CertificateList,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pem = Pem::new("X509 CRL", value.to_der().map_err(ser::Error::custom)?);
        serializer.serialize_str(&pem.to_string())
    }
}


pub mod u32_hex {
    use serde::Serializer;
    use zerocopy::AsBytes;

    use crate::types::UInt32LE;

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<UInt32LE, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: [u8; 4] = hex::deserialize(deserializer)?;
        Ok(value.into())
    }
    pub fn serialize<S: Serializer>(value: &UInt32LE, serializer: S) -> Result<S::Ok, S::Error> {
        hex::serialize(value.as_bytes(), serializer)
    }
}
