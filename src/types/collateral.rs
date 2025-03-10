use x509_cert::{crl::CertificateList, Certificate};
use crate::utils::{cert_chain, crl};
use serde::{Serialize, Deserialize};

use super::{enclave_identity::QuotingEnclaveIdentityAndSignature, tcb_info::TcbInfoAndSignature};


#[derive(Debug, Serialize, Deserialize)]
pub struct Collateral {

    /* Certificate Revocation List */

    /// Root CA CRL in PEM format
    /// Contains a list of revoked certificates signed by Intel SGX Root CA.
    /// It is used to check if any certificates in the verification chain have been revoked.
    #[serde(with = "crl")]
    pub root_ca_crl: CertificateList,

    /// PCK (Provisioning Certificate Key) CRL in PEM format
    /// Contains a list of revoked PCK Certificates.
    /// It is used to check if platform's attestation key has been revoked.
    #[serde(with = "crl")]
    pub pck_crl: CertificateList,

    /* Issuer Certificate Chains */

    /// TCB Info Issuer Chain in PEM format
    /// Chain of certificates used to verify TCB Info signature.
    #[serde(with = "cert_chain")]
    pub tcb_info_issuer_chain: Vec<Certificate>,

    /// PCK CRL Issuer Chain in PEM format
    /// Chain of certificates used to verify PCK CR Signatures
    #[serde(with = "cert_chain")]
    pub pck_crl_issuer_chain: Vec<Certificate>,

    /// Identity Issuer Chain in PEM format
    /// Chain of certificates used to verify QE Identity signature.
    #[serde(with = "cert_chain")]
    pub qe_identity_issuer_chain: Vec<Certificate>,


    /* Structured Data */

    /// TCB Info Structure
    /// Contains security version information and TCB levels.
    pub tcb_info: TcbInfoAndSignature,

    /// QE Identity Structure
    /// Contains Quoting Enclave identity information.
    pub qe_identity: QuotingEnclaveIdentityAndSignature,
}

#[cfg(test)]
mod tests {
    use super::Collateral;

    #[test]
    fn encode_decode_collateral_json() {
        let json = include_str!("../../data/full_collateral.json");
        let collateral: Collateral = serde_json::from_str(json).expect("json to parse");
        let json2 = serde_json::to_string(&collateral).expect("json to serialize");
        println!("{json2}");
        let _: Collateral = serde_json::from_str(&json2).expect("json2 to parse");
    }
}
