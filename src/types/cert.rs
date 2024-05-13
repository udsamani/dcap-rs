use serde::{Serialize, Deserialize};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

use crate::utils::cert::{get_crl_uri, is_cert_revoked};

use super::IntelCollateralV3;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxExtensionTcbLevel {
    pub sgxtcbcomp01svn: u64,
    pub sgxtcbcomp02svn: u64,
    pub sgxtcbcomp03svn: u64,
    pub sgxtcbcomp04svn: u64,
    pub sgxtcbcomp05svn: u64,
    pub sgxtcbcomp06svn: u64,
    pub sgxtcbcomp07svn: u64,
    pub sgxtcbcomp08svn: u64,
    pub sgxtcbcomp09svn: u64,
    pub sgxtcbcomp10svn: u64,
    pub sgxtcbcomp11svn: u64,
    pub sgxtcbcomp12svn: u64,
    pub sgxtcbcomp13svn: u64,
    pub sgxtcbcomp14svn: u64,
    pub sgxtcbcomp15svn: u64,
    pub sgxtcbcomp16svn: u64,
    pub pcesvn: u64,
    pub cpusvn: [u8; 16]
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SgxExtensions {
    pub ppid: [u8; 16],
    pub tcb: SgxExtensionTcbLevel,
    pub pceid: [u8; 2],
    pub fmspc: [u8; 6],
    pub sgx_type: u32,
    pub platform_instance_id: Option<[u8; 16]>,
    pub configuration: Option<PckPlatformConfiguration>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PckPlatformConfiguration {
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

#[derive(Debug)]
pub struct IntelSgxCrls<'a> {
    pub sgx_root_ca_crl: CertificateRevocationList<'a>,
    pub sgx_pck_processor_crl: CertificateRevocationList<'a>,
    pub sgx_pck_platform_crl: CertificateRevocationList<'a>,
}

impl<'a> IntelSgxCrls<'a> {
    pub fn new(sgx_root_ca_crl: CertificateRevocationList<'a>, sgx_pck_processor_crl: CertificateRevocationList<'a>, sgx_pck_platform_crl: CertificateRevocationList<'a>) -> Self {
        Self {
            sgx_root_ca_crl,
            sgx_pck_processor_crl,
            sgx_pck_platform_crl,
        }
    }

    pub fn from_collaterals(collaterals: &'a IntelCollateralV3) -> Self {
        let sgx_root_ca_crl = collaterals.get_sgx_intel_root_ca_crl();
        let sgx_pck_processor_crl = collaterals.get_sgx_pck_processor_crl();
        let sgx_pck_platform_crl = collaterals.get_sgx_pck_platform_crl();

        Self::new(sgx_root_ca_crl, sgx_pck_processor_crl, sgx_pck_platform_crl)
    }

    pub fn is_cert_revoked(&self, cert: &X509Certificate) -> bool {
        let crl = match get_crl_uri(cert) {
            Some(crl_uri) => {
                if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform") {
                    &self.sgx_pck_platform_crl
                } else if crl_uri.contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=processor") {
                    &self.sgx_pck_processor_crl
                } else if crl_uri.contains("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der") {
                    &self.sgx_root_ca_crl
                } else {
                    panic!("Unknown CRL URI: {}", crl_uri);
                }
            },
            None => {
                panic!("No CRL URI found in certificate");
            }
        };

        // check if the cert is revoked given the crl
        is_cert_revoked(cert, crl)
    }
}