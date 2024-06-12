use core::panic;

use serde::{Serialize, Deserialize};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

use crate::utils::cert::{parse_crl_der, parse_x509_der, parse_x509_der_multi, pem_to_der};
use crate::constants::{ENCLAVE_REPORT_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN};

use self::enclave_identity::EnclaveIdentityV2;
use self::tcbinfo::{TcbInfoV2, TcbInfoV3};
use self::quotes::body::*;

pub mod quotes;
pub mod tcbinfo;
pub mod enclave_identity;
pub mod cert;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TcbStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized
}

impl TcbStatus {
    pub fn from_str(s: &str) -> Self {
        return match s {
            "UpToDate" => TcbStatus::OK,
            "SWHardeningNeeded" => TcbStatus::TcbSwHardeningNeeded,
            "ConfigurationAndSWHardeningNeeded" => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
            "ConfigurationNeeded" => TcbStatus::TcbConfigurationNeeded,
            "OutOfDate" => TcbStatus::TcbOutOfDate,
            "OutOfDateConfigurationNeeded" => TcbStatus::TcbOutOfDateConfigurationNeeded,
            "Revoked" => TcbStatus::TcbRevoked,
            _ => TcbStatus::TcbUnrecognized,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IntelCollateral {
    pub tcbinfo_bytes: Option<Vec<u8>>,
    pub qeidentity_bytes: Option<Vec<u8>>,
    pub sgx_intel_root_ca_der: Option<Vec<u8>>,
    pub sgx_tcb_signing_der: Option<Vec<u8>>,
    pub sgx_pck_certchain_der: Option<Vec<u8>>,
    pub sgx_intel_root_ca_crl_der: Option<Vec<u8>>,
    pub sgx_pck_processor_crl_der: Option<Vec<u8>>,
    pub sgx_pck_platform_crl_der: Option<Vec<u8>>,
}

// builder pattern for IntelCollateralV3
impl IntelCollateral {
    pub fn new() -> IntelCollateral {
        IntelCollateral {
            tcbinfo_bytes: None,
            qeidentity_bytes: None,
            sgx_intel_root_ca_der: None,
            sgx_tcb_signing_der: None,
            sgx_pck_certchain_der: None,
            sgx_intel_root_ca_crl_der: None,
            sgx_pck_processor_crl_der: None,
            sgx_pck_platform_crl_der: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // serialization scheme is simple: the bytestream is made of 2 parts 
        // the first contains a u32 length for each of the members
        // the second contains the actual data
        // [lengths of each of the member][data segment]

        let tcbinfo_bytes = match self.tcbinfo_bytes {
            Some(ref tcbinfo) => tcbinfo.as_slice(),
            None => &[],
        };

        let qeidentity_bytes = match self.qeidentity_bytes {
            Some(ref qeidentity) => qeidentity.as_slice(),
            None => &[],
        };

        let sgx_intel_root_ca_der_bytes = match &self.sgx_intel_root_ca_der {
            Some(der) => der.as_slice(),
            None => &[],
        };

        let sgx_tcb_signing_der_bytes = match &self.sgx_tcb_signing_der {
            Some(der) => der.as_slice(),
            None => &[],
        };

        let sgx_pck_certchain_der_bytes = match &self.sgx_pck_certchain_der {
            Some(der) => der.as_slice(),
            None => &[],
        };

        let sgx_intel_root_ca_crl_der_bytes = match &self.sgx_intel_root_ca_crl_der {
            Some(der) => der.as_slice(),
            None => &[],
        };

        let sgx_pck_processor_crl_der_bytes = match &self.sgx_pck_processor_crl_der {
            Some(der) => der.as_slice(),
            None => &[],
        };

        let sgx_pck_platform_crl_der_bytes = match &self.sgx_pck_platform_crl_der {
            Some(der) => der.as_slice(),
            None => &[],
        };

        // get the total length
        let total_length = 4 * 8 + tcbinfo_bytes.len() + qeidentity_bytes.len() + sgx_intel_root_ca_der_bytes.len() + sgx_tcb_signing_der_bytes.len() + sgx_pck_certchain_der_bytes.len() + sgx_intel_root_ca_crl_der_bytes.len() + sgx_pck_processor_crl_der_bytes.len() + sgx_pck_platform_crl_der_bytes.len();

        // create the vec and copy the data
        let mut data = Vec::with_capacity(total_length);
        data.extend_from_slice(&(tcbinfo_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(qeidentity_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_intel_root_ca_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_tcb_signing_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_pck_certchain_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_intel_root_ca_crl_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_pck_processor_crl_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_pck_platform_crl_der_bytes.len() as u32).to_le_bytes());

        data.extend_from_slice(&tcbinfo_bytes);
        data.extend_from_slice(&qeidentity_bytes);
        data.extend_from_slice(&sgx_intel_root_ca_der_bytes);
        data.extend_from_slice(&sgx_tcb_signing_der_bytes);
        data.extend_from_slice(&sgx_pck_certchain_der_bytes);
        data.extend_from_slice(&sgx_intel_root_ca_crl_der_bytes);
        data.extend_from_slice(&sgx_pck_processor_crl_der_bytes);
        data.extend_from_slice(&sgx_pck_platform_crl_der_bytes);

        data
    }

    pub fn from_bytes(slice: &[u8]) -> Self {
        // reverse the serialization process
        // each length is 4 bytes long, we have a total of 8 members
        let tcbinfo_bytes_len = u32::from_le_bytes(slice[0..4].try_into().unwrap()) as usize;
        let qeidentity_bytes_len = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize;
        let sgx_intel_root_ca_der_len = u32::from_le_bytes(slice[8..12].try_into().unwrap()) as usize;
        let sgx_tcb_signing_der_len = u32::from_le_bytes(slice[12..16].try_into().unwrap()) as usize;
        let sgx_pck_certchain_der_len = u32::from_le_bytes(slice[16..20].try_into().unwrap()) as usize;
        let sgx_intel_root_ca_crl_der_len = u32::from_le_bytes(slice[20..24].try_into().unwrap()) as usize;
        let sgx_pck_processor_crl_der_len = u32::from_le_bytes(slice[24..28].try_into().unwrap()) as usize;
        let sgx_pck_platform_crl_der_len = u32::from_le_bytes(slice[28..32].try_into().unwrap()) as usize;

        let mut offset = 4 * 8 as usize;
        let tcbinfo_bytes: Option<Vec<u8>> = match tcbinfo_bytes_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += tcbinfo_bytes_len;

        let qeidentity_bytes: Option<Vec<u8>> = match qeidentity_bytes_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += qeidentity_bytes_len;

        let sgx_intel_root_ca_der: Option<Vec<u8>> = match sgx_intel_root_ca_der_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += sgx_intel_root_ca_der_len;

        let sgx_tcb_signing_der: Option<Vec<u8>> = match sgx_tcb_signing_der_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += sgx_tcb_signing_der_len;

        let sgx_pck_certchain_der: Option<Vec<u8>> = match sgx_pck_certchain_der_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += sgx_pck_certchain_der_len;

        let sgx_intel_root_ca_crl_der: Option<Vec<u8>> = match sgx_intel_root_ca_crl_der_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += sgx_intel_root_ca_crl_der_len;

        let sgx_pck_processor_crl_der: Option<Vec<u8>> = match sgx_pck_processor_crl_der_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += sgx_pck_processor_crl_der_len;

        let sgx_pck_platform_crl_der: Option<Vec<u8>> = match sgx_pck_platform_crl_der_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += sgx_pck_platform_crl_der_len;

        assert!(offset == slice.len());

        IntelCollateral {
            tcbinfo_bytes: tcbinfo_bytes,
            qeidentity_bytes: qeidentity_bytes,
            sgx_intel_root_ca_der,
            sgx_tcb_signing_der,
            sgx_pck_certchain_der,
            sgx_intel_root_ca_crl_der,
            sgx_pck_processor_crl_der,
            sgx_pck_platform_crl_der,
        }
    }

    pub fn get_tcbinfov2(&self) -> TcbInfoV2 {
        match &self.tcbinfo_bytes {
            Some(tcbinfov2) => {
                let tcbinfo: TcbInfoV2 = serde_json::from_slice(tcbinfov2).unwrap();
                assert_eq!(tcbinfo.tcb_info.version, 2);
                tcbinfo
            },
            None => panic!("TCB Info V2 not set"),
        }
    }

    pub fn get_tcbinfov3(&self) -> TcbInfoV3 {
        match &self.tcbinfo_bytes {
            Some(tcbinfov3) => {
                let tcbinfo: TcbInfoV3 = serde_json::from_slice(tcbinfov3).unwrap();
                assert_eq!(tcbinfo.tcb_info.version, 3);
                tcbinfo
            },
            None => panic!("TCB Info V3 not set"),
        }
    }

    pub fn set_tcbinfo_bytes(&mut self, tcbinfo_slice: &[u8]) {
        self.tcbinfo_bytes = Some(tcbinfo_slice.to_vec());
    }

    pub fn get_qeidentityv2(&self) -> EnclaveIdentityV2 {
        match &self.qeidentity_bytes {
            Some(qeidentityv2) => {
                let qeidentity = serde_json::from_slice(qeidentityv2).unwrap();
                qeidentity
            },
            None => panic!("QE Identity V2 not set"),
        }
    }

    pub fn set_qeidentity_bytes(&mut self, qeidentity_slice: &[u8]) {
        self.qeidentity_bytes = Some(qeidentity_slice.to_vec());
    }

    pub fn get_sgx_intel_root_ca<'a>(&'a self) -> X509Certificate<'a> {
        match self.sgx_intel_root_ca_der {
            Some(ref der) => {
                let cert = parse_x509_der(der);
                cert
            },
            None => panic!("Intel Root CA not set"),
        }
    }

    pub fn set_intel_root_ca_der(&mut self, intel_root_ca_der: &[u8]) {
        self.sgx_intel_root_ca_der = Some(intel_root_ca_der.to_vec());
    }

    pub fn get_sgx_tcb_signing<'a>(&'a self) -> X509Certificate<'a> {
        match self.sgx_tcb_signing_der {
            Some(ref der) => {
                let cert = parse_x509_der(der);
                cert
            },
            None => panic!("SGX TCB Signing Cert not set"),
        }
    }

    pub fn set_sgx_tcb_signing_der(&mut self, sgx_tcb_signing_der: &[u8]) {
        self.sgx_tcb_signing_der = Some(sgx_tcb_signing_der.to_vec());
    }

    pub fn set_sgx_tcb_signing_pem(&mut self, sgx_tcb_signing_pem: &[u8]) {
        // convert pem to der
        let sgx_tcb_signing_der = pem_to_der(sgx_tcb_signing_pem);
        self.sgx_tcb_signing_der = Some(sgx_tcb_signing_der);
    }

    pub fn get_sgx_pck_certchain<'a>(&'a self) -> Option<Vec<X509Certificate<'a>>> {
        match &self.sgx_pck_certchain_der {
            Some(certchain_der) => {
                let certchain = parse_x509_der_multi(certchain_der);
                Some(certchain)
            },
            None => None,
        }
    }

    pub fn set_sgx_pck_certchain_der(&mut self, sgx_pck_certchain_der: Option<&[u8]>) {
        match sgx_pck_certchain_der {
            Some(certchain_der) => {
                self.sgx_pck_certchain_der = Some(certchain_der.to_vec());
            },
            None => {
                self.sgx_pck_certchain_der = None;
            },
        }
    }

    pub fn set_sgx_pck_certchain_pem(&mut self, sgx_pck_certchain_pem: Option<&[u8]>) {
        match sgx_pck_certchain_pem {
            Some(certchain_pem) => {
                // convert pem to der
                let sgx_pck_certchain_der = pem_to_der(certchain_pem);
                self.sgx_pck_certchain_der = Some(sgx_pck_certchain_der);
            },
            None => {
                self.sgx_pck_certchain_der = None;
            },
        }
    }

    pub fn get_sgx_intel_root_ca_crl<'a>(&'a self) -> Option<CertificateRevocationList<'a>> {
        match &self.sgx_intel_root_ca_crl_der {
            Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                Some(crl)
            },
            None => None,
        }
    }

    pub fn set_sgx_intel_root_ca_crl_der(&mut self, sgx_intel_root_ca_crl_der: &[u8]) {
        self.sgx_intel_root_ca_crl_der = Some(sgx_intel_root_ca_crl_der.to_vec());
    }

    pub fn set_sgx_intel_root_ca_crl_pem(&mut self, sgx_intel_root_ca_crl_pem: &[u8]) {
        // convert pem to der
        let sgx_intel_root_ca_crl_der = pem_to_der(sgx_intel_root_ca_crl_pem);
        self.sgx_intel_root_ca_crl_der = Some(sgx_intel_root_ca_crl_der);
    }

    pub fn get_sgx_pck_processor_crl<'a>(&'a self) -> Option<CertificateRevocationList<'a>> {
        match &self.sgx_pck_processor_crl_der {
            Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                Some(crl)
            },
            None => None,
        }
    }

    pub fn set_sgx_processor_crl_der(&mut self, sgx_pck_processor_crl_der: &[u8]) {
        self.sgx_pck_processor_crl_der = Some(sgx_pck_processor_crl_der.to_vec());
    }

    pub fn set_sgx_processor_crl_der_pem(&mut self, sgx_pck_processor_crl_pem: &[u8]) {
        // convert pem to der
        let sgx_pck_processor_crl_der = pem_to_der(sgx_pck_processor_crl_pem);
        self.sgx_pck_processor_crl_der = Some(sgx_pck_processor_crl_der);
    }

    pub fn get_sgx_pck_platform_crl<'a>(&'a self) -> Option<CertificateRevocationList<'a>> {
        match &self.sgx_pck_platform_crl_der {
            Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                Some(crl)
            },
            None => None, 
        }
    }

    pub fn set_sgx_platform_crl_der(&mut self, sgx_pck_platform_crl_der: &[u8]) {
        self.sgx_pck_platform_crl_der = Some(sgx_pck_platform_crl_der.to_vec());
    }

    pub fn set_sgx_platform_crl_der_pem(&mut self, sgx_pck_platform_crl_pem: &[u8]) {
        // convert pem to der
        let sgx_pck_platform_crl_der = pem_to_der(sgx_pck_platform_crl_pem);
        self.sgx_pck_platform_crl_der = Some(sgx_pck_platform_crl_der);
    }
}

// serialization:
// [quote_vesion][tee_type][tcb_status][fmspc][quote_body_raw_bytes]
// 2 bytes + 4 bytes + 1 byte + 6 bytes + var (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584)
// total: 13 + var bytes
#[derive(Debug)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: TcbStatus,
    pub fmspc: [u8; 6],
    pub quote_body: QuoteBody
}

impl VerifiedOutput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_length: usize;
        // this comparison is wrong and needs to be fixed once we begin supporting v5 quotes
        if self.tee_type == SGX_TEE_TYPE {
            total_length = 13 + ENCLAVE_REPORT_LEN;
        } else {
            total_length = 13 + TD10_REPORT_LEN;
        }

        let mut output_vec = Vec::with_capacity(total_length);

        output_vec.extend_from_slice(&self.quote_version.to_be_bytes());
        output_vec.extend_from_slice(&self.tee_type.to_be_bytes());
        output_vec.push(match self.tcb_status {
            TcbStatus::OK => 0,
            TcbStatus::TcbSwHardeningNeeded => 1,
            TcbStatus::TcbConfigurationAndSwHardeningNeeded => 2,
            TcbStatus::TcbConfigurationNeeded => 3,
            TcbStatus::TcbOutOfDate => 4,
            TcbStatus::TcbOutOfDateConfigurationNeeded => 5,
            TcbStatus::TcbRevoked => 6,
            TcbStatus::TcbUnrecognized => 7,
        });
        output_vec.extend_from_slice(&self.fmspc);
        
        match self.quote_body {
            QuoteBody::SGXQuoteBody(body) => {
                output_vec.extend_from_slice(&body.to_bytes());
            },
            QuoteBody::TD10QuoteBody(body) => {
                output_vec.extend_from_slice(&body.to_bytes());
            }
        }

        output_vec
    }

    pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
        let mut quote_version = [0; 2];
        quote_version.copy_from_slice(&slice[0..2]);
        let mut tee_type = [0; 4];
        tee_type.copy_from_slice(&slice[2..6]);
        let tcb_status = match slice[6] {
            0 => TcbStatus::OK,
            1 => TcbStatus::TcbSwHardeningNeeded,
            2 => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
            3 => TcbStatus::TcbConfigurationNeeded,
            4 => TcbStatus::TcbOutOfDate,
            5 => TcbStatus::TcbOutOfDateConfigurationNeeded,
            6 => TcbStatus::TcbRevoked,
            7 => TcbStatus::TcbUnrecognized,
            _ => panic!("Invalid TCB Status"),
        };
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[7..13]);
        let mut raw_quote_body = Vec::new();
        raw_quote_body.extend_from_slice(&slice[13..]);

        let quote_body = match raw_quote_body.len() {
            ENCLAVE_REPORT_LEN => {
                QuoteBody::SGXQuoteBody(EnclaveReport::from_bytes(&raw_quote_body))
            },
            TD10_REPORT_LEN => {
                QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(&raw_quote_body))
            },
            _ => {
                panic!("Invalid quote body")
            }
        };

        VerifiedOutput {
            quote_version: u16::from_be_bytes(quote_version),
            tee_type: u32::from_be_bytes(tee_type),
            tcb_status,
            fmspc,
            quote_body
        }
    }
    
}
