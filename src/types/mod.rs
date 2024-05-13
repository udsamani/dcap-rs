use core::panic;

use serde::{Serialize, Deserialize};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

use crate::utils::cert::{parse_crl_der, parse_x509_der, parse_x509_der_multi, pem_to_der};

use self::{enclave_identity::EnclaveIdentityV2, tcbinfo::TcbInfoV2};

pub mod quote;
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

#[derive(Clone, Debug)]
pub struct IntelCollateralV3 {
    pub tcbinfov2: Option<Vec<u8>>,
    pub qeidentityv2: Option<Vec<u8>>,
    pub sgx_intel_root_ca_der: Option<Vec<u8>>,
    pub sgx_tcb_signing_der: Option<Vec<u8>>,
    pub sgx_pck_certchain_der: Option<Vec<u8>>,
    pub sgx_intel_root_ca_crl_der: Option<Vec<u8>>,
    pub sgx_pck_processor_crl_der: Option<Vec<u8>>,
    pub sgx_pck_platform_crl_der: Option<Vec<u8>>,
}

// builder pattern for IntelCollateralV3
impl IntelCollateralV3 {
    pub fn new() -> IntelCollateralV3 {
        IntelCollateralV3 {
            tcbinfov2: None,
            qeidentityv2: None,
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

        let tcbinfov2_bytes = match self.tcbinfov2 {
            Some(ref tcbinfov2) => tcbinfov2.as_slice(),
            None => &[],
        };

        let qeidentityv2_bytes = match self.qeidentityv2 {
            Some(ref qeidentityv2) => qeidentityv2.as_slice(),
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
        let total_length = 4 * 8 + tcbinfov2_bytes.len() + qeidentityv2_bytes.len() + sgx_intel_root_ca_der_bytes.len() + sgx_tcb_signing_der_bytes.len() + sgx_pck_certchain_der_bytes.len() + sgx_intel_root_ca_crl_der_bytes.len() + sgx_pck_processor_crl_der_bytes.len() + sgx_pck_platform_crl_der_bytes.len();

        // create the vec and copy the data
        let mut data = Vec::with_capacity(total_length);
        data.extend_from_slice(&(tcbinfov2_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(qeidentityv2_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_intel_root_ca_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_tcb_signing_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_pck_certchain_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_intel_root_ca_crl_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_pck_processor_crl_der_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&(sgx_pck_platform_crl_der_bytes.len() as u32).to_le_bytes());

        data.extend_from_slice(&tcbinfov2_bytes);
        data.extend_from_slice(&qeidentityv2_bytes);
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
        let tcbinfov2_len = u32::from_le_bytes(slice[0..4].try_into().unwrap()) as usize;
        let qeidentityv2_len = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize;
        let sgx_intel_root_ca_der_len = u32::from_le_bytes(slice[8..12].try_into().unwrap()) as usize;
        let sgx_tcb_signing_der_len = u32::from_le_bytes(slice[12..16].try_into().unwrap()) as usize;
        let sgx_pck_certchain_der_len = u32::from_le_bytes(slice[16..20].try_into().unwrap()) as usize;
        let sgx_intel_root_ca_crl_der_len = u32::from_le_bytes(slice[20..24].try_into().unwrap()) as usize;
        let sgx_pck_processor_crl_der_len = u32::from_le_bytes(slice[24..28].try_into().unwrap()) as usize;
        let sgx_pck_platform_crl_der_len = u32::from_le_bytes(slice[28..32].try_into().unwrap()) as usize;

        let mut offset = 4 * 8 as usize;
        let tcbinfov2: Option<Vec<u8>> = match tcbinfov2_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += tcbinfov2_len;

        let qeidentityv2: Option<Vec<u8>> = match qeidentityv2_len {
            0 => None,
            len => Some(slice[offset..offset + len].to_vec())
        };
        offset += qeidentityv2_len;

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

        IntelCollateralV3 {
            tcbinfov2,
            qeidentityv2,
            sgx_intel_root_ca_der,
            sgx_tcb_signing_der,
            sgx_pck_certchain_der,
            sgx_intel_root_ca_crl_der,
            sgx_pck_processor_crl_der,
            sgx_pck_platform_crl_der,
        }
    }

    pub fn get_tcbinfov2(&self) -> TcbInfoV2 {
        match &self.tcbinfov2 {
            Some(tcbinfov2) => {
                let tcbinfo = serde_json::from_slice(tcbinfov2).unwrap();
                tcbinfo
            },
            None => panic!("TCB Info V2 not set"),
        }
    }

    pub fn set_tcbinfov2(&mut self, tcbinfov2_slice: &[u8]) {
        self.tcbinfov2 = Some(tcbinfov2_slice.to_vec());
    }

    pub fn get_qeidentityv2(&self) -> EnclaveIdentityV2 {
        match &self.qeidentityv2 {
            Some(qeidentityv2) => {
                let qeidentity = serde_json::from_slice(qeidentityv2).unwrap();
                qeidentity
            },
            None => panic!("QE Identity V2 not set"),
        }
    }

    pub fn set_qeidentityv2(&mut self, qeidentityv2_slice: &[u8]) {
        self.qeidentityv2 = Some(qeidentityv2_slice.to_vec());
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

    pub fn get_sgx_intel_root_ca_crl<'a>(&'a self) -> CertificateRevocationList<'a> {
        match &self.sgx_intel_root_ca_crl_der {
            Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                crl
            },
            None => panic!("SGX Intel Root CA CRL not set"),
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

    pub fn get_sgx_pck_processor_crl<'a>(&'a self) -> CertificateRevocationList<'a> {
        match &self.sgx_pck_processor_crl_der {
            Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                crl
            },
            None => panic!("SGX PCK Processor CRL not set"),
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

    pub fn get_sgx_pck_platform_crl<'a>(&'a self) -> CertificateRevocationList<'a> {
        match &self.sgx_pck_platform_crl_der {
            Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                crl
            },
            None => panic!("SGX PCK Platform CRL not set"),
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
// [tcb_status] [mr_enclave] [mr_signer] [report_data]
// [ 1 byte   ] [32 bytes  ] [32 bytes ] [64 bytes   ]
// total: 129 bytes
#[derive(Clone, Debug)]
pub struct VerifiedOutput {
    pub tcb_status: TcbStatus,
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub report_data: [u8; 64],
    pub fmspc: [u8; 6],
}

impl VerifiedOutput {
    pub fn to_bytes(self) -> [u8; 135] {
        let mut raw_bytes = [0; 135];
        raw_bytes[0] = match self.tcb_status {
            TcbStatus::OK => 0,
            TcbStatus::TcbSwHardeningNeeded => 1,
            TcbStatus::TcbConfigurationAndSwHardeningNeeded => 2,
            TcbStatus::TcbConfigurationNeeded => 3,
            TcbStatus::TcbOutOfDate => 4,
            TcbStatus::TcbOutOfDateConfigurationNeeded => 5,
            TcbStatus::TcbRevoked => 6,
            TcbStatus::TcbUnrecognized => 7,
        };
        raw_bytes[1..33].copy_from_slice(&self.mr_enclave);
        raw_bytes[33..65].copy_from_slice(&self.mr_signer);
        raw_bytes[65..129].copy_from_slice(&self.report_data);
        raw_bytes[129..135].copy_from_slice(&self.fmspc);

        raw_bytes
    }

    pub fn from_bytes(slice: &[u8]) -> VerifiedOutput {
        let tcb_status = match slice[0] {
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
        let mut mr_enclave = [0; 32];
        mr_enclave.copy_from_slice(&slice[1..33]);
        let mut mr_signer = [0; 32];
        mr_signer.copy_from_slice(&slice[33..65]);
        let mut report_data= [0; 64];
        report_data.copy_from_slice(&slice[65..129]);
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[129..135]);

        VerifiedOutput {
            tcb_status,
            mr_enclave,
            mr_signer,
            report_data,
            fmspc,
        }
    }
    
}
