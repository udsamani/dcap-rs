use serde::{Deserialize, Serialize};

pub mod quote;
pub mod tcbinfo;
pub mod qve_identity;

use tcbinfo::{SgxExtensionTcbLevel, TcbStatus};

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
