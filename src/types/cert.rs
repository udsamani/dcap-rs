use serde::{Serialize, Deserialize};

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