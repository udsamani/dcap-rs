use serde::{Deserialize, Serialize};

pub enum TcbInfo {
    V2(TcbInfoV2),
    V3(TcbInfoV3)
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2 {
    pub tcb_info: TcbInfoV2Inner,
    pub signature: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2Inner {
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u64,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TcbInfoV2TcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2TcbLevelItem {
    pub tcb: TcbInfoV2TcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2TcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3 {
    pub tcb_info: TcbInfoV3Inner,
    pub signature: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3Inner {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u64,
    pub tcb_evaluation_data_number: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentities>>,
    pub tcb_levels: Vec<TcbInfoVgTcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    pub mrsigner: String,                   // Base 16-encoded string representation of the measurement of a TDX SEAM module’s signer.
    pub attributes: String,                 // Hex-encoded byte array (8 bytes) representing attributes "golden" value.
    pub attributes_mask: String,            // Hex-encoded byte array (8 bytes) representing mask to be applied to TDX SEAM module’s
                                            // attributes value retrieved from the platform
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentities {
    pub id: String,                         // Identifier of TDX Module
    pub mrsigner: String,                   // Base 16-encoded string representation of the measurement of a TDX SEAM module’s signer.
    pub attributes: String,                 // Base 16-encoded string representation of the byte array (8 bytes) representing attributes "golden" value.
    pub attributes_mask: String,            // Base 16-encoded string representation of the byte array (8 bytes) representing mask to be applied to TDX SEAM module’s
                                            // attributes value retrieved from the platform
    pub tcb_levels: Vec<TdxModuleIdentitiesTcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentitiesTcbLevelItem {
    pub tcb: TdxModuleIdentitiesTcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,

}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentitiesTcbLevel {
    pub isvsvn: u8,                        // TDX SEAM module’s ISV SVN
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3TcbLevelItem {
    pub tcb: TcbInfoV3TcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3TcbLevel {
    pub sgxtcbcomponents: Vec<TcbComponent>,
    pub pcesvn: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdxtcbcomponents: Option<Vec<TcbComponent>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbComponent {
    pub svn: u8,                                                   // SVN of TCB Component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,                                   // Category of TCB Component (e.g. BIOS, OS/VMM).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: Option<String>,                                      // Type of TCB Component (e.g. SGX Late Microcode Update, TXT SINIT).
}
