use serde::{Deserialize, Serialize};

// TcbInfoV2:
//     type: object
//     description: >-
//         SGX TCB Info encoded as JSON string in case of success (200 HTTP
//         status code)
//     properties:
//         tcbInfo:
//             type: object
//             properties:
//                 version:
//                     type: integer
//                     example: 2
//                     description: Version of the structure
//                 issueDate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time the TCB information
//                         was created. The time shall be in UTC and the
//                         encoding shall be compliant to ISO 8601 standard
//                         (YYYY-MM-DDThh:mm:ssZ)
//                 nextUpdate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time by which next TCB
//                         information will be issued. The time shall be in UTC
//                         and the encoding shall be compliant to ISO 8601
//                         standard (YYYY-MM-DDThh:mm:ssZ)
//                 fmspc:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{12}$
//                     example: '000000000000'
//                     description: >-
//                         Base 16-encoded string representation of FMSPC
//                         (Family-Model-Stepping-Platform-CustomSKU)
//                 pceId:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{4}$
//                     example: '0000'
//                     description: Base 16-encoded string representation of PCE identifier
//                 tcbType:
//                     type: integer
//                     example: 0
//                     description: >-
//                         Type of TCB level composition that determines TCB
//                         level comparison logic
//                 tcbEvaluationDataNumber:
//                     type: integer
//                     example: 2
//                     description: >-
//                         A monotonically increasing sequence number changed
//                         when Intel updates the content of the TCB evaluation data
//                         set: TCB Info, QE Idenity and QVE Identity. The tcbEvaluationDataNumber
//                         update is synchronized across TCB Info for all flavors of
//                         SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE
//                         Identity. This sequence number allows users to easily determine
//                         when a particular TCB Info/QE Idenity/QVE Identiy superseedes
//                         another TCB Info/QE Identity/QVE Identity (value: current
//                         TCB Recovery event number stored in the database).
//                 tcbLevels:
//                     type: array
//                     description: >-
//                         Sorted list of supported TCB levels for given FMSPC
//                         encoded as a JSON array of TCB level objects
//                     items:
//                         type: object
//                         properties:
//                             tcb:
//                                 type: object
//                                 properties:
//                                     pcesvn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 65535
//                                     sgxtcbcomp01svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp02svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp03svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp04svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp05svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp06svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp07svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp08svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp09svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp10svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp11svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp12svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp13svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp14svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp15svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                                     sgxtcbcomp16svn:
//                                         type: integer
//                                         example: 0
//                                         minimum: 0
//                                         maximum: 255
//                             tcbDate:
//                                 type: string
//                                 format: date-time
//                                 description: >-
//                                     If there are security advisories published by Intel after tcbDate
//                                     that are for issues whose mitigations are currently enforced* by SGX attestation,
//                                     then the value of tcbStatus for the TCB level will not be UpToDate.
//                                     Otherwise (i.e., either no advisories after or not currently enforced),
//                                     the value of tcbStatus for the TCB level will not be OutOfDate.
// 
//                                     The time shall be in UTC and the encoding shall
//                                     be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
//                             tcbStatus:
//                                 type: string
//                                 enum:
//                                     - UpToDate
//                                     - SWHardeningNeeded
//                                     - ConfigurationNeeded
//                                     - ConfigurationAndSWHardeningNeeded
//                                     - OutOfDate
//                                     - OutOfDateConfigurationNeeded
//                                     - Revoked
//                                 description: >-
//                                     TCB level status. One of the following values:
// 
//                                     "UpToDate" - TCB level of the SGX platform is up-to-date.
// 
//                                     "SWHardeningNeeded" - TCB level of the SGX platform
//                                     is up-to-date but due to certain issues affecting the
//                                     platform, additional SW Hardening in the attesting
//                                     SGX enclaves may be needed.
// 
//                                     "ConfigurationNeeded" - TCB level of the SGX platform
//                                     is up-to-date but additional configuration of SGX
//                                     platform may be needed.
// 
//                                     "ConfigurationAndSWHardeningNeeded" - TCB level of the
//                                     SGX platform is up-to-date but additional configuration
//                                     for the platform and SW Hardening in the attesting SGX
//                                     enclaves may be needed.
// 
//                                     "OutOfDate" - TCB level of SGX platform is outdated.
// 
//                                     "OutOfDateConfigurationNeeded" - TCB level of SGX
//                                     platform is outdated and additional configuration
//                                     of SGX platform may be needed.
// 
//                                     "Revoked" - TCB level of SGX platform is revoked.
//                                     The platform is not trustworthy.
//         signature:
//             type: string
//             description: >-
//                 Base 16-encoded string representation of signature calculated over tcbInfo
//                 body without whitespaces using TCB Signing Key
//                 i.e:
//                 {"version":2,"issueDate":"2019-07-30T12:00:00Z","nextUpdate":"2019-08-30T12:00:00Z",...}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2 {
    pub tcb_info: TcbInfoV2Inner,
    pub signature: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV2Inner {
    pub version: u64,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u64,
    pub tcb_evaluation_data_number: u64,
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
    pub pcesvn: u64,
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
}

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
