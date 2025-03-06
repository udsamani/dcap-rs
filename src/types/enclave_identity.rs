use chrono::Utc;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use crate::utils::u32_hex;
use super::UInt32LE;
use serde_json::value::RawValue;
use anyhow::Context;

const ENCLAVE_IDENTITY_V2: u16 = 2;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcb {
    pub isvsvn: u16,
}


#[derive(Deserialize, Serialize, Debug)]
pub struct QuotingEnclaveIdentityAndSignature {
    #[serde(rename = "enclaveIdentity")]
    enclave_identity_raw: Box<RawValue>,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}


impl QuotingEnclaveIdentityAndSignature {
    /// Validate the enclave identity and return the enclave identity if it is valid
    /// It checks the signature, the version, and the timestamp.
    /// The enclave identities should have their version set to 2.
    pub fn validate_enclave_identity(
        &self,
        public_key: &VerifyingKey,
        timestamp: chrono::DateTime<Utc>,
    ) -> anyhow::Result<EnclaveIdentity> {

        public_key.verify(
            self.enclave_identity_raw.to_string().as_bytes(),
            &Signature::from_slice(&self.signature)?
        ).context("Failed to verify enclave identity signature")?;

        let enclave_identity: EnclaveIdentity = serde_json::from_str(self.enclave_identity_raw.get())
            .context("Failed to deserialize enclave identity")?;

        if enclave_identity.version != ENCLAVE_IDENTITY_V2 {
            return Err(anyhow::anyhow!("unsupported enclave identity version, only v2 is supported"));
        }

        if timestamp < enclave_identity.issue_date || timestamp > enclave_identity.next_update {
            return Err(anyhow::anyhow!("enclave identity is not valid at this time"));
        }

        Ok(enclave_identity)
    }

}


#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    /// Identifier of the SGX Enclave issued by Intel.
    pub id: EnclaveType,

    /// Version of the structure.
    pub version: u16,

    /// The time the Enclave Identity Information was created. The time shalle be in UTC
    /// and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
    pub issue_date: chrono::DateTime<Utc>,

    /// The time by which next Enclave Identity information will be issued. The time shall be in UTC
    /// and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
    pub next_update: chrono::DateTime<Utc>,

    /// A monotonically increasing sequence number changed when Intel updates the content of the TCB evaluation data set:
    /// TCB Info, QE Identity, QVE Identity. The tcbEvaluationDataNUmber update is synchronized across TCB infor for all
    /// flavours of SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE Identity.
    /// This sequence number allows users to easily determine when a particular TCB Info/QE Identity/QVE Identity
    /// superseedes another TCB Info/QE Identity/QVE Identity (value: current TCB Recovery event number stored in the database).
    _tcb_evaluation_data_number: u16,

    /// Base 16-encoded string representing miscselect "golden" value (upon applying mask).
    #[serde(with = "u32_hex")]
    pub miselect: UInt32LE,

    /// Base 16-encoded string representing mask to be applied to miscselect value retrieved from the platform.
    #[serde(with = "u32_hex")]
    pub miselect_mask: UInt32LE,

    /// Base 16-encoded string representing attributes "golden" value (upon applying mask).
    #[serde(with = "hex")]
    pub attributes: [u8; 16],

    /// Base 16-encoded string representing mask to be applied to attributes value retrieved from the platform.
    #[serde(with = "hex")]
    pub attributes_mask: [u8; 16],

    /// Base 16-encoded string representing mrsigner hash.
    #[serde(with = "hex")]
    pub mrsigner: [u8; 32],

    /// Enclave Product ID.
    pub isvprodid: u16,

    /// Sorted list of supported Enclave TCB levels for given QVE encoded as a JSON array of Enclave TCB level objects.
    pub tcb_levels: Vec<QeTcbLevel>,
}

/// Enclave TCB level
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    /// SGX Enclave's ISV SVN
    tcb: QeTcb,
    /// The time the TCB was evaluated. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDhh:mm:ssZ)
    _tcb_date: chrono::DateTime<Utc>,
    /// TCB level status
    tcb_status: QeTcbStatus,
    #[serde(rename = "advisoryIDs")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
}

/// TCB level status
#[derive(Deserialize, Serialize, Debug)]
pub enum QeTcbStatus {
    /// TCB level of the SGX platform is up-to-date.
    UpToDate,
    /// TCB level of SGX platform is outdated.
    OutOfDate,
    /// TCB level of SGX platform is revoked.
    Revoked,
    /// Unknown TCB level status.
    Unspecified,
}


impl QeTcbStatus {
    pub fn from_str(status: &str) -> Self {
        match status {
            "UpToDate" => QeTcbStatus::UpToDate,
            "OutOfDate" => QeTcbStatus::OutOfDate,
            "Revoked" => QeTcbStatus::Revoked,
            _ => QeTcbStatus::Unspecified,
        }
    }
}



#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EnclaveType {
    /// Quoting Enclave
    Qe,
    /// Quote Verification Enclave
    Qve,
    /// TDX Quoting Enclave
    #[serde(rename = "TD_QE")]
    TdQe,
}
