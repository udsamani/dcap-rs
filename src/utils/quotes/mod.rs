pub mod version_3;
pub mod version_4;

use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::types::TcbStatus;
use crate::types::quotes::body::EnclaveReport;
use crate::utils::hash::sha256sum;

fn validate_qe_enclave(enclave_report: &EnclaveReport, qeidentityv2: &EnclaveIdentityV2) -> bool {
    // make sure that the enclave_identityv2 is a qeidentityv2
    // check that id is "QE", "TD_QE" or "QVE" and version is 2
    if !((qeidentityv2.enclave_identity.id == "QE" || qeidentityv2.enclave_identity.id == "TD_QE" || qeidentityv2.enclave_identity.id == "QVE") && qeidentityv2.enclave_identity.version == 2) {
        return false;
    }

    let mrsigner_ok = enclave_report.mrsigner == hex::decode(&qeidentityv2.enclave_identity.mrsigner).unwrap().as_slice();
    let isvprodid_ok = enclave_report.isv_prod_id == qeidentityv2.enclave_identity.isvprodid;

    let attributes = hex::decode(&qeidentityv2.enclave_identity.attributes).unwrap();
    let attributes_mask = hex::decode(&qeidentityv2.enclave_identity.attributes_mask).unwrap();
    let masked_attributes = attributes.iter().zip(attributes_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let masked_enclave_attributes = enclave_report.attributes.iter().zip(attributes_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let enclave_attributes_ok = masked_enclave_attributes == masked_attributes;

    let miscselect = hex::decode(&qeidentityv2.enclave_identity.miscselect).unwrap();
    let miscselect_mask = hex::decode(&qeidentityv2.enclave_identity.miscselect_mask).unwrap();
    let masked_miscselect = miscselect.iter().zip(miscselect_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let masked_enclave_miscselect = enclave_report.misc_select.iter().zip(miscselect_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let enclave_miscselect_ok = masked_enclave_miscselect == masked_miscselect;

    let tcb_status = get_qe_tcbstatus(enclave_report, qeidentityv2);

    mrsigner_ok && isvprodid_ok && enclave_attributes_ok && enclave_miscselect_ok && tcb_status == TcbStatus::OK
}

fn get_qe_tcbstatus(enclave_report: &EnclaveReport, qeidentityv2: &EnclaveIdentityV2) -> TcbStatus {
    for tcb_level in qeidentityv2.enclave_identity.tcb_levels.iter() {
        if tcb_level.tcb.isvsvn <= enclave_report.isv_svn {
            let tcb_status = match &tcb_level.tcb_status[..] {
                "UpToDate" => TcbStatus::OK,
                "SWHardeningNeeded" => TcbStatus::TcbSwHardeningNeeded,
                "ConfigurationAndSWHardeningNeeded" => TcbStatus::TcbConfigurationAndSwHardeningNeeded,
                "ConfigurationNeeded" => TcbStatus::TcbConfigurationNeeded,
                "OutOfDate" => TcbStatus::TcbOutOfDate,
                "OutOfDateConfigurationNeeded" => TcbStatus::TcbOutOfDateConfigurationNeeded,
                "Revoked" => TcbStatus::TcbRevoked,
                _ => TcbStatus::TcbUnrecognized,
            };
            return tcb_status;
        }
    }

    TcbStatus::TcbUnrecognized
}

fn verify_qe_report_data(report_data: &[u8], ecdsa_attestation_key: &[u8], qe_auth_data: &[u8]) -> bool {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(ecdsa_attestation_key);
    verification_data.extend_from_slice(qe_auth_data);
    let mut recomputed_report_data = [0u8; 64];
    recomputed_report_data[..32].copy_from_slice(&sha256sum(&verification_data));
    recomputed_report_data == report_data
}