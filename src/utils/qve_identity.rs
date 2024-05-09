use crate::types::qve_identity::QveIdentityV2;
use crate::utils::crypto::verify_p256_signature_bytes;

fn validate_qveidentityv2(qve_identityv2: &QveIdentityV2, root_ca_pubkey: &[u8], current_time: u64) -> bool {
    // get tcb_info_root time
    let issue_date = chrono::DateTime::parse_from_rfc3339(&qve_identityv2.enclave_identity.issue_date).unwrap();
    let next_update_date = chrono::DateTime::parse_from_rfc3339(&qve_identityv2.enclave_identity.next_update).unwrap();

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds = issue_date.timestamp() as u64;
    let next_update_seconds = next_update_date.timestamp() as u64;

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        return false;
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let qve_identityv2_signature_bytes= hex::decode(&qve_identityv2.signature).unwrap();

    // verify that the enclave_identity_root is signed by the root cert
    let qve_identityv2_signature_data = serde_json::to_vec(&qve_identityv2.enclave_identity).unwrap();
    verify_p256_signature_bytes(&qve_identityv2_signature_data, &qve_identityv2_signature_bytes, &root_ca_pubkey)
}
