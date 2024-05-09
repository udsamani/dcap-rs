use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::utils::crypto::verify_p256_signature_bytes;

use crate::X509Certificate;

pub fn validate_enclave_identityv2(enclave_identityv2: &EnclaveIdentityV2, sgx_signing_pubkey: &X509Certificate, current_time: u64) -> bool {
    // get tcb_info_root time
    let issue_date = chrono::DateTime::parse_from_rfc3339(&enclave_identityv2.enclave_identity.issue_date).unwrap();
    let next_update_date = chrono::DateTime::parse_from_rfc3339(&enclave_identityv2.enclave_identity.next_update).unwrap();

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds = issue_date.timestamp() as u64;
    let next_update_seconds = next_update_date.timestamp() as u64;

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        return false;
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let enclave_identityv2_signature_bytes= hex::decode(&enclave_identityv2.signature).unwrap();

    // verify that the enclave_identity_root is signed by the root cert
    let enclave_identityv2_signature_data = serde_json::to_vec(&enclave_identityv2.enclave_identity).unwrap();
    verify_p256_signature_bytes(&enclave_identityv2_signature_data, &enclave_identityv2_signature_bytes, sgx_signing_pubkey.public_key().subject_public_key.as_ref())
}
