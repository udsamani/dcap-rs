use crate::types::cert::IntelSgxCrls;
use crate::types::quote::{SgxQuote, SgxEnclaveReport, SgxQuoteSignatureData};
use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::types::{IntelCollateralV3, TcbStatus, VerifiedOutput};

use crate::utils::hash::sha256sum;
use crate::utils::cert::{extract_sgx_extension, get_fmspc_tcbstatus, parse_certchain, parse_pem, verify_certchain_signature, verify_certificate};
use crate::utils::enclave_identity::validate_enclave_identityv2;
use crate::utils::tcbinfo::validate_tcbinfov2;
use crate::utils::crypto::verify_p256_signature_bytes;


fn validate_qe_enclave(enclave_report: &SgxEnclaveReport, qeidentityv2: &EnclaveIdentityV2) -> bool {
    // make sure that the enclave_identityv2 is a qeidentityv2
    // check that id is "QE" and version is 2
    if qeidentityv2.enclave_identity.id != "QE" || qeidentityv2.enclave_identity.version != 2 {
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

fn get_qe_tcbstatus(enclave_report: &SgxEnclaveReport, qeidentityv2: &EnclaveIdentityV2) -> TcbStatus {
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

fn verify_qe_report_data(qe_info: &SgxQuoteSignatureData) -> bool {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&qe_info.ecdsa_attestation_key);
    verification_data.extend_from_slice(&qe_info.qe_auth_data.data);

    sha256sum(&verification_data) == qe_info.qe_report.report_data[..32]
}

pub fn verify_quote_dcapv3(quote: &SgxQuote, collaterals: &IntelCollateralV3, current_time: u64) -> VerifiedOutput {
    let signing_cert = collaterals.get_sgx_tcb_signing();
    let root_cert = collaterals.get_intel_root_ca();
    let tcbinfov2 = collaterals.get_tcbinfov2();
    let qeidentityv2 = collaterals.get_qeidentityv2();

    // make sure that all the certificates we are using are not revoked
    let intel_crls = IntelSgxCrls::from_collaterals(collaterals);

    // ZL: Currently don't think this is needed, but for soundness sake we'll add it in
    // Can consider removing it for the risc0 case.
    intel_crls.is_cert_revoked(&signing_cert);
    intel_crls.is_cert_revoked(&root_cert);

    // we'll delay the checking of the certchain to later
    // verify that signing_verifying_key is signed by the root cert
    assert!(verify_certificate(&signing_cert, &root_cert));

    // check that tcb_info_root and enclave_identity_root are valid
    assert!(validate_tcbinfov2(&tcbinfov2, &signing_cert, current_time));
    assert!(validate_enclave_identityv2(&qeidentityv2, &signing_cert, current_time));

    // we'll extract the ISV (local enclave AKA the enclave that is attesting) report from the quote 
    let isv_enclave_report = quote.isv_enclave_report;

    // check that the QE Report is correct
    // we'll first parse the signature into a ECDSA Quote signature data
    let ecdsa_quote_signature_data =  SgxQuoteSignatureData::from_bytes(&quote.signature);

    // verify that the isv_enclave has been signed by the quoting enclave
    let mut data = [0; 48 + 384];
    data[..48].copy_from_slice(&quote.header.to_bytes());
    data[48..432].copy_from_slice(&isv_enclave_report.to_bytes());
    let mut pubkey = [4; 65];
    pubkey[1..65].copy_from_slice(&ecdsa_quote_signature_data.ecdsa_attestation_key);
    assert!(verify_p256_signature_bytes(&data, &ecdsa_quote_signature_data.isv_enclave_report_signature, &pubkey));

    // we'll get the certchain embedded in the ecda quote signature data
    // this can be one of 5 types
    // we'll only handle type 5 for now...
    // TODO: Add support for all other types

    assert_eq!(ecdsa_quote_signature_data.qe_cert_data.cert_data_type, 5);
    let certchain_pems = parse_pem(&ecdsa_quote_signature_data.qe_cert_data.cert_data).unwrap();
    let certchain = parse_certchain(&certchain_pems);

    // checks that the certificates used in the certchain are not revoked
    for cert in certchain.iter() {
        assert!(!intel_crls.is_cert_revoked(cert));
    }

    // verify that the cert chain signatures are valid
    assert!(verify_certchain_signature(&certchain, &root_cert));

    // get the leaf certificate
    let leaf_cert = parse_certchain(&certchain_pems)[0].clone();

    // calculate the qe_report_hash
    let qe_report_bytes = ecdsa_quote_signature_data.qe_report.to_bytes();

    // verify the signature of the QE report
    let qe_report_signature = ecdsa_quote_signature_data.qe_report_signature;
    let qe_report_public_key = leaf_cert.public_key().subject_public_key.as_ref();
    assert!(verify_p256_signature_bytes(&qe_report_bytes, &qe_report_signature, qe_report_public_key));

    // at this point in time, we have verified everything is kosher
    // isv_enclae is signed by the qe enclave
    // qe enclave is signed by intel

    // ensure that qe enclave matches with qeidentity
    assert!(validate_qe_enclave(&ecdsa_quote_signature_data.qe_report, &qeidentityv2));
    
    // ensure that qe_report_data is correct
    assert!(verify_qe_report_data(&ecdsa_quote_signature_data));


    // we'll create the VerifiedOutput struct that will be produced by this function
    // this allows anyone to perform application specific checks on information such as
    // mrenclave, mrsigner, tcbstatus, etc.

    // extract the sgx extensions from the leaf certificate
    let sgx_extensions = extract_sgx_extension(&leaf_cert);
    let tcb_status = get_fmspc_tcbstatus(&sgx_extensions, &tcbinfov2);

    VerifiedOutput {
        tcb_status,
        mr_enclave: isv_enclave_report.mrenclave,
        mr_signer: isv_enclave_report.mrsigner,
        report_data: quote.isv_enclave_report.report_data,
        fmspc: sgx_extensions.fmspc,
    }
}
