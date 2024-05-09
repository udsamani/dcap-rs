use crate::types::quote::{SgxQuote, SgxEnclaveReport, SgxQuoteSignatureData};
use crate::types::enclave_identity::QveIdentityV2;
use crate::types::tcbinfo::{TcbInfoV2, TcbStatus};

use crate::utils::hash::sha256sum;

use super::qve_identity;

fn validate_qe_enclave(enclave_report: &SgxEnclaveReport, enclave_identity_root: &QveIdentityV2) -> bool {
    let mrsigner_ok = enclave_report.mrsigner == hex::decode(&enclave_identity_root.enclave_identity.mrsigner).unwrap().as_slice();
    let isvprodid_ok = enclave_report.isv_prod_id == enclave_identity_root.enclave_identity.isvprodid;

    let attributes = hex::decode(&enclave_identity_root.enclave_identity.attributes).unwrap();
    let attributes_mask = hex::decode(&enclave_identity_root.enclave_identity.attributes_mask).unwrap();
    let masked_attributes = attributes.iter().zip(attributes_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let masked_enclave_attributes = enclave_report.attributes.iter().zip(attributes_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let enclave_attributes_ok = masked_enclave_attributes == masked_attributes;

    let miscselect = hex::decode(&enclave_identity_root.enclave_identity.miscselect).unwrap();
    let miscselect_mask = hex::decode(&enclave_identity_root.enclave_identity.miscselect_mask).unwrap();
    let masked_miscselect = miscselect.iter().zip(miscselect_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let masked_enclave_miscselect = enclave_report.misc_select.iter().zip(miscselect_mask.iter()).map(|(a, m)| a & m).collect::<Vec<u8>>();
    let enclave_miscselect_ok = masked_enclave_miscselect == masked_miscselect;

    let tcb_status = get_qe_tcbstatus(enclave_report, enclave_identity_root);

    mrsigner_ok && isvprodid_ok && enclave_attributes_ok && enclave_miscselect_ok && tcb_status == TcbStatus::OK
}

fn get_qe_tcbstatus(enclave_report: &SgxEnclaveReport, qve_identityv2: &QveIdentityV2) -> TcbStatus {
    for tcb_level in qve_identityv2.enclave_identity.tcb_levels.iter() {
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

fn get_pck_tcbstatus(sgx_extension: )

fn verify_qe_report_data(qe_info: &SgxQuoteSignatureData) -> bool {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&qe_info.ecdsa_attestation_key);
    verification_data.extend_from_slice(&qe_info.qe_auth_data.data);

    sha256sum(&verification_data) == qe_info.qe_report.report_data[..32]
}

pub fn verify_quote<'a>(quote: &SgxQuote, tcb_info_root: &TcbInfoV2, enclave_identity_root: &QveIdentityV2, signing_cert: &X509Certificate<'a>, root_cert: &X509Certificate<'a>, current_time: u64) -> VerifiedOutput {
    let root_cert_public_key = root_cert.public_key().subject_public_key.as_ref();
    // let root_verifying_key = VerifyingKey::from_sec1_bytes(root_cert_public_key).unwrap();

    // verify that signing_verifying_key is signed by the root cert
    assert!(verify_certificate(signing_cert, root_cert_public_key));
    let signing_cert_public_key = signing_cert.public_key().subject_public_key.as_ref();
    let signing_verifying_key = VerifyingKey::from_sec1_bytes(signing_cert_public_key).unwrap();


    // check that tcb_info_root and enclave_identity_root are valid
    assert!(validate_tcbinforoot(&tcb_info_root, &signing_verifying_key, current_time));
    assert!(validate_enclaveidentityroot(&enclave_identity_root, &signing_verifying_key, current_time));

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
    let isv_signature = Signature::from_bytes(&ecdsa_quote_signature_data.isv_enclave_report_signature.into()).unwrap();
    let isv_verifying_key = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
    // println!("signature: {:?}", hex::encode(isv_signature.to_bytes()));
    // println!("verifying_key: {:?}", isv_verifying_key);
    assert!(isv_verifying_key.verify(&data, &isv_signature).is_ok());

    // we'll get the certchain embedded in the ecda quote signature data
    // this can be one of 5 types
    // we'll only handle type 5 for now...
    // TODO: Add support for all other types

    assert_eq!(ecdsa_quote_signature_data.qe_cert_data.cert_data_type, 5);
    let certchain_pems = parse_pem(&ecdsa_quote_signature_data.qe_cert_data.cert_data).unwrap();
    let certchain = parse_certchain(&certchain_pems);
    // verify that the cert chain is valid
    // we'll assume that the root cert is the last cert in the chain
    // TODO: Replace root cert here to be the actual root cert
    // let root_cert = certchain.last().unwrap();
    assert!(verify_certchain(&certchain, root_cert));

    // get the leaf certificate
    let leaf_cert = parse_certchain(&certchain_pems)[0].clone();

    // calculate the qe_report_hash
    let qe_report_bytes = ecdsa_quote_signature_data.qe_report.to_bytes();
    // println!("qe_report_bytes:: {:?}", hex::encode(qe_report_bytes));

    // verify the signature of the QE report
    let qe_report_signature = ecdsa_quote_signature_data.qe_report_signature;
    let qe_report_public_key = leaf_cert.public_key().subject_public_key.as_ref();
    // println!("qe_pubkey: {:?}", hex::encode(qe_report_public_key));
    let qe_report_signature = Signature::from_bytes(&qe_report_signature.into()).unwrap();
    let qe_report_verifying_key = VerifyingKey::from_sec1_bytes(qe_report_public_key).unwrap();
    // println!("qe_report_signautre_bytes:: {:?}", hex::encode(qe_report_signature.to_bytes()));
    // println!("qe_report_signature:::: {:?}", qe_report_signature);
    // println!("qe_report_verifying_key:::: {:?}", qe_report_verifying_key);
    assert!(qe_report_verifying_key.verify(&qe_report_bytes, &qe_report_signature).is_ok());

    // at this point in time, we have verified everything is kosher
    // isv_enclae is signed by the qe enclave
    // qe enclave is signed by intel

    // ensure that qe enclave matches with qeidentity
    assert!(validate_qe_enclave(&ecdsa_quote_signature_data.qe_report, &enclave_identity_root));
    
    // ensure that qe_report_data is correct
    assert!(verify_qe_report_data(&ecdsa_quote_signature_data));


    // we'll create the VerifiedOutput struct that will be produced by this function
    // this allows anyone to perform application specific checks on information such as
    // mrenclave, mrsigner, tcbstatus, etc.

    // extract the sgx extensions from the leaf certificate
    let sgx_extensions = extract_sgx_extension(&leaf_cert);
    // println!("sgx_extensions: {:?}", sgx_extensions);
    let tcb_status = get_tcbrootinfo_tcb_status(&sgx_extensions, &tcb_info_root);


    VerifiedOutput {
        tcb_status,
        mr_enclave: isv_enclave_report.mrenclave,
        mr_signer: isv_enclave_report.mrsigner,
        report_data: quote.isv_enclave_report.report_data,
        fmspc: sgx_extensions.fmspc,
    }
}
