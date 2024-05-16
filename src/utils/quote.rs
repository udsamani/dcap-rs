use crate::types::cert::IntelSgxCrls;
use crate::types::quote::{CertDataType, QuoteSignatureDataV4, QuoteV4, SgxEnclaveReport, SgxQuoteSignatureDataV3, SgxQuoteV3};
use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::types::{IntelCollateral, TcbStatus, VerifiedOutput};

use crate::utils::hash::sha256sum;
use crate::utils::cert::{extract_sgx_extension, get_fmspc_tcbstatus, get_x509_subject_cn, parse_certchain, parse_pem, verify_certchain_signature, verify_certificate, verify_crl, get_tdx_fmspc_tcbstatus_v3};
use crate::utils::enclave_identity::validate_enclave_identityv2;
use crate::utils::tcbinfo::{validate_tcbinfov2, validate_tcbinfov3};
use crate::utils::crypto::verify_p256_signature_bytes;


fn validate_qe_enclave(enclave_report: &SgxEnclaveReport, qeidentityv2: &EnclaveIdentityV2) -> bool {
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

fn verify_qe_report_data(report_data: &[u8], ecdsa_attestation_key: &[u8], qe_auth_data: &[u8]) -> bool {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(ecdsa_attestation_key);
    verification_data.extend_from_slice(qe_auth_data);
    let mut recomputed_report_data = [0u8; 64];
    recomputed_report_data[..32].copy_from_slice(&sha256sum(&verification_data));
    recomputed_report_data == report_data
}

pub fn verify_quote_dcapv3(quote: &SgxQuoteV3, collaterals: &IntelCollateral, current_time: u64) -> VerifiedOutput {
    let signing_cert = collaterals.get_sgx_tcb_signing();
    let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca();
    let tcbinfov2 = collaterals.get_tcbinfov2();
    let qeidentityv2 = collaterals.get_qeidentityv2();

    // make sure that all the certificates we are using are not revoked
    let intel_crls = IntelSgxCrls::from_collaterals(collaterals);

    // ZL: Currently don't think this is needed, but for soundness sake we'll add it in
    // Can consider removing it for the risc0 case.
    match &intel_crls.sgx_root_ca_crl {
        Some(crl) => {
            assert!(verify_crl(crl, &intel_sgx_root_cert));
        },
        None => {
            panic!("No SGX Root CA CRL found");
        }
    }
    intel_crls.is_cert_revoked(&signing_cert);
    intel_crls.is_cert_revoked(&intel_sgx_root_cert);

    // we'll delay the checking of the certchain to later
    // verify that signing_verifying_key is signed by the root cert
    assert!(verify_certificate(&signing_cert, &intel_sgx_root_cert));

    // check that tcb_info_root and enclave_identity_root are valid
    assert!(validate_tcbinfov2(&tcbinfov2, &signing_cert, current_time));
    assert!(validate_enclave_identityv2(&qeidentityv2, &signing_cert, current_time));

    // we'll extract the ISV (local enclave AKA the enclave that is attesting) report from the quote 
    let isv_enclave_report = quote.isv_enclave_report;

    // check that the QE Report is correct
    // we'll first parse the signature into a ECDSA Quote signature data
    let ecdsa_quote_signature_data =  SgxQuoteSignatureDataV3::from_bytes(&quote.signature);

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
    assert!(verify_certchain_signature(&certchain, &intel_sgx_root_cert));

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
    // get the reportdata
    assert!(verify_qe_report_data(&ecdsa_quote_signature_data.qe_report.report_data, &ecdsa_quote_signature_data.ecdsa_attestation_key, &ecdsa_quote_signature_data.qe_auth_data.data));


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

pub fn verify_quote_dcapv4 (quote: &QuoteV4, collaterals: &IntelCollateral, current_time: u64) {
    let tcbinfov3 = collaterals.get_tcbinfov3();
    let qeidentityv2 = collaterals.get_qeidentityv2();

    let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca();
    let tcb_signing_cert = collaterals.get_sgx_tcb_signing();

    let intel_crls = IntelSgxCrls::from_collaterals(collaterals);
    // ZL: If collaterals are checked by the caller, then these can be removed
    // check that CRLs are valid
    match &intel_crls.sgx_root_ca_crl {
        Some(crl) => {
            assert!(verify_crl(crl, &intel_sgx_root_cert));
        },
        None => {
            panic!("No SGX Root CA CRL found");
        }
    }
    // ZL: we'll delay the verification of either platform or processor CRLs to later

    // check that the tcb signing cert is not revoked
    assert!(!intel_crls.is_cert_revoked(&tcb_signing_cert));
    assert!(!intel_crls.is_cert_revoked(&intel_sgx_root_cert));

    // check that the tcb signing cert is signed by the root cert
    assert!(verify_certificate(&tcb_signing_cert, &intel_sgx_root_cert));

    // check that tcb_info_root and enclave_identity_root are valid
    assert!(validate_tcbinfov3(&tcbinfov3, &tcb_signing_cert, current_time));
    assert!(validate_enclave_identityv2(&qeidentityv2, &tcb_signing_cert, current_time));

    // get the signature data from the quote
    let quote_signature_data = QuoteSignatureDataV4::from_bytes(&quote.signature);

    // we'll verify the head + body of the quote
    let mut quote_data = [0u8; 48 + 584];
    // copy the header
    quote_data[..48].copy_from_slice(&quote.header.to_bytes());
    // copy the body
    quote_data[48..].copy_from_slice(&quote.quote_body.to_bytes());
    // public key is in x + y form, 64 bytes, convert to sec1 uncompressed form
    let mut ecdsa_attestation_key = [4u8; 65];
    ecdsa_attestation_key[1..].copy_from_slice(&quote_signature_data.ecdsa_attestation_key);
    // verify the signature
    assert!(verify_p256_signature_bytes(&quote_data, &quote_signature_data.quote_signature, &ecdsa_attestation_key));

    // at this point, quote is valid iff qe is valid

    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = quote_signature_data.qe_cert_data;

    // right now we just handle type 6, which has yet another QeCertDataV4 within it
    let (qe_report_cert_data, certchain) = if let CertDataType::QeReportCertData(qe_report_cert_data) = qe_cert_data_v4.get_cert_data() {
        let certchain = if let CertDataType::CertChain(certchain) = qe_report_cert_data.qe_cert_data.get_cert_data() {
            certchain
        } else {
            panic!("Unsupported CertDataType in QeReportCertData");
        };
        (qe_report_cert_data, certchain)
    }
    else {
        panic!("Unsupported CertDataType in QuoteSignatureDataV4");
    };

    // verify that certchain is valid
    assert!(verify_certchain_signature(&certchain.get_certs(), &intel_sgx_root_cert));
    // get the pck cert (leaf cert)
    let pck_cert = &certchain.get_certs()[0];
    let pck_signer_cert = &certchain.get_certs()[1];
    // we'll check what kind of cert is it, and validate the appropriate CRL
    let pck_cert_subject_cn = get_x509_subject_cn(pck_signer_cert);
    match pck_cert_subject_cn.as_str() {
        "Intel SGX PCK Platform CA" => {
            assert!(verify_crl(intel_crls.sgx_pck_platform_crl.as_ref().unwrap(), pck_signer_cert));
        },
        "Intel SGX PCK Processor CA" => {
            assert!(verify_crl(&intel_crls.sgx_pck_processor_crl.as_ref().unwrap(), pck_signer_cert));
        },
        _ => {
            panic!("Unknown PCK Cert Subject CN: {}", pck_cert_subject_cn);
        },
    }

    // ensure that all the certs in the chain are not revoked
    for cert in certchain.get_certs().iter() {
        assert!(!intel_crls.is_cert_revoked(cert));
    }

    // at this point we know certchain is valid, i.e., pck_cert is signed by intel sgx root ca
    // now we'll use pck_cert to verify the qe

    let qe_report_bytes = qe_report_cert_data.qe_report.to_bytes();
    let pck_cert_public_key = pck_cert.public_key().subject_public_key.as_ref();
    assert!(verify_p256_signature_bytes(&qe_report_bytes, &qe_report_cert_data.qe_report_signature, pck_cert_public_key));

    // at this point we are sure that the qe_report is signed by the pck_cert
    // so... root -> pck_signer -> pck_cert -> qe_report -> quote

    // all verifications check out, we'll now validate that values are correct

    // check that report_data in qe_report is correct
    validate_qe_enclave(&qe_report_cert_data.qe_report, &qeidentityv2);

    // check that tcb_info_root and enclave_identity_root are valid
    assert!(validate_tcbinfov3(&tcbinfov3, &tcb_signing_cert, current_time));
    assert!(validate_enclave_identityv2(&qeidentityv2, &tcb_signing_cert, current_time));

    // ensure that qe enclave matches with qeidentity
    assert!(validate_qe_enclave(&qe_report_cert_data.qe_report, &qeidentityv2));
    
    // ensure that qe_report_data is correct
    assert!(verify_qe_report_data(&qe_report_cert_data.qe_report.report_data, &ecdsa_attestation_key[1..], &qe_report_cert_data.qe_auth_data.data));

    // extract the sgx extensions from the leaf certificate
    let sgx_extensions = extract_sgx_extension(&pck_cert);
    let tee_tcb_svn = &quote.quote_body.tee_tcb_svn;
    let _tcb_status = get_tdx_fmspc_tcbstatus_v3(&sgx_extensions, tee_tcb_svn, &tcbinfov3);
}