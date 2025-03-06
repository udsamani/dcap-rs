pub mod version_3;
pub mod version_4;

use x509_parser::certificate::X509Certificate;

use crate::constants::{ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID};
use crate::utils::hash::sha256sum;

use crate::types::cert::{IntelSgxCrls, SgxExtensions};
use crate::types::collaterals::IntelCollateral;
use crate::types::quotes::{
    body::{EnclaveReport, QuoteBody},
    CertData, QuoteHeader,
};
use crate::types::tcbinfo::TcbInfo;
use crate::types::TcbStatus;

use crate::utils::cert::{
    extract_sgx_extension, get_x509_issuer_cn, get_x509_subject_cn, parse_certchain, parse_pem,
    verify_certchain_signature, verify_certificate, verify_crl,
};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::utils::tcbinfo::{validate_tcbinfov2, validate_tcbinfov3};

fn check_quote_header(quote_header: &QuoteHeader, quote_version: u16) -> bool {
    let quote_version_is_valid = quote_header.version == quote_version;
    let att_key_type_is_supported = quote_header.att_key_type == ECDSA_256_WITH_P256_CURVE;
    let qe_vendor_id_is_valid = quote_header.qe_vendor_id == INTEL_QE_VENDOR_ID;

    quote_version_is_valid && att_key_type_is_supported && qe_vendor_id_is_valid
}

// Split the large function into smaller functions to reduce stack usage
fn common_verify_and_fetch_tcb(
    quote_header: &QuoteHeader,
    quote_body: &QuoteBody,
    ecdsa_attestation_signature: &[u8],
    ecdsa_attestation_pubkey: &[u8],
    qe_report: &EnclaveReport,
    qe_report_signature: &[u8],
    qe_auth_data: &[u8],
    qe_cert_data: &CertData,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> (TcbStatus, SgxExtensions, TcbInfo) {
    // Step 1: Verify certificates and CRLs
    verify_certificates_and_crls(collaterals);

    // Step 2: Validate QE identity and get TCB status
    let qe_tcb_status = verify_qe_identity(qe_report, collaterals, current_time);

    // Step 3: Verify QE report data
    verify_qe_report_data_and_values(
        qe_report,
        ecdsa_attestation_pubkey,
        qe_auth_data,
        collaterals
    );

    // Step 4: Process certificate chain and get SGX extensions
    let sgx_extensions = process_cert_chain(
        qe_cert_data,
        qe_report,
        qe_report_signature,
        collaterals
    );

    // Step 5: Verify attestation signature
    verify_attestation_signature(
        quote_header,
        quote_body,
        ecdsa_attestation_signature,
        ecdsa_attestation_pubkey
    );

    // Step 6: Validate TCB info
    let tcb_info = validate_appropriate_tcb_info(quote_header, collaterals, current_time);

    (qe_tcb_status, sgx_extensions, tcb_info)
}

#[inline(never)]
fn verify_certificates_and_crls(collaterals: &IntelCollateral) {
    let signing_cert = collaterals.get_sgx_tcb_signing();
    let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca();
    let intel_crls = IntelSgxCrls::from_collaterals(collaterals);

    // Check CRLs
    match &intel_crls.sgx_root_ca_crl {
        Some(crl) => {
            assert!(verify_crl(crl, &intel_sgx_root_cert));
        }
        None => {
            panic!("No SGX Root CA CRL found");
        }
    }

    // Verify signing cert
    let signing_cert_revoked = intel_crls.is_cert_revoked(&signing_cert);
    assert!(!signing_cert_revoked, "TCB Signing Cert revoked");
    assert!(
        verify_certificate(&signing_cert, &intel_sgx_root_cert),
        "TCB Signing Cert is not signed by Intel SGX Root CA"
    );
}

#[inline(never)]
fn verify_qe_identity(
    qe_report: &EnclaveReport,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> TcbStatus {
    let signing_cert = collaterals.get_sgx_tcb_signing();
    let qeidentityv2 = collaterals.get_qeidentityv2();

    assert!(validate_enclave_identityv2(
        &qeidentityv2,
        &signing_cert,
        current_time
    ));

    let qe_tcb_status = get_qe_tcbstatus(qe_report, &qeidentityv2);
    assert!(
        qe_tcb_status != TcbStatus::TcbRevoked,
        "QEIdentity TCB Revoked"
    );

    qe_tcb_status
}

#[inline(never)]
fn verify_qe_report_data_and_values(
    qe_report: &EnclaveReport,
    ecdsa_attestation_pubkey: &[u8],
    qe_auth_data: &[u8],
    collaterals: &IntelCollateral,
) {
    let qeidentityv2 = collaterals.get_qeidentityv2();

    assert!(
        verify_qe_report_data(
            &qe_report.report_data,
            ecdsa_attestation_pubkey,
            qe_auth_data
        ),
        "QE Report Data is incorrect"
    );

    assert!(
        validate_qe_report(qe_report, &qeidentityv2),
        "QE Report values do not match with the provided QEIdentity"
    );
}

#[inline(never)]
fn process_cert_chain(
    qe_cert_data: &CertData,
    qe_report: &EnclaveReport,
    qe_report_signature: &[u8],
    collaterals: &IntelCollateral,
) -> SgxExtensions {
    let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca();
    let intel_crls = IntelSgxCrls::from_collaterals(collaterals);

    // Verify cert type
    assert_eq!(qe_cert_data.cert_data_type, 5, "QE Cert Type must be 5");

    // Parse certificates
    let certchain_pems = parse_pem(&qe_cert_data.cert_data).unwrap();
    let certchain = parse_certchain(&certchain_pems);

    // Check revocation status
    for cert in certchain.iter() {
        assert!(!intel_crls.is_cert_revoked(cert));
    }

    // Verify PCK certificate
    let pck_cert = &certchain[0];
    let pck_cert_issuer = &certchain[1];

    assert!(
        check_pck_issuer_and_crl(pck_cert, pck_cert_issuer, &intel_crls),
        "Invalid PCK Issuer or CRL"
    );

    // Verify cert chain signatures
    assert!(
        verify_certchain_signature(&certchain, &intel_sgx_root_cert),
        "Invalid PCK Chain"
    );

    // Verify QE report signature
    verify_qe_report_signature(qe_report, qe_report_signature, pck_cert);

    // Extract SGX extensions
    extract_sgx_extension(pck_cert)
}

#[inline(never)]
fn verify_qe_report_signature(
    qe_report: &EnclaveReport,
    qe_report_signature: &[u8],
    pck_cert: &X509Certificate,
) {
    let qe_report_bytes = qe_report.to_bytes();
    let qe_report_public_key = pck_cert.public_key().subject_public_key.as_ref();

    assert!(
        verify_p256_signature_bytes(&qe_report_bytes, qe_report_signature, qe_report_public_key),
        "Invalid qe signature"
    );
}

#[inline(never)]
fn verify_attestation_signature(
    quote_header: &QuoteHeader,
    quote_body: &QuoteBody,
    ecdsa_attestation_signature: &[u8],
    ecdsa_attestation_pubkey: &[u8],
) {
    // Create data buffer
    let mut data = Vec::new();
    let header_bytes = quote_header.to_bytes();
    match quote_body {
        QuoteBody::SGXQuoteBody(body) => data.extend_from_slice(&body.to_bytes()),
        QuoteBody::TD10QuoteBody(body) => data.extend_from_slice(&body.to_bytes()),
    };

    // Prepare signature verification data
    data.extend_from_slice(&header_bytes);

    // Prepare public key
    let mut prefixed_pub_key = [4u8; 65];
    prefixed_pub_key[1..65].copy_from_slice(ecdsa_attestation_pubkey);

    // Verify signature
    assert!(
        verify_p256_signature_bytes(&data, ecdsa_attestation_signature, &prefixed_pub_key),
        "Invalid attestation signature"
    );
}

#[inline(never)]
fn validate_appropriate_tcb_info(
    quote_header: &QuoteHeader,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> TcbInfo {
    let signing_cert = collaterals.get_sgx_tcb_signing();

    if quote_header.version >= 4 {
        let tcb_info_v3 = collaterals.get_tcbinfov3();
        assert!(
            validate_tcbinfov3(&tcb_info_v3, &signing_cert, current_time),
            "Invalid TCBInfoV3"
        );
        TcbInfo::V3(tcb_info_v3)
    } else {
        let tcb_info_v2 = collaterals.get_tcbinfov2();
        assert!(
            validate_tcbinfov2(&tcb_info_v2, &signing_cert, current_time),
            "Invalid TCBInfoV2"
        );
        TcbInfo::V2(tcb_info_v2)
    }
}

fn check_pck_issuer_and_crl(
    pck_cert: &X509Certificate,
    pck_issuer_cert: &X509Certificate,
    intel_crls: &IntelSgxCrls,
) -> bool {
    // we'll check what kind of cert is it, and validate the appropriate CRL
    let pck_cert_subject_cn = get_x509_issuer_cn(pck_cert);
    let pck_cert_issuer_cn = get_x509_subject_cn(pck_issuer_cert);

    assert!(
        pck_cert_issuer_cn == pck_cert_subject_cn,
        "PCK Issuer CN does not match with PCK Intermediate Subject CN"
    );

    match pck_cert_issuer_cn.as_str() {
        "Intel SGX PCK Platform CA" => verify_crl(
            intel_crls.sgx_pck_platform_crl.as_ref().unwrap(),
            pck_issuer_cert,
        ),
        "Intel SGX PCK Processor CA" => verify_crl(
            &intel_crls.sgx_pck_processor_crl.as_ref().unwrap(),
            pck_issuer_cert,
        ),
        _ => {
            panic!("Unknown PCK Cert Subject CN: {}", pck_cert_subject_cn);
        }
    }
}

fn validate_qe_report(enclave_report: &EnclaveReport, qeidentityv2: &EnclaveIdentityV2) -> bool {
    // make sure that the enclave_identityv2 is a qeidentityv2
    // check that id is "QE", "TD_QE" or "QVE" and version is 2
    if !((qeidentityv2.enclave_identity.id == "QE"
        || qeidentityv2.enclave_identity.id == "TD_QE"
        || qeidentityv2.enclave_identity.id == "QVE")
        && qeidentityv2.enclave_identity.version == 2)
    {
        return false;
    }

    let mrsigner_ok = enclave_report.mrsigner
        == hex::decode(&qeidentityv2.enclave_identity.mrsigner)
            .unwrap()
            .as_slice();
    let isvprodid_ok = enclave_report.isv_prod_id == qeidentityv2.enclave_identity.isvprodid;

    let attributes = hex::decode(&qeidentityv2.enclave_identity.attributes).unwrap();
    let attributes_mask = hex::decode(&qeidentityv2.enclave_identity.attributes_mask).unwrap();
    let masked_attributes = attributes
        .iter()
        .zip(attributes_mask.iter())
        .map(|(a, m)| a & m)
        .collect::<Vec<u8>>();
    let masked_enclave_attributes = enclave_report
        .attributes
        .iter()
        .zip(attributes_mask.iter())
        .map(|(a, m)| a & m)
        .collect::<Vec<u8>>();
    let enclave_attributes_ok = masked_enclave_attributes == masked_attributes;

    let miscselect = hex::decode(&qeidentityv2.enclave_identity.miscselect).unwrap();
    let miscselect_mask = hex::decode(&qeidentityv2.enclave_identity.miscselect_mask).unwrap();
    let masked_miscselect = miscselect
        .iter()
        .zip(miscselect_mask.iter())
        .map(|(a, m)| a & m)
        .collect::<Vec<u8>>();
    let masked_enclave_miscselect = enclave_report
        .misc_select
        .iter()
        .zip(miscselect_mask.iter())
        .map(|(a, m)| a & m)
        .collect::<Vec<u8>>();
    let enclave_miscselect_ok = masked_enclave_miscselect == masked_miscselect;

    mrsigner_ok && isvprodid_ok && enclave_attributes_ok && enclave_miscselect_ok
}

fn verify_qe_report_data(
    report_data: &[u8],
    ecdsa_attestation_key: &[u8],
    qe_auth_data: &[u8],
) -> bool {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(ecdsa_attestation_key);
    verification_data.extend_from_slice(qe_auth_data);
    let mut recomputed_report_data = [0u8; 64];
    recomputed_report_data[..32].copy_from_slice(&sha256sum(&verification_data));
    recomputed_report_data == report_data
}

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
fn converge_tcb_status_with_qe_tcb(tcb_status: TcbStatus, qe_tcb_status: TcbStatus) -> TcbStatus {
    let converged_tcb_status: TcbStatus;
    match qe_tcb_status {
        TcbStatus::TcbOutOfDate => {
            if tcb_status == TcbStatus::OK || tcb_status == TcbStatus::TcbSwHardeningNeeded {
                converged_tcb_status = TcbStatus::TcbOutOfDate;
            } else if tcb_status == TcbStatus::TcbConfigurationNeeded
                || tcb_status == TcbStatus::TcbConfigurationAndSwHardeningNeeded
            {
                converged_tcb_status = TcbStatus::TcbOutOfDateConfigurationNeeded;
            } else {
                converged_tcb_status = tcb_status;
            }
        },
        _ => {
            converged_tcb_status = tcb_status;
        }
    }
    converged_tcb_status
}
