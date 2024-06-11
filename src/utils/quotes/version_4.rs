use crate::types::cert::IntelSgxCrls;
use crate::types::quotes::body::{QuoteBody, TD10ReportBody};
use crate::types::quotes::{
    version_4::{QuoteSignatureDataV4, QuoteV4},
    CertDataType,
};
use crate::types::{IntelCollateral, VerifiedOutput};
use crate::utils::cert::{
    extract_sgx_extension, get_tdx_fmspc_tcbstatus_v3, get_x509_subject_cn,
    verify_certchain_signature, verify_certificate, verify_crl,
};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::utils::enclave_identity::validate_enclave_identityv2;
use crate::utils::tcbinfo::validate_tcbinfov3;

use super::{validate_qe_report, verify_qe_report_data};

pub fn verify_quote_dcapv4(quote: &QuoteV4, collaterals: &IntelCollateral, current_time: u64) -> VerifiedOutput {
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
        }
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
    assert!(validate_tcbinfov3(
        &tcbinfov3,
        &tcb_signing_cert,
        current_time
    ));
    assert!(validate_enclave_identityv2(
        &qeidentityv2,
        &tcb_signing_cert,
        current_time
    ));

    // get the signature data from the quote
    let quote_signature_data = QuoteSignatureDataV4::from_bytes(&quote.signature);

    // we'll verify the head + body of the quote
    // let mut quote_data = [0u8; 48 + 584];
    // // copy the header
    // quote_data[..48].copy_from_slice(&quote.header.to_bytes());
    // // copy the body
    // quote_data[48..].copy_from_slice(&quote.quote_body.to_bytes());

    let mut quote_data = Vec::new();
    quote_data.extend_from_slice(&quote.header.to_bytes());
    match quote.quote_body {
        QuoteBody::SGXQuoteBody(body) => {
            quote_data.extend_from_slice(&body.to_bytes());
        },
        QuoteBody::TD10QuoteBody(body) => {
            quote_data.extend_from_slice(&body.to_bytes());
        }
    }

    // public key is in x + y form, 64 bytes, convert to sec1 uncompressed form
    let mut ecdsa_attestation_key = [4u8; 65];
    ecdsa_attestation_key[1..].copy_from_slice(&quote_signature_data.ecdsa_attestation_key);
    // verify the signature
    assert!(verify_p256_signature_bytes(
        &quote_data,
        &quote_signature_data.quote_signature,
        &ecdsa_attestation_key
    ));

    // at this point, quote is valid iff qe is valid

    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = quote_signature_data.qe_cert_data;

    // right now we just handle type 6, which has yet another QeCertDataV4 within it
    let (qe_report_cert_data, certchain) = if let CertDataType::QeReportCertData(
        qe_report_cert_data,
    ) = qe_cert_data_v4.get_cert_data()
    {
        let certchain = if let CertDataType::CertChain(certchain) =
            qe_report_cert_data.qe_cert_data.get_cert_data()
        {
            certchain
        } else {
            panic!("Unsupported CertDataType in QeReportCertData");
        };
        (qe_report_cert_data, certchain)
    } else {
        panic!("Unsupported CertDataType in QuoteSignatureDataV4");
    };

    // verify that certchain is valid
    assert!(verify_certchain_signature(
        &certchain.get_certs(),
        &intel_sgx_root_cert
    ));
    // get the pck cert (leaf cert)
    let pck_cert = &certchain.get_certs()[0];
    let pck_signer_cert = &certchain.get_certs()[1];
    // we'll check what kind of cert is it, and validate the appropriate CRL
    let pck_cert_subject_cn = get_x509_subject_cn(pck_signer_cert);
    match pck_cert_subject_cn.as_str() {
        "Intel SGX PCK Platform CA" => {
            assert!(verify_crl(
                intel_crls.sgx_pck_platform_crl.as_ref().unwrap(),
                pck_signer_cert
            ));
        }
        "Intel SGX PCK Processor CA" => {
            assert!(verify_crl(
                &intel_crls.sgx_pck_processor_crl.as_ref().unwrap(),
                pck_signer_cert
            ));
        }
        _ => {
            panic!("Unknown PCK Cert Subject CN: {}", pck_cert_subject_cn);
        }
    }

    // ensure that all the certs in the chain are not revoked
    for cert in certchain.get_certs().iter() {
        assert!(!intel_crls.is_cert_revoked(cert));
    }

    // at this point we know certchain is valid, i.e., pck_cert is signed by intel sgx root ca
    // now we'll use pck_cert to verify the qe

    let qe_report_bytes = qe_report_cert_data.qe_report.to_bytes();
    let pck_cert_public_key = pck_cert.public_key().subject_public_key.as_ref();
    assert!(verify_p256_signature_bytes(
        &qe_report_bytes,
        &qe_report_cert_data.qe_report_signature,
        pck_cert_public_key
    ));

    // at this point we are sure that the qe_report is signed by the pck_cert
    // so... root -> pck_signer -> pck_cert -> qe_report -> quote

    // all verifications check out, we'll now validate that values are correct

    // check that report_data in qe_report is correct
    validate_qe_report(&qe_report_cert_data.qe_report, &qeidentityv2);

    // check that tcb_info_root and enclave_identity_root are valid
    assert!(validate_tcbinfov3(
        &tcbinfov3,
        &tcb_signing_cert,
        current_time
    ));
    assert!(validate_enclave_identityv2(
        &qeidentityv2,
        &tcb_signing_cert,
        current_time
    ));

    // ensure that qe enclave matches with qeidentity
    assert!(validate_qe_report(
        &qe_report_cert_data.qe_report,
        &qeidentityv2
    ));

    // ensure that qe_report_data is correct
    assert!(verify_qe_report_data(
        &qe_report_cert_data.qe_report.report_data,
        &ecdsa_attestation_key[1..],
        &qe_report_cert_data.qe_auth_data.data
    ));

    // extract the sgx extensions from the leaf certificate
    let sgx_extensions = extract_sgx_extension(&pck_cert);
    let quote_tdx_body = &quote.quote_body;
    let tee_tcb_svn;
    if let QuoteBody::TD10QuoteBody(body) = quote_tdx_body {
        tee_tcb_svn = body.tee_tcb_svn;
    } else {
        // SGX TCB Status
        tee_tcb_svn = [0;16];
    }
    let tcb_status = get_tdx_fmspc_tcbstatus_v3(&sgx_extensions, &tee_tcb_svn, &tcbinfov3);

    // TEMP: Cloning TDX body for now, which is kinda dumb. i need to fix this asap
    let tdx_body_clone = QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(&quote_data[48..]));

    VerifiedOutput {
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: sgx_extensions.fmspc,
        quote_body: tdx_body_clone
    }
}
