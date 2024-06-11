use crate::types::quotes::body::{QuoteBody, TD10ReportBody};
use crate::types::quotes::{version_4::QuoteV4, CertDataType};
use crate::types::{
    tcbinfo::{TcbInfo, TcbInfoV3},
    IntelCollateral, VerifiedOutput,
};
use crate::utils::cert::get_tdx_fmspc_tcbstatus_v3;

use super::{common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb};

pub fn verify_quote_dcapv4(
    quote: &QuoteV4,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> VerifiedOutput {
    // TEMP
    let mut quote_data = Vec::new();
    quote_data.extend_from_slice(&quote.header.to_bytes());
    match quote.quote_body {
        QuoteBody::SGXQuoteBody(body) => {
            quote_data.extend_from_slice(&body.to_bytes());
        }
        QuoteBody::TD10QuoteBody(body) => {
            quote_data.extend_from_slice(&body.to_bytes());
        }
    }

    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = &quote.signature.qe_cert_data;

    // right now we just handle type 6, which contains the QEReport, QEReportSignature, QEAuthData and another CertData
    let qe_report_cert_data = if let CertDataType::QeReportCertData(qe_report_cert_data) =
        qe_cert_data_v4.get_cert_data()
    {
        qe_report_cert_data
    } else {
        panic!("Unsupported CertDataType in QuoteSignatureDataV4");
    };

    let (qe_tcb_status, sgx_extensions, tcb_info) = common_verify_and_fetch_tcb(
        &quote.header,
        &quote.quote_body,
        &quote.signature.quote_signature,
        &quote.signature.ecdsa_attestation_key,
        &qe_report_cert_data.qe_report,
        &qe_report_cert_data.qe_report_signature,
        &qe_report_cert_data.qe_auth_data.data,
        &qe_report_cert_data.qe_cert_data,
        collaterals,
        current_time,
    );

    let tcb_info_v3: TcbInfoV3;
    if let TcbInfo::V3(tcb) = tcb_info {
        tcb_info_v3 = tcb;
    } else {
        panic!("TcbInfo must be V3!");
    }

    let quote_tdx_body = &quote.quote_body;
    let tee_tcb_svn;
    if let QuoteBody::TD10QuoteBody(body) = quote_tdx_body {
        tee_tcb_svn = body.tee_tcb_svn;
    } else {
        // SGX does not produce tee_tcb_svns
        tee_tcb_svn = [0; 16];
    }

    // TODO: update this
    let mut tcb_status = get_tdx_fmspc_tcbstatus_v3(&sgx_extensions, &tee_tcb_svn, &tcb_info_v3);

    // TODO: check TDX module

    // TODO: converge TCB with TDX Module TCB

    tcb_status = converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

    // TEMP: Cloning TDX body for now, which is kinda dumb. i need to fix this asap
    let tdx_body_clone = QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(&quote_data[48..]));

    VerifiedOutput {
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: sgx_extensions.fmspc,
        quote_body: tdx_body_clone,
    }
}
