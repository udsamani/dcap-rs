use crate::types::quotes::{
    version_3::QuoteV3,
    body::QuoteBody
};
use crate::types::{IntelCollateral, VerifiedOutput, tcbinfo::{TcbInfo, TcbInfoV2}};
use crate::utils::cert:: get_fmspc_tcbstatus;

use super::{common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb};

pub fn verify_quote_dcapv3(
    quote: &QuoteV3,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> VerifiedOutput {
    let quote_body = QuoteBody::SGXQuoteBody(quote.isv_enclave_report);
    let (qe_tcb_status, sgx_extensions, tcb_info) = common_verify_and_fetch_tcb(
        &quote.header, 
        &quote_body, 
        &quote.signature.isv_enclave_report_signature, 
        &quote.signature.ecdsa_attestation_key,  
        &quote.signature.qe_report, 
        &quote.signature.qe_report_signature, 
        &quote.signature.qe_auth_data.data,
        &quote.signature.qe_cert_data,
        collaterals, 
        current_time
    );

    let tcb_info_v2: TcbInfoV2;
    if let TcbInfo::V2(tcb) = tcb_info {
        tcb_info_v2 = tcb;
    } else {
        panic!("TcbInfo must be V2!");
    }
    let mut tcb_status = get_fmspc_tcbstatus(&sgx_extensions, &tcb_info_v2);

    tcb_status = converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

    VerifiedOutput {
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status,
        fmspc: sgx_extensions.fmspc,
        quote_body: QuoteBody::SGXQuoteBody(quote.isv_enclave_report)
    }
}
