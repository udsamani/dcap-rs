use zerocopy::AsBytes;

use crate::types::report::{EnclaveReportBody, TdxReportBody};

use super::{SGX_TEE_TYPE, TDX_TEE_TYPE};

/// Body of the Quote data structure.
#[derive(Debug)]
pub enum QuoteBody {
    SgxQuoteBody(EnclaveReportBody),
    TdxQuoteBody(TdxReportBody),
}

impl QuoteBody {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::SgxQuoteBody(body) => body.as_bytes(),
            Self::TdxQuoteBody(body) => body.as_bytes(),
        }
    }

    pub fn tee_type(&self) -> u32 {
        match self {
            Self::SgxQuoteBody(_) => SGX_TEE_TYPE,
            Self::TdxQuoteBody(_) => TDX_TEE_TYPE,
        }
    }

    pub fn as_tdx_report_body(&self) -> Option<&TdxReportBody> {
        match self {
            Self::TdxQuoteBody(body) => Some(body),
            _ => None,
        }
    }
}
